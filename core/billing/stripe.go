package billing

// Stripe usage-record client (Batch 6).
//
// The client speaks the classic Stripe form API: one POST per
// metered subscription item,
// /v1/subscription_items/{item}/usage_records, with quantity,
// timestamp, and action=increment. It creates no customers, no
// subscriptions, and no charges — the operator creates those in
// Stripe (or in the Stripe dashboard) and maps them in config.
//
// Safety rules, enforced here and in the reporter:
//
//   - The secret key travels only as HTTP Basic auth to the
//     configured API base. It is never logged, never returned
//     by any API action, and redacted from config exports.
//   - Requests never follow redirects: a redirect must not
//     carry the key somewhere unexpected.
//   - Every request carries a deterministic idempotency key
//     derived from the reported delta, so a retried report
//     cannot double-bill.
//   - Only test/live secret keys (sk_test_/sk_live_) are
//     accepted. Publishable keys (pk_) cannot report usage and
//     are rejected rather than failing obscurely server-side.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultAPIBase is the Stripe API endpoint. The config apiBase
// override exists only for tests and the smoke harness mock.
const DefaultAPIBase = "https://api.stripe.com"

const stripeTimeout = 15 * time.Second

// ValidSecretKey reports whether key looks like a Stripe secret
// key. It proves the shape only; Stripe itself authenticates.
func ValidSecretKey(key string) bool {
	return strings.HasPrefix(key, "sk_test_") || strings.HasPrefix(key, "sk_live_")
}

// KeyMode reports "test", "live", or "" for a key. The mode is
// safe to expose in status responses; the key itself never is.
func KeyMode(key string) string {
	switch {
	case strings.HasPrefix(key, "sk_test_"):
		return "test"
	case strings.HasPrefix(key, "sk_live_"):
		return "live"
	default:
		return ""
	}
}

// ValidCustomerID reports whether id looks like a Stripe
// customer id (cus_...).
func ValidCustomerID(id string) bool {
	return strings.HasPrefix(id, "cus_") && len(id) > 4
}

// ValidSubscriptionItemID reports whether id looks like a Stripe
// subscription item id (si_...).
func ValidSubscriptionItemID(id string) bool {
	return strings.HasPrefix(id, "si_") && len(id) > 3
}

// Client posts usage records to one Stripe-compatible endpoint.
type Client struct {
	base   string
	key    string
	client *http.Client
}

// NewClient builds a client for base (DefaultAPIBase when empty)
// authenticated with key. It does not validate the key; the
// reporter validates before reporting.
func NewClient(base, key string) *Client {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = DefaultAPIBase
	}
	return &Client{
		base: base,
		key:  key,
		client: &http.Client{
			Timeout: stripeTimeout,
			// Never follow redirects with the secret key.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// stripeError is the error envelope Stripe returns on failure.
type stripeError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// ReportUsage increments one metered subscription item by
// quantity at timestamp (Unix seconds). idempotencyKey must be
// deterministic for a given delta: retrying the same report
// with the same key returns the original result instead of
// recording twice. Quantities must be positive.
func (c *Client) ReportUsage(itemID string, quantity, timestamp int64, idempotencyKey string) error {
	if quantity <= 0 {
		return fmt.Errorf("quantity must be positive")
	}
	form := url.Values{}
	form.Set("quantity", strconv.FormatInt(quantity, 10))
	form.Set("timestamp", strconv.FormatInt(timestamp, 10))
	form.Set("action", "increment")
	req, err := http.NewRequest(http.MethodPost,
		c.base+"/v1/subscription_items/"+itemID+"/usage_records",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	req.SetBasicAuth(c.key, "")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var parsed stripeError
	if json.Unmarshal(body, &parsed) == nil && parsed.Error.Message != "" {
		if parsed.Error.Code != "" {
			return fmt.Errorf("stripe HTTP %d (%s): %s", resp.StatusCode, parsed.Error.Code, parsed.Error.Message)
		}
		return fmt.Errorf("stripe HTTP %d: %s", resp.StatusCode, parsed.Error.Message)
	}
	return fmt.Errorf("stripe HTTP %d", resp.StatusCode)
}
