// Package sonushield is a minimal client for the SonuShield
// public API v1 (/_bProxy/public/v1/*) — the tenant/reseller
// read API. It is not a client for the internal control API.
//
// The client authenticates with a per-tenant API key
// (Authorization: Bearer) and retries 429 responses honoring
// Retry-After, capped at 30 seconds per wait. All calls are
// GETs, so retries are safe.
//
// Example:
//
//	client := sonushield.NewClient("https://example.com", "your-api-key")
//	usage, err := client.Usage(context.Background())
package sonushield

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxRetries is the number of 429 retries per call.
const DefaultMaxRetries = 3

// maxRetryWait caps each Retry-After wait.
const maxRetryWait = 30 * time.Second

// Error is a public API failure. Code is the machine-readable
// error code from the envelope ("unauthorized",
// "rate_limited", "not_found", ...). RetryAfter is set (in
// seconds) on rate-limit errors when the server sent it.
type Error struct {
	StatusCode int
	Code       string
	Message    string
	RetryAfter int
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("sonushield: HTTP %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("sonushield: HTTP %d: %s", e.StatusCode, e.Message)
}

// Usage is the response of GET /v1/usage.
type Usage struct {
	Tenant     string   `json:"tenant"`
	Requests   int64    `json:"requests"`
	Blocked    int64    `json:"blocked"`
	BytesIn    int64    `json:"bytes_in"`
	BytesOut   int64    `json:"bytes_out"`
	BytesTotal int64    `json:"bytes_total"`
	Domains    []string `json:"domains"`
}

// Domain is one entry of GET /v1/domains.
type Domain struct {
	Name        string `json:"name"`
	Stage       int    `json:"stage"`
	StageName   string `json:"stage_name"`
	StageLocked bool   `json:"stage_locked"`
	UnderAttack bool   `json:"under_attack"`
	Requests    int64  `json:"requests"`
	Blocked     int64  `json:"blocked"`
	BytesTotal  int64  `json:"bytes_total"`
}

// DomainsResponse is the response of GET /v1/domains.
type DomainsResponse struct {
	Tenant  string   `json:"tenant"`
	Domains []Domain `json:"domains"`
}

// PingResponse is the response of GET /v1/ping.
type PingResponse struct {
	Tenant  string `json:"tenant"`
	KeyName string `json:"key_name"`
}

// Client talks to one SonuShield instance's public API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	maxRetries int
}

// NewClient builds a client for baseURL (the proxy origin,
// e.g. "https://example.com") with the given API key.
func NewClient(baseURL, apiKey string) *Client {
	return NewClientWithHTTP(baseURL, apiKey, &http.Client{Timeout: 15 * time.Second})
}

// NewClientWithHTTP builds a client with a caller-supplied
// HTTP client (custom transport, timeout, or test server).
func NewClientWithHTTP(baseURL, apiKey string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: httpClient,
		maxRetries: DefaultMaxRetries,
	}
}

// SetMaxRetries changes the 429 retry budget (default 3).
func (c *Client) SetMaxRetries(n int) {
	if n < 0 {
		n = 0
	}
	c.maxRetries = n
}

type envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/_bProxy/public/v1/"+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			if attempt >= c.maxRetries {
				return c.rateLimitError(resp, body)
			}
			wait := retryWait(resp)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return c.responseError(resp, body)
		}
		var env envelope
		if err := json.Unmarshal(body, &env); err != nil {
			return fmt.Errorf("sonushield: invalid response: %w", err)
		}
		if !env.OK {
			return c.responseError(resp, body)
		}
		if out != nil {
			if err := json.Unmarshal(env.Data, out); err != nil {
				return fmt.Errorf("sonushield: invalid response data: %w", err)
			}
		}
		return nil
	}
}

func (c *Client) rateLimitError(resp *http.Response, body []byte) error {
	err := c.responseError(resp, body)
	if apiErr, ok := err.(*Error); ok {
		if n, convErr := strconv.Atoi(resp.Header.Get("Retry-After")); convErr == nil {
			apiErr.RetryAfter = n
		}
		return apiErr
	}
	return err
}

func (c *Client) responseError(resp *http.Response, body []byte) error {
	var env envelope
	apiErr := &Error{StatusCode: resp.StatusCode}
	if json.Unmarshal(body, &env) == nil && env.Error != nil {
		apiErr.Code = env.Error.Code
		apiErr.Message = env.Error.Message
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(resp.StatusCode)
	}
	return apiErr
}

func retryWait(resp *http.Response) time.Duration {
	if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
		wait := time.Duration(n) * time.Second
		if wait > maxRetryWait {
			return maxRetryWait
		}
		return wait
	}
	return time.Second
}

// Ping checks the key and returns the tenant it reads.
func (c *Client) Ping(ctx context.Context) (*PingResponse, error) {
	var out PingResponse
	if err := c.get(ctx, "ping", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Usage returns the tenant's aggregate usage.
func (c *Client) Usage(ctx context.Context) (*Usage, error) {
	var out Usage
	if err := c.get(ctx, "usage", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UsageForDomain returns usage for one of the tenant's
// domains. Domains outside the tenant return a not_found
// error, exactly like nonexistent ones.
func (c *Client) UsageForDomain(ctx context.Context, domain string) (*Usage, error) {
	var out Usage
	path := "usage?domain=" + url.QueryEscape(domain)
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Domains lists the tenant's domains with stage and counters.
func (c *Client) Domains(ctx context.Context) (*DomainsResponse, error) {
	var out DomainsResponse
	if err := c.get(ctx, "domains", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
