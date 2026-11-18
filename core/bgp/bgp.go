package bgp

// BGP announcement monitoring (Batch 8).
//
// The monitor periodically asks an external data source which
// ASNs originate the operator's own prefixes and alerts when
// an unexpected origin appears (or an expected announcement
// disappears after having been seen). Monitoring is advisory
// and fail-open: fetch errors never affect traffic and never
// raise alerts; the last-known state is kept.
//
// Sources: "ripestat" reads the RIPEstat prefix-overview call
// (public, no credentials); "custom" reads an operator API
// returning {"announced": bool, "origins": [ASN, ...]} with an
// optional Bearer token. The fetcher is injectable so the
// alert logic is testable without the network.
//
// Alert semantics: the first successful check for a prefix is
// a silent baseline. A later check alerts (once, on the
// transition) when the observed origin set differs from the
// expected set — an origin outside the expected list, or no
// announcement at all. A return to the expected set alerts
// once as a recovery. Prefixes are never alerted on when no
// expected origins are configured: without an expectation
// there is nothing to compare.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PrefixState is the monitored state of one prefix.
type PrefixState struct {
	Prefix      string
	Expected    []int
	LastOrigins []int
	Announced   bool
	Seen        bool
	Alerting    bool
	LastCheck   time.Time
	LastError   string
}

// Fetcher returns the origin ASNs and announcement flag for a
// prefix, from the configured source.
type Fetcher func(apiBase, token, source, prefix string) (origins []int, announced bool, err error)

var (
	mu     sync.Mutex
	states = map[string]*PrefixState{}

	httpClient = &http.Client{Timeout: 15 * time.Second}
)

// Check runs one monitoring pass over the configured
// prefixes, using the given fetcher, and returns the alert
// events produced (each at most one per prefix per pass).
// An event is (prefix, unexpected bool, detail): unexpected
// true means an unexpected-origin alert, false means recovery.
type Event struct {
	Prefix     string
	Unexpected bool
	Detail     string
}

// Check evaluates every configured prefix. cfg carries the
// prefixes and expected origins; apiBase/token/source select
// the data source.
func Check(prefixes []string, expected []int, apiBase, token, source string, fetch Fetcher) []Event {
	mu.Lock()
	defer mu.Unlock()
	var events []Event
	now := time.Now().UTC()
	for _, prefix := range prefixes {
		state, ok := states[prefix]
		if !ok {
			state = &PrefixState{Prefix: prefix}
			states[prefix] = state
		}
		state.Expected = append([]int(nil), expected...)
		origins, announced, err := fetch(apiBase, token, source, prefix)
		state.LastCheck = now
		if err != nil {
			// Fail open: keep the last-known state, record the
			// error, raise no alert.
			state.LastError = err.Error()
			continue
		}
		state.LastError = ""
		state.LastOrigins = append([]int(nil), origins...)
		state.Announced = announced
		if !state.Seen {
			// Silent baseline.
			state.Seen = true
			continue
		}
		unexpected := isUnexpected(origins, announced, expected)
		if unexpected && !state.Alerting {
			state.Alerting = true
			events = append(events, Event{Prefix: prefix, Unexpected: true, Detail: describeOrigins(origins, announced)})
		} else if !unexpected && state.Alerting {
			state.Alerting = false
			events = append(events, Event{Prefix: prefix, Unexpected: false, Detail: describeOrigins(origins, announced)})
		}
	}
	return events
}

func isUnexpected(origins []int, announced bool, expected []int) bool {
	if len(expected) == 0 {
		return false
	}
	if !announced {
		return true
	}
	expectedSet := map[int]bool{}
	for _, asn := range expected {
		expectedSet[asn] = true
	}
	for _, asn := range origins {
		if !expectedSet[asn] {
			return true
		}
	}
	return len(origins) == 0
}

func describeOrigins(origins []int, announced bool) string {
	if !announced {
		return "not announced"
	}
	sorted := append([]int(nil), origins...)
	sort.Ints(sorted)
	parts := make([]string, 0, len(sorted))
	for _, asn := range sorted {
		parts = append(parts, "AS"+strconv.Itoa(asn))
	}
	return "origin(s) " + strings.Join(parts, ", ")
}

// Status returns a snapshot of every monitored prefix.
func Status() []PrefixState {
	mu.Lock()
	defer mu.Unlock()
	out := make([]PrefixState, 0, len(states))
	for _, state := range states {
		copy := *state
		copy.Expected = append([]int(nil), state.Expected...)
		copy.LastOrigins = append([]int(nil), state.LastOrigins...)
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// FetchOrigins is the production fetcher. It dispatches on the
// source name.
func FetchOrigins(apiBase, token, source, prefix string) ([]int, bool, error) {
	switch source {
	case "custom":
		if apiBase == "" {
			return nil, false, fmt.Errorf("custom BGP source needs apiBase")
		}
		return fetchCustom(apiBase, token, prefix)
	default:
		return fetchRIPEstat(apiBase, prefix)
	}
}

// fetchRIPEstat reads GET {apiBase}/data/prefix-overview/
// data.json?resource=<prefix>. The data.asns array holds
// {"asn": <int or string>, "holder": ...} objects and
// data.announced is a boolean (older payloads used the
// strings "True"/"False", which are accepted too).
func fetchRIPEstat(apiBase, prefix string) ([]int, bool, error) {
	endpoint := strings.TrimRight(apiBase, "/") + "/data/prefix-overview/data.json?resource=" + url.QueryEscape(prefix)
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("RIPEstat status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, false, err
	}
	var envelope struct {
		Data struct {
			Announced flexibleBool `json:"announced"`
			ASNs      []struct {
				ASN    flexibleASN `json:"asn"`
				Holder string      `json:"holder"`
			} `json:"asns"`
		} `json:"data"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, err
	}
	if envelope.Status != "" && envelope.Status != "ok" {
		return nil, false, fmt.Errorf("RIPEstat status %q", envelope.Status)
	}
	origins := make([]int, 0, len(envelope.Data.ASNs))
	for _, entry := range envelope.Data.ASNs {
		origins = append(origins, int(entry.ASN))
	}
	return origins, bool(envelope.Data.Announced), nil
}

// fetchCustom reads GET {apiBase}?prefix=<prefix> with an
// optional Bearer token, expecting
// {"announced": true, "origins": [12345]}.
func fetchCustom(apiBase, token, prefix string) ([]int, bool, error) {
	separator := "?"
	if strings.Contains(apiBase, "?") {
		separator = "&"
	}
	endpoint := apiBase + separator + "prefix=" + url.QueryEscape(prefix)
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("custom BGP source status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, false, err
	}
	var payload struct {
		Announced bool  `json:"announced"`
		Origins   []int `json:"origins"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false, err
	}
	return payload.Origins, payload.Announced, nil
}

// flexibleBool accepts a JSON boolean or the strings
// "True"/"False"/"true"/"false".
type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(data []byte) error {
	var boolean bool
	if err := json.Unmarshal(data, &boolean); err == nil {
		*b = flexibleBool(boolean)
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	switch strings.ToLower(text) {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		return fmt.Errorf("invalid boolean %q", text)
	}
	return nil
}

// flexibleASN accepts a JSON number or a numeric string
// (RIPEstat returns ASNs as strings in some calls).
type flexibleASN int

func (a *flexibleASN) UnmarshalJSON(data []byte) error {
	var number json.Number
	if err := json.Unmarshal(data, &number); err == nil {
		parsed, err := number.Int64()
		if err == nil {
			*a = flexibleASN(parsed)
			return nil
		}
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	text = strings.TrimPrefix(strings.ToUpper(text), "AS")
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return err
	}
	*a = flexibleASN(parsed)
	return nil
}
