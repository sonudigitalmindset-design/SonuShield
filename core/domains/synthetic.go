package domains

import "time"

// Synthetic check configuration (Batch 8).
//
// SyntheticConfig schedules self-checks that request the
// operator's domains through the proxy like ordinary
// visitors and alert (over the existing notice channels)
// when a check fails or latency crosses a threshold. Checks
// are off unless enabled with at least one check configured.
//
// A check is a normal request: it passes challenges like any
// visitor, appears in request totals, and carries the
// distinctive user-agent "SonuShield-Synthetic-Check/1.0"
// so the operator can filter it in logs. Checks never trip
// attack detection — one request per check per interval is
// far below any rate limit — and they never write to attack
// statistics as attack traffic. TLS is always verified:
// checks against self-signed endpoints fail, by design.

// SyntheticCheck is one scheduled self-check: a name, the
// URL to request, the expected status (0 means 200), and an
// optional body substring that must be present. Method
// defaults to GET; only GET and HEAD are accepted.
type SyntheticCheck struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	Method             string `json:"method"`
	ExpectStatus       int    `json:"expectStatus"`
	ExpectBodyContains string `json:"expectBodyContains"`
}

// SyntheticConfig is the proxy-level synthetic-check
// configuration (proxy.synthetic). IntervalSeconds defaults
// to 300 (minimum 60). LatencyThresholdMs, when positive,
// alerts when a check's latency exceeds it.
type SyntheticConfig struct {
	Enabled             bool             `json:"enabled"`
	Checks              []SyntheticCheck `json:"checks"`
	IntervalSeconds     int              `json:"intervalSeconds"`
	LatencyThresholdMs  int              `json:"latencyThresholdMs"`
}

// SyntheticInterval resolves the check interval with the
// documented default and floor.
func (c SyntheticConfig) SyntheticInterval() time.Duration {
	seconds := c.IntervalSeconds
	if seconds <= 0 {
		seconds = 300
	}
	if seconds < 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}
