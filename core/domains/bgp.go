package domains

import "time"

// BGP monitoring configuration (Batch 8).
//
// BGPMonitorConfig names the operator's own prefixes and the
// external data source that reports who announces them. Two
// source shapes are supported: "ripestat" (the default) reads
// the RIPEstat prefix-overview call, a free public API that
// needs no credentials; "custom" reads an operator-supplied
// API base URL (with an optional Bearer token) that returns
// {"announced": true, "origins": [12345]}. No other source is
// understood, and no data is bundled: without prefixes and
// expected origins configured, monitoring is inert.
//
// RIPEstat aggregates RIS collector data in multi-hour
// intervals, so BGP alerts are coarse-grained: a hijack
// lasting minutes can be missed entirely. This feature is an
// advisory early-warning check, not real-time hijack
// detection. See core/bgp.

// BGPMonitorConfig is the proxy-level BGP monitoring
// configuration (proxy.bgpMonitor). ExpectedOrigins lists the
// ASNs that are supposed to originate the prefixes; any other
// origin triggers an alert. CheckIntervalSeconds defaults to
// 3600 (minimum 300).
type BGPMonitorConfig struct {
	Enabled             bool     `json:"enabled"`
	Source              string   `json:"source"`
	APIBase             string   `json:"apiBase"`
	APIToken            string   `json:"apiToken"`
	Prefixes            []string `json:"prefixes"`
	ExpectedOrigins     []int    `json:"expectedOrigins"`
	CheckIntervalSeconds int      `json:"checkIntervalSeconds"`
}

// BGPSource resolves the source name, defaulting to ripestat.
func (c BGPMonitorConfig) BGPSource() string {
	if c.Source == "custom" {
		return "custom"
	}
	return "ripestat"
}

// BGPAPIBase resolves the API base URL for the source.
func (c BGPMonitorConfig) BGPAPIBase() string {
	if c.APIBase != "" {
		return c.APIBase
	}
	if c.BGPSource() == "custom" {
		return ""
	}
	return "https://stat.ripe.net"
}

// BGPCheckInterval resolves the check interval with the
// documented default and floor.
func (c BGPMonitorConfig) BGPCheckInterval() time.Duration {
	seconds := c.CheckIntervalSeconds
	if seconds <= 0 {
		seconds = 3600
	}
	if seconds < 300 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}
