// Package privacy holds the global privacy-mode switch and
// the IP anonymization helper (Batch 7). It has no
// dependencies so the logging, firewall, reports, API, and
// server packages can all read it without import cycles.
//
// Privacy mode minimizes STORED personal data: IPs are
// anonymized and user-agents are dropped in logs, reports,
// and API responses, and log retention is capped. It does
// NOT anonymize live enforcement state: rate limiting,
// connection tracking, and IP reputation need exact client
// IPs to function, and that in-memory state is never
// written to disk or returned unmasked. Fingerprints
// (TLS/JA4/HTTP) are pseudonymous signals, not IPs, and are
// retained as-is; privacy mode does not remove them.
package privacy

import (
	"net"
	"sync/atomic"
)

var enabled atomic.Bool

// Set turns privacy mode on or off. Called from config
// loading and reload, before logging is configured.
func Set(on bool) {
	enabled.Store(on)
}

// Enabled reports whether privacy mode is on.
func Enabled() bool {
	return enabled.Load()
}

// MaskIP anonymizes one IP address: the last octet of an
// IPv4 address becomes 0, and the last 64 bits (interface
// identifier) of an IPv6 address become zero. Values that
// do not parse as IPs (placeholders, hostnames, already
// masked values) pass through unchanged, so masking never
// destroys non-IP data.
func MaskIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return net.IPv4(v4[0], v4[1], v4[2], 0).String()
	}
	v6 := parsed.To16()
	masked := make(net.IP, net.IPv6len)
	copy(masked, v6)
	for i := 8; i < net.IPv6len; i++ {
		masked[i] = 0
	}
	return masked.String()
}

// MaskCounts anonymizes the keys of an IP-keyed count map,
// summing counts whose keys collide after masking (so
// totals are preserved). Non-IP keys pass through. When
// privacy mode is off the input map is returned unchanged.
func MaskCounts(counts map[string]int) map[string]int {
	if !Enabled() {
		return counts
	}
	masked := make(map[string]int, len(counts))
	for key, count := range counts {
		masked[MaskIP(key)] += count
	}
	return masked
}
