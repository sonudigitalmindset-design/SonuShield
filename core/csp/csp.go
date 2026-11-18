package csp

// CSP violation report store (Batch 8).
//
// Reports arrive at POST /_bProxy/csp-report (see
// server/csp.go) in either the legacy application/csp-report
// shape or the Reporting API (application/reports+json)
// shape. Only a small subset of fields is kept: the document
// and blocked URIs (query strings stripped, matching the
// logging policy), the violated/effective directives, the
// source file and position, the status code, and the
// disposition. Referrer, original policy, and script samples
// are deliberately dropped: they can carry page content and
// add nothing to a violation overview.
//
// Storage is a bounded per-domain ring (200 reports); a reload
// discards it. Reports are only as trustworthy as their
// sender: the endpoint is unauthenticated by design (browsers
// cannot authenticate report delivery), so a malicious client
// can pollute a domain's report list — the bound keeps the
// damage to noise, and reports never influence enforcement.

import (
	"sync"
	"time"
)

// maxReportsPerDomain bounds the ring per domain.
const maxReportsPerDomain = 200

// Report is one stored CSP violation report.
type Report struct {
	Time              time.Time `json:"time"`
	DocumentURI       string    `json:"documentUri"`
	BlockedURI        string    `json:"blockedUri"`
	ViolatedDirective string    `json:"violatedDirective"`
	EffectiveDirective string   `json:"effectiveDirective"`
	SourceFile        string    `json:"sourceFile"`
	LineNumber        int       `json:"lineNumber"`
	ColumnNumber      int       `json:"columnNumber"`
	StatusCode        int       `json:"statusCode"`
	Disposition       string    `json:"disposition"`
}

var (
	mu      sync.Mutex
	reports = map[string][]Report{}
)

// Record appends a report for a domain, trimming the ring to
// the cap.
func Record(domain string, report Report) {
	if domain == "" {
		return
	}
	if report.Time.IsZero() {
		report.Time = time.Now().UTC()
	}
	mu.Lock()
	defer mu.Unlock()
	list := append(reports[domain], report)
	if len(list) > maxReportsPerDomain {
		list = list[len(list)-maxReportsPerDomain:]
	}
	reports[domain] = list
}

// Recent returns up to limit reports for a domain,
// newest-first. limit <= 0 means 50; values above the cap are
// clamped to it.
func Recent(domain string, limit int) []Report {
	if limit <= 0 {
		limit = 50
	}
	if limit > maxReportsPerDomain {
		limit = maxReportsPerDomain
	}
	mu.Lock()
	defer mu.Unlock()
	list := reports[domain]
	if len(list) == 0 {
		return nil
	}
	if limit > len(list) {
		limit = len(list)
	}
	out := make([]Report, 0, limit)
	for i := len(list) - 1; i >= len(list)-limit; i-- {
		out = append(out, list[i])
	}
	return out
}

// Count reports the stored report count for a domain.
func Count(domain string) int {
	mu.Lock()
	defer mu.Unlock()
	return len(reports[domain])
}
