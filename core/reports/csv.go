package reports

// CSV rendering for attack reports (Batch 2).
//
// ToCSV renders a Report as one well-formed table with the header
// "section,key,value,detail". Sections: "summary" (one row per
// scalar field), "blocks", "challenges", "waf", "verified_ips",
// "unverified_ips", "unknown_fingerprints", "countries". The detail
// column carries GeoIP info for IP rows ("country=US asn=15169",
// or "country=unknown" when no database is loaded) and is empty
// elsewhere. Rows within each map-backed section are sorted by key
// so repeated exports of the same report are byte-identical.
// encoding/csv handles all quoting; no field is ever hand-escaped.

import (
	"bytes"
	"encoding/csv"
	"sort"
	"strconv"
	"time"
)

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func formatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func formatFloat(f *float64) string {
	if f == nil {
		return ""
	}
	return strconv.FormatFloat(*f, 'f', 6, 64)
}

// ToCSV renders the report as a single CSV table. It cannot fail:
// the writer targets an in-memory buffer.
func ToCSV(report Report) string {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	row := func(section, key, value, detail string) {
		_ = writer.Write([]string{section, key, value, detail})
	}
	_ = writer.Write([]string{"section", "key", "value", "detail"})

	row("summary", "domain", report.Domain, "")
	row("summary", "generated_at", report.GeneratedAt.UTC().Format(time.RFC3339), "")
	row("summary", "window_start", formatTime(report.WindowStart), "")
	row("summary", "window_end", formatTime(report.WindowEnd), "")
	row("summary", "window_seconds", strconv.Itoa(report.WindowSeconds), "")
	row("summary", "stage", strconv.Itoa(report.Stage), "")
	row("summary", "stage_manually_set", formatBool(report.StageManuallySet), "")
	row("summary", "raw_attack", formatBool(report.RawAttack), "")
	row("summary", "bypass_attack", formatBool(report.BypassAttack), "")
	row("summary", "total_requests", strconv.Itoa(report.TotalRequests), "")
	row("summary", "bypassed_requests", strconv.Itoa(report.BypassedRequests), "")
	row("summary", "requests_per_second", strconv.Itoa(report.RequestsPerSecond), "")
	row("summary", "bypassed_per_second", strconv.Itoa(report.BypassedPerSecond), "")
	row("summary", "peak_requests_per_second", strconv.Itoa(report.PeakRequestsPerSecond), "")
	row("summary", "peak_bypassed_per_second", strconv.Itoa(report.PeakBypassedPerSecond), "")
	row("summary", "cooldown_remaining_seconds", strconv.Itoa(report.CooldownRemainingSeconds), "")
	row("summary", "backend_requests_ok", strconv.FormatInt(report.BackendRequestsOK, 10), "")
	row("summary", "backend_requests_failed", strconv.FormatInt(report.BackendRequestsError, 10), "")
	row("summary", "backend_latency_avg_seconds", formatFloat(report.BackendLatencyAvg), "")
	row("summary", "risk_avg", formatFloat(report.RiskAvg), "")
	row("summary", "risk_max", strconv.Itoa(report.RiskMax), "")
	row("summary", "risk_samples", strconv.FormatInt(report.RiskSamples, 10), "")
	row("summary", "top_limit", strconv.Itoa(report.TopLimit), "")

	writeCountMap := func(section string, values map[string]int64) {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			row(section, key, strconv.FormatInt(values[key], 10), "")
		}
	}
	writeCountMap("blocks", report.BlocksByReason)
	writeCountMap("challenges", report.ChallengesByStage)
	writeCountMap("waf", report.WAFMatchesByRule)

	writeIPs := func(section string, entries []IPEntry) {
		for _, entry := range entries {
			country := entry.Country
			if country == "" {
				country = "unknown"
			}
			detail := "country=" + country
			if entry.ASN != 0 {
				detail += " asn=" + strconv.Itoa(entry.ASN)
			}
			row(section, entry.IP, strconv.Itoa(entry.Requests), detail)
		}
	}
	writeIPs("verified_ips", report.TopVerifiedIPs)
	writeIPs("unverified_ips", report.TopUnverifiedIPs)

	for _, entry := range report.TopUnknownFingerprints {
		row("unknown_fingerprints", entry.Key, strconv.Itoa(entry.Count), "")
	}
	for _, entry := range report.Countries {
		row("countries", entry.Key, strconv.Itoa(entry.Count), "")
	}

	writer.Flush()
	return buf.String()
}
