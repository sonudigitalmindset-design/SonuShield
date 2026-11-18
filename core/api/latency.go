package api

// Latency + SLA API (Batch 7).
//
// GET_LATENCY returns the per-domain latency summary over the
// retained sample window (last 512 origin samples): TTFB and
// total percentiles, mean proxy latency, error counts, the
// origin success rate, and the SLA comparison against the
// domain's slaTarget (default 99.9). Durations are reported
// in milliseconds with one decimal. "UPTIME_PCT" is the
// origin success rate over the window, not wall-clock uptime;
// "ERROR_BUDGET_REMAINING_PCT" is (success rate - target) in
// percentage points and can be negative. Read-only; viewers
// may call it. No parameters are accepted.

import (
	"math"
	"time"

	"sonushield/core/domains"
	"sonushield/core/latency"
)

// defaultSLATarget is the SLA target when slaTarget is unset
// or out of range.
const defaultSLATarget = 99.9

// effectiveSLATarget normalizes the configured target: unset
// (0), negative, or above 100 all fall back to the default.
func effectiveSLATarget(configured float64) float64 {
	if configured <= 0 || configured > 100 {
		return defaultSLATarget
	}
	return configured
}

// latencyMillis renders a duration in milliseconds with one
// decimal of precision, rounding half away from zero.
func latencyMillis(d time.Duration) float64 {
	return math.Round(d.Seconds()*10000) / 10
}

// latencyResponse builds the GET_LATENCY response.
func latencyResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	stats := latency.StatsFor(domainSettings.Name)
	target := effectiveSLATarget(domainSettings.SLATarget)
	return map[string]interface{}{
		"SAMPLES":                    stats.Samples,
		"ERRORS":                     stats.Errors,
		"STATUS_5XX":                 stats.Status5xx,
		"TTFB_P50_MS":                latencyMillis(stats.TTFBP50),
		"TTFB_P95_MS":                latencyMillis(stats.TTFBP95),
		"TTFB_P99_MS":                latencyMillis(stats.TTFBP99),
		"TOTAL_P50_MS":               latencyMillis(stats.TotalP50),
		"TOTAL_P95_MS":               latencyMillis(stats.TotalP95),
		"TOTAL_P99_MS":               latencyMillis(stats.TotalP99),
		"PROXY_MEAN_MS":              latencyMillis(stats.ProxyMean),
		"UPTIME_PCT":                 math.Round(stats.SuccessRate*100) / 100,
		"SLA_TARGET_PCT":             target,
		"ERROR_BUDGET_REMAINING_PCT": math.Round((stats.SuccessRate-target)*100) / 100,
		"WINDOW_START":               stats.WindowStart.Format(time.RFC3339),
		"WINDOW_END":                 stats.WindowEnd.Format(time.RFC3339),
	}, ""
}
