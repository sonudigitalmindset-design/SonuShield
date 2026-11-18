package api

// Synthetic check status API (Batch 8, proxy action).
//
// GET_SYNTHETIC_STATUS (viewer) returns every check's last
// run state: URL, last run time, pass/fail, latency,
// last error, and consecutive failures. No parameters are
// accepted.

import (
	"sonushield/core/domains"
	"sonushield/core/synthetic"
)

func syntheticStatusResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	enabled := false
	if domains.Config != nil {
		cfg := domains.Config.Proxy.Synthetic
		enabled = cfg.Enabled && len(cfg.Checks) > 0
	}
	checks := []map[string]interface{}{}
	for _, state := range synthetic.Status() {
		lastRun := ""
		if !state.LastRun.IsZero() {
			lastRun = state.LastRun.Format("2006-01-02T15:04:05Z07:00")
		}
		checks = append(checks, map[string]interface{}{
			"NAME":                 state.Name,
			"URL":                  state.URL,
			"LAST_RUN":             lastRun,
			"OK":                   state.LastOK,
			"LATENCY_MS":           state.LastLatencyMs,
			"LAST_ERROR":           state.LastError,
			"CONSECUTIVE_FAILURES": state.ConsecutiveFailures,
			"LATENCY_BREACHING":    state.LatencyBreaching,
		})
	}
	return map[string]interface{}{
		"ENABLED": enabled,
		"CHECKS":  checks,
	}, ""
}
