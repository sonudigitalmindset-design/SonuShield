package api

// BGP status API (Batch 8, proxy action).
//
// GET_BGP_STATUS (viewer) returns the monitored prefixes with
// their expected origins, last observed origins, announcement
// state, alert state, last check time, and last fetch error.
// No parameters are accepted. The API token is never
// returned.

import (
	"sonushield/core/bgp"
	"sonushield/core/domains"
)

func bgpStatusResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	enabled := false
	if domains.Config != nil {
		monitor := domains.Config.Proxy.BGPMonitor
		enabled = monitor.Enabled && len(monitor.Prefixes) > 0 && len(monitor.ExpectedOrigins) > 0
	}
	prefixes := []map[string]interface{}{}
	for _, state := range bgp.Status() {
		lastCheck := ""
		if !state.LastCheck.IsZero() {
			lastCheck = state.LastCheck.Format("2006-01-02T15:04:05Z07:00")
		}
		prefixes = append(prefixes, map[string]interface{}{
			"PREFIX":       state.Prefix,
			"EXPECTED":     state.Expected,
			"LAST_ORIGINS": state.LastOrigins,
			"ANNOUNCED":    state.Announced,
			"ALERTING":     state.Alerting,
			"LAST_CHECK":   lastCheck,
			"LAST_ERROR":   state.LastError,
		})
	}
	return map[string]interface{}{
		"ENABLED":  enabled,
		"PREFIXES": prefixes,
	}, ""
}
