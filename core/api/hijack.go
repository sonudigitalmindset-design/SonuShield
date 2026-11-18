package api

// Session-hijack status API (Batch 8).
//
// GET_HIJACK_STATUS (domain, viewer) returns detector counts:
// live session bindings and sessions flagged within the last
// hour. Counts only: no cookie values, hashes, IPs, or
// fingerprints are returned. No parameters are accepted.

import (
	"sonushield/core/domains"
	"sonushield/core/firewall"
)

func hijackStatusResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	bindings, flagged := firewall.HijackStats()
	return map[string]interface{}{
		"ENABLED":        domainSettings.SessionHijack.Cookie != "",
		"MODE":           map[bool]string{true: "block", false: "log"}[domainSettings.SessionHijack.HijackBlock()],
		"BINDINGS":       bindings,
		"FLAGGED_RECENT": flagged,
	}, ""
}
