package api

// DLP status API (Batch 8).
//
// GET_DLP_STATUS (domain, viewer) returns the scan counters
// and per-pattern match counts. Pattern names and counts only:
// matched content is never stored, so it can never be
// returned. No parameters are accepted.

import "sonushield/core/domains"

func dlpStatusResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	scanned, redacted, blocked, patterns := domainSettings.DLP.Stats()
	patternList := []map[string]interface{}{}
	for _, pattern := range patterns {
		patternList = append(patternList, map[string]interface{}{
			"NAME":    pattern.Name,
			"MATCHES": pattern.Matches,
		})
	}
	return map[string]interface{}{
		"ENABLED":  domainSettings.DLP != nil,
		"MODE":     map[bool]string{true: "block", false: "redact"}[domainSettings.DLP.BlockMode()],
		"SCANNED":  scanned,
		"REDACTED": redacted,
		"BLOCKED":  blocked,
		"PATTERNS": patternList,
	}, ""
}
