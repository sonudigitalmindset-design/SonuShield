package api

// Credential-stuffing status API (Batch 8).
//
// GET_STUFFING_STATUS (domain, viewer) returns the current
// window counts for the domain's watched login paths: failures
// recorded, distinct IPs, and whether either detection pattern
// is currently flagged. No parameters are accepted. Counts only:
// no IPs, usernames, or request details are returned.

import (
	"sonushield/core/domains"
	"sonushield/core/firewall"
)

func stuffingStatusResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	_, _, perIP, distributed, window, block := domainSettings.CredentialStuffing.StuffingEffective()
	paths := []map[string]interface{}{}
	for _, status := range firewall.StuffingStatus(domainSettings.Name, domainSettings.CredentialStuffing) {
		paths = append(paths, map[string]interface{}{
			"PATH":        status.Path,
			"FAILURES":    status.Failures,
			"DISTINCT_IP": status.DistinctIP,
			"FLAGGED":     status.Flagged,
			"KIND":        status.Kind,
		})
	}
	return map[string]interface{}{
		"ENABLED":               len(domainSettings.CredentialStuffing.Paths) > 0,
		"MODE":                  map[bool]string{true: "block", false: "log"}[block],
		"PER_IP_THRESHOLD":      perIP,
		"DISTRIBUTED_THRESHOLD": distributed,
		"WINDOW_SECONDS":        window,
		"PATHS":                 paths,
	}, ""
}
