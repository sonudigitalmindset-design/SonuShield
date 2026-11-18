package api

// OpenAPI status API (Batch 8).
//
// GET_OPENAPI_STATUS (domain, viewer) returns whether a spec
// is loaded, how many paths it defines, and the validation
// counters (requests checked, violations found). No parameters
// are accepted.

import "sonushield/core/domains"

func openAPIStatusResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	paths, checked, violated := domainSettings.OpenAPI.Stats()
	return map[string]interface{}{
		"LOADED":    domainSettings.OpenAPI != nil,
		"PATHS":     paths,
		"CHECKED":   checked,
		"VIOLATIONS": violated,
	}, ""
}
