package api

// PURGE_CACHE (domain): drop edge-cache entries for a domain.
//
// With no parameters, the whole domain cache is purged. With a
// "path" parameter, only entries for that URL path are purged
// (the exact path and the same path with any query string).
// Purging a domain whose edge cache is disabled succeeds and
// reports zero entries purged. Unknown parameters are rejected,
// matching the other write actions.

import "sonushield/core/domains"

func purgeCacheResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for key := range params {
		if key != "path" {
			return nil, ERR_INVALID_PARAM
		}
	}
	purged := 0
	if domainSettings.Cache != nil {
		if path, ok := params["path"]; ok && path != "" {
			purged = domainSettings.Cache.PurgePath(path)
		} else {
			purged = domainSettings.Cache.Purge()
		}
	}
	remaining, _ := domainSettings.Cache.Stats()
	return map[string]interface{}{
		"PURGED":            purged,
		"ENTRIES_REMAINING": remaining,
		"CACHE_ENABLED":     domainSettings.Cache != nil,
	}, ""
}
