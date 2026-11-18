package api

// PURGE_CACHE (domain) + GET_CACHE_STATS (domain).
//
// PURGE_CACHE drops edge-cache entries for a domain. With no
// parameters, the whole domain cache is purged. Exactly one
// selector may be given: "path" purges one URL path (the
// exact path and the same path with any query string),
// "prefix" purges every path starting with the prefix, and
// "tag" purges entries recorded with that Cache-Tag value.
// Purging a domain whose edge cache is disabled succeeds and
// reports zero entries purged. Unknown parameters and
// multiple selectors are rejected.
//
// GET_CACHE_STATS (viewer) returns the analytics counters:
// hits, misses, bytes served, stores, evictions, purges,
// stale serves, and the current entry/byte totals. Counters
// only — no keys, paths, or bodies.

import "sonushield/core/domains"

func purgeCacheResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	selectors := 0
	for key := range params {
		switch key {
		case "path", "prefix", "tag":
			selectors++
		default:
			return nil, ERR_INVALID_PARAM
		}
	}
	if selectors > 1 {
		return nil, ERR_INVALID_PARAM
	}
	purged := 0
	if domainSettings.Cache != nil {
		switch {
		case params["path"] != "":
			purged = domainSettings.Cache.PurgePath(params["path"])
		case params["prefix"] != "":
			purged = domainSettings.Cache.PurgePrefix(params["prefix"])
		case params["tag"] != "":
			purged = domainSettings.Cache.PurgeTag(params["tag"])
		default:
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

func cacheStatsResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	stats := domainSettings.Cache.Analytics()
	return map[string]interface{}{
		"CACHE_ENABLED": domainSettings.Cache != nil,
		"HITS":          stats.Hits,
		"MISSES":        stats.Misses,
		"BYTES_SERVED":  stats.BytesServed,
		"STORES":        stats.Stores,
		"EVICTIONS":     stats.Evictions,
		"PURGES":        stats.Purges,
		"STALE_SERVES":  stats.StaleServes,
		"ENTRIES":       stats.Entries,
		"BYTES":         stats.Bytes,
	}, ""
}
