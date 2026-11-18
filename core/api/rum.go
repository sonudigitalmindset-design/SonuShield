package api

// RUM statistics API (Batch 8).
//
// GET_RUM_STATS (domain, viewer) returns the aggregated
// real-user timing stats for a domain: beacon count,
// per-metric samples/average/p50/p95 (10 ms buckets), and the
// top paths by beacon count with average TTFB/load. No
// parameters are accepted. No per-visitor data exists to
// return: aggregates only.

import (
	"sonushield/core/domains"
	"sonushield/core/rum"
)

func rumStatsResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	stats := rum.Snapshot(domainSettings.Name)
	metrics := map[string]interface{}{}
	for name, metric := range stats.Metrics {
		metrics[name] = map[string]interface{}{
			"SAMPLES": metric.Samples,
			"AVERAGE": metric.Average,
			"P50":     metric.P50,
			"P95":     metric.P95,
		}
	}
	paths := []map[string]interface{}{}
	for _, path := range stats.Paths {
		paths = append(paths, map[string]interface{}{
			"PATH":     path.Path,
			"COUNT":    path.Count,
			"AVG_TTFB": path.AvgTTFB,
			"AVG_LOAD": path.AvgLoad,
		})
	}
	return map[string]interface{}{
		"COUNT":   stats.Count,
		"METRICS": metrics,
		"PATHS":   paths,
	}, ""
}
