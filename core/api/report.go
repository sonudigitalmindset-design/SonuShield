package api

// GET_ATTACK_REPORT (Batch 2).
//
// Domain action returning an attack summary for the requested
// domain, built from copied live state. Same apisecret auth as every
// other domain action; no visitor-visible page exists.
//
// Parameters (v1 "params" or v2 query parameters):
//   - format: "json" (default) or "csv". JSON returns the report
//     object in the usual envelope; CSV returns the flat CSV table
//     as a string in the envelope.
//   - top: 1..50, how many top IPs/fingerprints to list (default
//     10). Unknown parameters are rejected so typos never silently
//     pass as applied, matching SET_DOMAIN_FEATURES.

import (
	"sonushield/core/domains"
	"sonushield/core/metrics"
	"sonushield/core/reports"
	"strconv"
	"strings"
)

func attackReportResponse(domain string, domainData *domains.DomainData, params map[string]string) (map[string]interface{}, string) {
	format := "json"
	top := reports.DefaultTop
	for key, value := range params {
		switch key {
		case "format":
			cleaned := strings.ToLower(strings.TrimSpace(value))
			if cleaned != "json" && cleaned != "csv" {
				return nil, ERR_INVALID_PARAM
			}
			format = cleaned
		case "top":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 1 || parsed > reports.MaxTop {
				return nil, ERR_INVALID_PARAM
			}
			top = parsed
		default:
			return nil, ERR_INVALID_PARAM
		}
	}

	verified, unverified, fingerprints := reports.CopyTallies()
	report := reports.Build(domain, *domainData, metrics.SnapshotFor(domain), verified, unverified, fingerprints, top)

	if format == "csv" {
		return map[string]interface{}{
			"REPORT_FORMAT": "csv",
			"REPORT":        reports.ToCSV(report),
		}, ""
	}
	return map[string]interface{}{
		"REPORT": report,
	}, ""
}
