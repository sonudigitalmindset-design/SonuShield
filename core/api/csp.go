package api

// CSP report API (Batch 8).
//
// GET_CSP_REPORTS (domain, viewer) returns the most recent CSP
// violation reports for a domain, newest-first. The optional
// "limit" parameter (1..200, default 50) bounds the result.
// Reports carry the stored subset only; see core/csp.

import (
	"sonushield/core/csp"
	"sonushield/core/domains"
	"strconv"
)

func cspReportsResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	limit := 50
	for key, value := range params {
		if key != "limit" {
			return nil, ERR_INVALID_PARAM
		}
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 200 {
			return nil, ERR_INVALID_PARAM
		}
		limit = parsed
	}
	reports := []map[string]interface{}{}
	for _, report := range csp.Recent(domainSettings.Name, limit) {
		reports = append(reports, map[string]interface{}{
			"TIME":                report.Time.Format("2006-01-02T15:04:05Z07:00"),
			"DOCUMENT_URI":        report.DocumentURI,
			"BLOCKED_URI":         report.BlockedURI,
			"VIOLATED_DIRECTIVE":  report.ViolatedDirective,
			"EFFECTIVE_DIRECTIVE": report.EffectiveDirective,
			"SOURCE_FILE":         report.SourceFile,
			"LINE":                report.LineNumber,
			"COLUMN":              report.ColumnNumber,
			"STATUS":              report.StatusCode,
			"DISPOSITION":         report.Disposition,
		})
	}
	return map[string]interface{}{
		"REPORTS": reports,
		"TOTAL":   csp.Count(domainSettings.Name),
	}, ""
}
