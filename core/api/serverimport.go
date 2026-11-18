package api

// Nginx/Apache configuration import (Batch 8).
//
// PREVIEW_SERVER_IMPORT (operator) parses pasted nginx or
// Apache configuration and reports exactly what would be
// imported, what would be skipped, and what has no
// equivalent — without changing anything. APPLY_SERVER_IMPORT
// (admin) parses the same input and creates the domains
// through the bulk-import machinery (all-or-nothing,
// validated, persisted, reloaded), returning the same report
// alongside the result so dropped directives stay visible.
//
// Params: format (nginx|apache), data (the config text),
// template (optional, default "standard"). Data is capped at
// 1 MB like bulk import. The parse itself never writes.

import (
	"sonushield/core/importcfg"
	"strconv"
)

func serverImportParams(params map[string]string) (format, data, template string, errCode, detail string) {
	for key, value := range params {
		switch key {
		case "format":
			format = value
		case "data":
			data = value
		case "template":
			template = value
		default:
			return "", "", "", ERR_INVALID_PARAM, ""
		}
	}
	if data == "" {
		return "", "", "", ERR_PARAMS_REQUIRED, ""
	}
	if len(data) > maxImportDomainsSize {
		return "", "", "", ERR_INVALID_PARAM, "import payload too large"
	}
	if format != "nginx" && format != "apache" {
		return "", "", "", ERR_INVALID_PARAM, "format must be nginx or apache"
	}
	return format, data, template, "", ""
}

func serverImportReportResponse(report importcfg.Report) map[string]interface{} {
	domains := []map[string]interface{}{}
	for _, domain := range report.Domains {
		domains = append(domains, map[string]interface{}{
			"NAME":        domain.Name,
			"BACKEND":     domain.Backend,
			"SCHEME":      domain.Scheme,
			"CERTIFICATE": domain.Certificate,
			"KEY":         domain.Key,
			"SOURCE":      domain.Source,
		})
	}
	return map[string]interface{}{
		"DOMAINS":      domains,
		"COUNT":        len(domains),
		"SKIPPED":      report.Skipped,
		"WARNINGS":     report.Warnings,
		"NOT_IMPORTED": report.NotImported,
	}
}

func previewServerImport(params map[string]string) (map[string]interface{}, string, string) {
	format, data, _, errCode, detail := serverImportParams(params)
	if errCode != "" {
		return nil, errCode, detail
	}
	report, err := importcfg.Parse(format, data)
	if err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	return serverImportReportResponse(report), "", ""
}

func applyServerImport(params map[string]string) (map[string]interface{}, string, string) {
	format, data, template, errCode, detail := serverImportParams(params)
	if errCode != "" {
		return nil, errCode, detail
	}
	report, err := importcfg.Parse(format, data)
	if err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	if len(report.Domains) == 0 {
		return nil, ERR_INVALID_PARAM, "no importable domains found in the pasted configuration"
	}
	entries := make([]domainImportEntry, 0, len(report.Domains))
	labels := make([]string, 0, len(report.Domains))
	for i, domain := range report.Domains {
		entries = append(entries, domainImportEntry{
			Name: domain.Name, Backend: domain.Backend,
			Scheme: domain.Scheme, Template: template,
			Certificate: domain.Certificate, Key: domain.Key,
		})
		labels = append(labels, domain.Source+" domain "+strconv.Itoa(i+1))
	}
	built, errCode, detail := buildImportedDomains(entries, labels)
	if errCode != "" {
		return nil, errCode, detail
	}
	response, errCode, detail := appendDomainsAndReload(built)
	if errCode != "" {
		return nil, errCode, detail
	}
	response["SKIPPED"] = report.Skipped
	response["WARNINGS"] = report.Warnings
	response["NOT_IMPORTED"] = report.NotImported
	return response, "", ""
}
