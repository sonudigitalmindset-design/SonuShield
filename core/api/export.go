package api

// Firewall rule export/import (Batch 4).
//
// EXPORT_RULES returns a domain's rule set as JSON: the same
// {"expression", "action"} objects GET_FIREWALL_RULES returns,
// plus the domain name and a count.
//
// IMPORT_RULES replaces or appends a rule set from a JSON array
// of those objects (params: rules, mode=replace|append; replace
// is the default). Every imported rule goes through the same
// validation as rule CRUD — the expression must compile and use
// only known fields, and the action must be a valid spelling —
// and the whole resulting list is compiled before anything is
// stored, so an invalid import is rejected with nothing changed.
// The import is capped at 1 MB.

import (
	"bytes"
	"encoding/json"
	"sonushield/core/domains"
	"strconv"
	"strings"
)

const maxImportRulesSize = 1 << 20 // 1 MB

// exportRules returns a domain's rule set for download.
func exportRules(domainName string, settings *domains.DomainSettings) map[string]interface{} {
	rules := settings.RawCustomRules
	if rules == nil {
		rules = []domains.JsonRule{}
	}
	return map[string]interface{}{
		"RULES":      rules,
		"DOMAIN":     domainName,
		"RULE_COUNT": len(rules),
	}
}

// importRules validates and applies an imported rule set.
func importRules(domainName string, params map[string]string) (map[string]interface{}, string, string) {
	for key := range params {
		if key != "rules" && key != "mode" {
			return nil, ERR_INVALID_PARAM, ""
		}
	}
	raw, ok := params["rules"]
	if !ok {
		return nil, ERR_PARAMS_REQUIRED, ""
	}
	if len(raw) > maxImportRulesSize {
		return nil, ERR_INVALID_PARAM, "rules payload too large"
	}
	mode := strings.ToLower(strings.TrimSpace(params["mode"]))
	if mode == "" {
		mode = "replace"
	}
	if mode != "replace" && mode != "append" {
		return nil, ERR_INVALID_PARAM, "mode must be replace or append"
	}

	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	var imported []domains.JsonRule
	if err := decoder.Decode(&imported); err != nil {
		return nil, ERR_INVALID_PARAM, "rules is not a JSON array of {expression, action} objects: " + err.Error()
	}
	if imported == nil {
		imported = []domains.JsonRule{}
	}
	for i, rule := range imported {
		if err := validateRule(rule); err != nil {
			return nil, ERR_INVALID_PARAM, "rule " + strconv.Itoa(i) + ": " + err.Error()
		}
	}

	ruleMutex.Lock()
	defer ruleMutex.Unlock()
	settings, ok := loadFreshSettings(domainName)
	if !ok {
		return nil, ERR_DOMAIN_NOT_FOUND, ""
	}
	var newRaw []domains.JsonRule
	switch mode {
	case "append":
		newRaw = make([]domains.JsonRule, 0, len(settings.RawCustomRules)+len(imported))
		newRaw = append(newRaw, settings.RawCustomRules...)
		newRaw = append(newRaw, imported...)
	default:
		newRaw = imported
	}
	response, errCode, detail := applyRuleList(domainName, settings, newRaw)
	if errCode != "" {
		return nil, errCode, detail
	}
	response["IMPORTED"] = len(imported)
	return response, "", ""
}
