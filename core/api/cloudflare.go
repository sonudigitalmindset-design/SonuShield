package api

// Cloudflare import (Batch 7).
//
// CF_PREVIEW_IMPORT fetches a domain's Cloudflare firewall
// rules (using the operator's own API token and zone ID
// from the domain configuration — config-only, never
// accepted as a parameter, never logged, never returned)
// and returns a read-only plan: translated rules, rules
// skipped with a reason, and the Cloudflare settings this
// import deliberately does not touch. Nothing is changed.
//
// CF_APPLY_IMPORT re-fetches and re-translates (it never
// trusts a stale preview) and applies the translated rules
// like a rule import: validated, compiled, and stored
// all-or-nothing, in append mode by default (replace is
// available via MODE=replace). Applying is an admin action.
//
// The expression subset and action mapping live in
// cftranslate.go. Zone settings are never imported: the
// preview lists the setting categories that stay untouched
// so the operator is not left guessing.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sonushield/core/domains"
)

const (
	cfDefaultAPIBase = "https://api.cloudflare.com"
	cfFetchTimeout   = 10 * time.Second
	cfMaxResponse    = 1 << 20 // 1 MB per page
	cfMaxPages       = 10
	cfPerPage        = 100
)

// cfNotImportedSettings lists Cloudflare setting categories
// the import never evaluates or changes.
var cfNotImportedSettings = []string{
	"security_level (Cloudflare Security Level) — use SonuShield stages and rules instead",
	"browser_check (Browser Integrity Check) — no equivalent is imported",
	"challenge_ttl (Challenge Passage) — SonuShield challenge cookies use their own TTL",
	"privacy_pass and managed-challenge tuning — no equivalent is imported",
	"rate limiting rules — a separate Cloudflare product; use SonuShield rate limits",
	"WAF managed rules and custom rulesets — only legacy firewall rules are read",
}

// cfFirewallRule is one rule in the Cloudflare list response.
type cfFirewallRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Paused      bool   `json:"paused"`
	Action      string `json:"action"`
	Filter      struct {
		Expression string `json:"expression"`
		Paused     bool   `json:"paused"`
	} `json:"filter"`
}

// cfListResponse is the Cloudflare firewall-rules list envelope.
type cfListResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result     []cfFirewallRule `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// cfTranslatedRule is one rule the plan can apply.
type cfTranslatedRule struct {
	CFExpression  string   `json:"cf_expression"`
	CFAction      string   `json:"cf_action"`
	CFDescription string   `json:"cf_description"`
	Expression    string   `json:"expression"`
	Action        string   `json:"action"`
	Notes         []string `json:"notes,omitempty"`
}

// cfSkippedRule is one rule the plan cannot apply, with the reason.
type cfSkippedRule struct {
	CFExpression  string `json:"cf_expression"`
	CFAction      string `json:"cf_action"`
	CFDescription string `json:"cf_description"`
	Reason        string `json:"reason"`
}

// cfPlan is the full import plan.
type cfPlan struct {
	Translated []cfTranslatedRule `json:"translated"`
	Skipped    []cfSkippedRule    `json:"skipped"`
}

// cfCredentials returns the domain's Cloudflare settings
// from the live configuration, or an error when they are
// not configured. The token is returned only to the caller
// in this file, for the Authorization header.
func cfCredentials(domainName string) (token, zoneID, base string, err error) {
	if domains.Config == nil {
		return "", "", "", errors.New("no configuration loaded")
	}
	for _, domain := range domains.Config.Domains {
		if domain.Name != domainName {
			continue
		}
		if domain.CloudflareAPIToken == "" || domain.CloudflareZoneID == "" {
			return "", "", "", errors.New("configure cloudflareApiToken and cloudflareZoneId for this domain in config.json")
		}
		base = strings.TrimRight(domain.CloudflareAPIBase, "/")
		if base == "" {
			base = cfDefaultAPIBase
		}
		return domain.CloudflareAPIToken, domain.CloudflareZoneID, base, nil
	}
	return "", "", "", errors.New("domain not found in configuration")
}

// fetchCFRules lists all firewall rules for a zone,
// following pagination up to cfMaxPages pages.
func fetchCFRules(base, token, zoneID string) ([]cfFirewallRule, error) {
	client := &http.Client{Timeout: cfFetchTimeout}
	var all []cfFirewallRule
	for page := 1; page <= cfMaxPages; page++ {
		url := fmt.Sprintf("%s/client/v4/zones/%s/firewall/rules?page=%d&per_page=%d", base, zoneID, page, cfPerPage)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("could not reach the Cloudflare API: %v", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, cfMaxResponse+1))
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("could not read the Cloudflare API response: %v", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Cloudflare API returned HTTP %d", resp.StatusCode)
		}
		if len(data) > cfMaxResponse {
			return nil, errors.New("Cloudflare API response exceeds the 1 MB cap")
		}
		var envelope cfListResponse
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, fmt.Errorf("Cloudflare API response is not valid: %v", err)
		}
		if !envelope.Success {
			message := "unknown error"
			if len(envelope.Errors) > 0 && envelope.Errors[0].Message != "" {
				message = envelope.Errors[0].Message
			}
			return nil, fmt.Errorf("Cloudflare API reported failure: %s", message)
		}
		all = append(all, envelope.Result...)
		if envelope.ResultInfo.TotalPages <= page || len(envelope.Result) == 0 {
			break
		}
	}
	return all, nil
}

// buildCFPlan fetches and translates the domain's
// Cloudflare firewall rules into an import plan.
func buildCFPlan(domainName string) (*cfPlan, string, string) {
	token, zoneID, base, err := cfCredentials(domainName)
	if err != nil {
		if strings.Contains(err.Error(), "configure cloudflareApiToken") {
			return nil, ERR_PARAMS_REQUIRED, err.Error()
		}
		return nil, ERR_DOMAIN_NOT_FOUND, ""
	}
	rules, err := fetchCFRules(base, token, zoneID)
	if err != nil {
		return nil, ERR_FETCH_FAILED, err.Error()
	}
	plan := &cfPlan{Translated: []cfTranslatedRule{}, Skipped: []cfSkippedRule{}}
	for _, rule := range rules {
		skip := func(reason string) {
			plan.Skipped = append(plan.Skipped, cfSkippedRule{
				CFExpression:  rule.Filter.Expression,
				CFAction:      rule.Action,
				CFDescription: rule.Description,
				Reason:        reason,
			})
		}
		if rule.Paused || rule.Filter.Paused {
			skip("paused in Cloudflare")
			continue
		}
		if strings.TrimSpace(rule.Filter.Expression) == "" {
			skip("no filter expression")
			continue
		}
		action, ok := translateCFAction(rule.Action)
		if !ok {
			skip(fmt.Sprintf("action %q has no SonuShield equivalent (log and skip actions are not imported)", rule.Action))
			continue
		}
		expression, notes, err := translateCFExpression(rule.Filter.Expression)
		if err != nil {
			skip("expression uses features outside the supported subset: " + err.Error())
			continue
		}
		if err := validateRuleExpression(expression); err != nil {
			skip("translated expression does not compile: " + err.Error())
			continue
		}
		plan.Translated = append(plan.Translated, cfTranslatedRule{
			CFExpression:  rule.Filter.Expression,
			CFAction:      rule.Action,
			CFDescription: rule.Description,
			Expression:    expression,
			Action:        action,
			Notes:         notes,
		})
	}
	return plan, "", ""
}

// cfPreviewImport builds the CF_PREVIEW_IMPORT response.
// Read-only: nothing is stored.
func cfPreviewImport(domainName string, params map[string]string) (map[string]interface{}, string, string) {
	for range params {
		return nil, ERR_INVALID_PARAM, ""
	}
	plan, errCode, detail := buildCFPlan(domainName)
	if errCode != "" {
		return nil, errCode, detail
	}
	return map[string]interface{}{
		"TRANSLATED":            plan.Translated,
		"SKIPPED":               plan.Skipped,
		"TRANSLATED_COUNT":      len(plan.Translated),
		"SKIPPED_COUNT":         len(plan.Skipped),
		"NOT_IMPORTED_SETTINGS": cfNotImportedSettings,
		"NOTE":                  "Read-only preview: nothing was changed. Run CF_APPLY_IMPORT to apply the translated rules.",
	}, "", ""
}

// cfApplyImport re-fetches, re-translates, and applies the
// translated rules like a rule import. MODE defaults to
// append (unlike IMPORT_RULES, which defaults to replace):
// a Cloudflare import must not wipe local rules by
// accident.
func cfApplyImport(domainName string, params map[string]string) (map[string]interface{}, string, string) {
	for key := range params {
		if key != "MODE" {
			return nil, ERR_INVALID_PARAM, "unknown parameter: " + key
		}
	}
	mode := strings.ToLower(strings.TrimSpace(params["MODE"]))
	if mode == "" {
		mode = "append"
	}
	if mode != "replace" && mode != "append" {
		return nil, ERR_INVALID_PARAM, "MODE must be replace or append"
	}
	plan, errCode, detail := buildCFPlan(domainName)
	if errCode != "" {
		return nil, errCode, detail
	}
	imported := make([]domains.JsonRule, 0, len(plan.Translated))
	for _, rule := range plan.Translated {
		imported = append(imported, domains.JsonRule{Expression: rule.Expression, Action: rule.Action})
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
	response["APPLIED"] = len(imported)
	response["SKIPPED_COUNT"] = len(plan.Skipped)
	response["SKIPPED"] = plan.Skipped
	response["MODE"] = mode
	return response, "", ""
}
