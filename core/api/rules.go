package api

// Firewall rule CRUD for the control panel.
//
//   - ADD_RULE: append one rule (params: expression, action).
//   - UPDATE_RULE: change one rule (params: index, plus expression
//     and/or action; omitted fields keep their current value).
//   - DELETE_RULE: remove one rule (params: index).
//
// Index is 0-based, matching the order GET_FIREWALL_RULES returns
// (evaluation order, first rule first). All three actions return the
// updated rule list in the same FIREWALL_RULES shape.
//
// Validation happens before anything changes, and the whole list is
// compiled before it is stored, so an invalid rule can never reach
// the running proxy or the config file:
//
//   - The expression must compile in the gofilter engine, the same
//     check Load() applies to config-file rules.
//   - Every dotted field name in the expression must be one of the
//     documented, populated rule fields (see docs/firewall-rules.md).
//     The engine silently never matches unknown fields, so without
//     this check a typo would create a rule that looks live but
//     does nothing. The registered-but-never-populated names
//     (ip.requests, http.headers, http.body) are rejected too,
//     matching the documentation.
//   - The action must be a plain integer (static suspicion level)
//     or +N / -N (adjust the level and keep evaluating). An empty
//     or non-numeric action would crash request evaluation, so it
//     is rejected here.
//
// Changes persist to config.json (atomically, with backup) before
// they are applied to the running proxy. The read-modify-persist-
// apply sequence is serialised per process so two concurrent rule
// edits can never lose each other's rules.

import (
	"encoding/json"
	"errors"
	"regexp"
	"sonushield/core/domains"
	"strconv"
	"strings"
	"sync"

	"github.com/kor44/gofilter"
)

var ruleMutex sync.Mutex

// ruleFields is the set of field names a rule expression may use:
// every field the proxy populates, as documented in
// docs/firewall-rules.md.
var ruleFields = map[string]bool{
	"ip.src": true, "ip.country": true, "ip.asn": true,
	"ip.engine": true, "ip.bot": true, "ip.fingerprint": true,
	"ip.ja4": true, "ip.reputation": true, "ip.searchbot": true,
	"ip.os": true, "ip.tcpinfo": true, "ip.behavior": true,
	"ip.risk": true, "ip.timing": true, "ip.http_requests": true, "ip.challenge_requests": true,
	"http.host": true, "http.version": true, "http.method": true,
	"http.url": true, "http.query": true, "http.path": true,
	"http.user_agent": true, "http.cookie": true,
	"http.fingerprint": true, "http.http2": true,
	"proxy.stage":      true, "proxy.cloudflare": true,
	"proxy.stage_locked": true, "proxy.attack": true,
	"proxy.bypass_attack": true, "proxy.rps": true,
	"proxy.rps_allowed": true,
}

var (
	// Double-quoted string literals, with backslash escapes, so
	// dotted text inside a literal (e.g. "example.com") is never
	// mistaken for a field name.
	ruleStringLiteral = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	// Dotted identifiers starting with a letter: field references.
	// Numeric literals (1.2.3.4) and bare keywords (and, or, not,
	// eq, contains, matches) never match this pattern.
	ruleFieldToken = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+`)
)

// validateRuleExpression compiles the expression and checks every
// field name it references. It returns a human-readable reason when
// the expression is not usable.
func validateRuleExpression(expression string) error {
	if strings.TrimSpace(expression) == "" {
		return errors.New("expression must not be empty")
	}
	if _, err := gofilter.NewFilter(expression); err != nil {
		return errors.New("expression does not compile: " + err.Error())
	}
	stripped := ruleStringLiteral.ReplaceAllString(expression, `""`)
	for _, token := range ruleFieldToken.FindAllString(stripped, -1) {
		if !ruleFields[token] {
			return errors.New("unknown rule field: " + token)
		}
	}
	return nil
}

// validateRuleAction checks the action spelling. The evaluator
// indexes the first byte and scans the rest as an integer, so
// anything else would fail or crash at request time.
func validateRuleAction(action string) error {
	if !domains.ValidRuleAction(action) {
		return errors.New("action must be an integer, +N, or -N")
	}
	return nil
}

func validateRule(rule domains.JsonRule) error {
	if err := validateRuleExpression(rule.Expression); err != nil {
		return err
	}
	if err := validateRuleAction(rule.Action); err != nil {
		return err
	}
	// Schedules (Batch 7): an invalid cron expression is
	// rejected at write time, so bad schedules cannot enter
	// through the control panel. Hand-edited configs with
	// bad schedules still load (fail-safe, always active).
	if err := domains.ValidateSchedule(rule.Schedule); err != nil {
		return errors.New("schedule is invalid: " + err.Error())
	}
	return nil
}

// compileRules compiles a whole rule list. Every rule is checked, so
// a list is only ever stored when all of it evaluates.
func compileRules(raw []domains.JsonRule) ([]domains.Rule, error) {
	compiled := make([]domains.Rule, 0, len(raw))
	for i, rawRule := range raw {
		filter, err := gofilter.NewFilter(rawRule.Expression)
		if err != nil {
			return nil, errors.New("rule " + strconv.Itoa(i) + " does not compile: " + err.Error())
		}
		var schedule *domains.Schedule
		if strings.TrimSpace(rawRule.Schedule) != "" {
			parsed, err := domains.ParseSchedule(rawRule.Schedule)
			if err != nil {
				return nil, errors.New("rule " + strconv.Itoa(i) + " schedule is invalid: " + err.Error())
			}
			schedule = parsed
		}
		compiled = append(compiled, domains.Rule{Filter: filter, Action: rawRule.Action, Schedule: schedule})
	}
	return compiled, nil
}

// applyRuleList persists a new rule list for a domain and applies it
// to the running proxy. The caller must hold ruleMutex and pass the
// freshly loaded settings. On any failure nothing changes.
func applyRuleList(domainName string, settings domains.DomainSettings, newRaw []domains.JsonRule) (map[string]interface{}, string, string) {
	compiled, err := compileRules(newRaw)
	if err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}

	if err := updateConfigDomain(domainName, func(domain map[string]json.RawMessage) error {
		return setRawField(domain, "firewallRules", newRaw)
	}); err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}

	settings.CustomRules = compiled
	settings.RawCustomRules = newRaw
	domains.DomainsMap.Store(domainName, settings)
	syncDomainConfigMemory(domainName, func(domain *domains.Domain) {
		domain.FirewallRules = newRaw
	})

	return map[string]interface{}{
		"FIREWALL_RULES": newRaw,
	}, "", ""
}

func loadFreshSettings(domainName string) (domains.DomainSettings, bool) {
	uncasted, ok := domains.DomainsMap.Load(domainName)
	if !ok {
		return domains.DomainSettings{}, false
	}
	settings, _ := uncasted.(domains.DomainSettings)
	return settings, true
}

// addRule appends one validated rule. Params: expression, action,
// schedule (optional cron expression; empty means always active).
func addRule(domainName string, params map[string]string) (map[string]interface{}, string, string) {
	expression, hasExpression := params["expression"]
	action, hasAction := params["action"]
	for key := range params {
		if key != "expression" && key != "action" && key != "schedule" {
			return nil, ERR_INVALID_PARAM, ""
		}
	}
	if !hasExpression || !hasAction {
		return nil, ERR_PARAMS_REQUIRED, ""
	}
	rule := domains.JsonRule{Expression: expression, Action: action, Schedule: params["schedule"]}
	if err := validateRule(rule); err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}

	ruleMutex.Lock()
	defer ruleMutex.Unlock()
	settings, ok := loadFreshSettings(domainName)
	if !ok {
		return nil, ERR_DOMAIN_NOT_FOUND, ""
	}
	newRaw := make([]domains.JsonRule, 0, len(settings.RawCustomRules)+1)
	newRaw = append(newRaw, settings.RawCustomRules...)
	newRaw = append(newRaw, rule)
	return applyRuleList(domainName, settings, newRaw)
}

// updateRule changes one rule. Params: index (0-based), plus
// expression, action, and/or schedule. At least one of
// expression/action/schedule is required; omitted fields keep
// their current value. An empty schedule clears the schedule.
func updateRule(domainName string, params map[string]string) (map[string]interface{}, string, string) {
	indexRaw, hasIndex := params["index"]
	_, hasExpression := params["expression"]
	_, hasAction := params["action"]
	_, hasSchedule := params["schedule"]
	for key := range params {
		if key != "index" && key != "expression" && key != "action" && key != "schedule" {
			return nil, ERR_INVALID_PARAM, ""
		}
	}
	if !hasIndex || (!hasExpression && !hasAction && !hasSchedule) {
		return nil, ERR_PARAMS_REQUIRED, ""
	}
	index, err := strconv.Atoi(indexRaw)
	if err != nil || index < 0 {
		return nil, ERR_INVALID_PARAM, ""
	}

	ruleMutex.Lock()
	defer ruleMutex.Unlock()
	settings, ok := loadFreshSettings(domainName)
	if !ok {
		return nil, ERR_DOMAIN_NOT_FOUND, ""
	}
	if index >= len(settings.RawCustomRules) {
		return nil, ERR_INVALID_PARAM, "rule index out of range"
	}
	updated := settings.RawCustomRules[index]
	if hasExpression {
		updated.Expression = params["expression"]
	}
	if hasAction {
		updated.Action = params["action"]
	}
	if hasSchedule {
		updated.Schedule = params["schedule"]
	}
	if err := validateRule(updated); err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	newRaw := make([]domains.JsonRule, len(settings.RawCustomRules))
	copy(newRaw, settings.RawCustomRules)
	newRaw[index] = updated
	return applyRuleList(domainName, settings, newRaw)
}

// deleteRule removes one rule. Params: index (0-based).
func deleteRule(domainName string, params map[string]string) (map[string]interface{}, string, string) {
	indexRaw, hasIndex := params["index"]
	for key := range params {
		if key != "index" {
			return nil, ERR_INVALID_PARAM, ""
		}
	}
	if !hasIndex {
		return nil, ERR_PARAMS_REQUIRED, ""
	}
	index, err := strconv.Atoi(indexRaw)
	if err != nil || index < 0 {
		return nil, ERR_INVALID_PARAM, ""
	}

	ruleMutex.Lock()
	defer ruleMutex.Unlock()
	settings, ok := loadFreshSettings(domainName)
	if !ok {
		return nil, ERR_DOMAIN_NOT_FOUND, ""
	}
	if index >= len(settings.RawCustomRules) {
		return nil, ERR_INVALID_PARAM, "rule index out of range"
	}
	newRaw := make([]domains.JsonRule, 0, len(settings.RawCustomRules)-1)
	newRaw = append(newRaw, settings.RawCustomRules[:index]...)
	newRaw = append(newRaw, settings.RawCustomRules[index+1:]...)
	return applyRuleList(domainName, settings, newRaw)
}
