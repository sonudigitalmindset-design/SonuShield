package api

// Control-plane actions: stage, logs, and domain configuration.
//
// These actions replace the terminal commands (stage, clrlogs, and
// reading config.json) so the dashboard can manage the proxy without
// a terminal. Same apisecret auth as every other action.
//
//   - GET_STAGE / SET_STAGE (domain): live stage state. SET_STAGE
//     mirrors the terminal "stage" command: stage 0 unlocks back to
//     automatic switching, stage 1..N locks that stage. The
//     underAttack parameter is shorthand for the same thing:
//     true locks Stage 3, false unlocks. Stage changes are
//     runtime-only: a reload or restart resets them, exactly like
//     the terminal command. Only one of "stage" / "underAttack"
//     may be given.
//   - CLEAR_LOGS (domain, or proxy for all domains): clears the
//     in-memory recent-request logs, like terminal "clrlogs".
//   - GET_DOMAINS (proxy): the configured domain list with a live
//     summary per domain. Backends and schemes come from the
//     config-file copy in memory; the "debug" pseudo-domain is
//     never listed.
//   - GET_DOMAIN_CONFIG / SET_DOMAIN_CONFIG (domain): the safe,
//     non-secret subset of a domain's settings. SET_DOMAIN_CONFIG
//     validates every parameter, persists the change to
//     config.json (atomically, with backup), and only then applies
//     it to the running proxy, so a failed write changes nothing.
//     Secrets are never accepted or returned here: challenge keys,
//     the Telegram bot token, the email password, and webhook URLs
//     (which embed a token) stay config-file-only. Structural
//     settings (name, backend, scheme, certificate/key paths) are
//     not settable: change them in config.json and reload.
//
// Unknown parameters are rejected so typos never silently pass as
// applied, matching SET_DOMAIN_FEATURES.

import (
	"encoding/json"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/utils"
	"strconv"
	"strings"
)

// configDomainInfo returns the config-file fields for a domain that
// the live DomainSettings does not carry (backend, scheme,
// certificate/key paths). Empty strings when the config copy is
// unavailable; never an error.
func configDomainInfo(domainName string) (backend, scheme, certificate, key string) {
	if domains.Config == nil {
		return "", "", "", ""
	}
	for _, domain := range domains.Config.Domains {
		if domain.Name == domainName {
			return domain.Backend, domain.Scheme, domain.Certificate, domain.Key
		}
	}
	return "", "", "", ""
}

func stageResponse(domainName string) map[string]interface{} {
	firewall.Mutex.RLock()
	data := domains.DomainsData[domainName]
	firewall.Mutex.RUnlock()
	return map[string]interface{}{
		"STAGE":             data.Stage,
		"STAGE_LOCKED":      data.StageManuallySet,
		"UNDER_ATTACK":      data.RawAttack || data.BypassAttack,
		"RAW_ATTACK":        data.RawAttack,
		"BYPASS_ATTACK":     data.BypassAttack,
		"BUFFER_COOLDOWN":   data.BufferCooldown,
		"STAGE2_DIFFICULTY": data.Stage2Difficulty,
	}
}

// applyStage validates params and, only if every param is valid,
// applies the new stage state to the live domain data. It returns
// the new stage payload, or an error code and no change.
func applyStage(domainName string, params map[string]string) (map[string]interface{}, string) {
	if len(params) == 0 {
		return nil, ERR_PARAMS_REQUIRED
	}

	stageSet := false
	stage := 0
	underAttackSet := false
	underAttack := false
	for key, value := range params {
		switch key {
		case "stage":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return nil, ERR_INVALID_PARAM
			}
			stage, stageSet = parsed, true
		case "underAttack":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, ERR_INVALID_PARAM
			}
			underAttack, underAttackSet = parsed, true
		default:
			return nil, ERR_INVALID_PARAM
		}
	}
	if stageSet && underAttackSet {
		// One instruction per call: "stage" and "underAttack"
		// are two spellings of the same switch.
		return nil, ERR_INVALID_PARAM
	}

	newStage := stage
	locked := true
	if underAttackSet {
		if underAttack {
			newStage, locked = 3, true
		} else {
			newStage, locked = 1, false
		}
	} else if stage == 0 {
		// Terminal parity: "stage 0" unlocks and returns to
		// automatic switching from Stage 1.
		newStage, locked = 1, false
	}

	firewall.Mutex.Lock()
	data, ok := domains.DomainsData[domainName]
	if !ok {
		firewall.Mutex.Unlock()
		return nil, ERR_DOMAIN_NOT_FOUND
	}
	data.Stage = newStage
	data.StageManuallySet = locked
	domains.DomainsData[domainName] = data
	firewall.Mutex.Unlock()

	return stageResponse(domainName), ""
}

func clearLogsResponse(domainName string) map[string]interface{} {
	firewall.Mutex.Lock()
	utils.ClearLogs(domainName)
	firewall.Mutex.Unlock()
	return map[string]interface{}{
		"LOGS_CLEARED": true,
		"DOMAIN":       domainName,
	}
}

func clearAllLogsResponse() map[string]interface{} {
	firewall.Mutex.Lock()
	for _, name := range domains.Domains {
		utils.ClearLogs(name)
	}
	count := len(domains.Domains)
	firewall.Mutex.Unlock()
	return map[string]interface{}{
		"LOGS_CLEARED":    true,
		"DOMAINS_CLEARED": count,
	}
}

func domainsListResponse() map[string]interface{} {
	list := []map[string]interface{}{}
	for _, name := range domains.Domains {
		uncasted, ok := domains.DomainsMap.Load(name)
		if !ok {
			continue
		}
		settings, _ := uncasted.(domains.DomainSettings)
		firewall.Mutex.RLock()
		data := domains.DomainsData[name]
		firewall.Mutex.RUnlock()
		backend, scheme, _, _ := configDomainInfo(name)
		list = append(list, map[string]interface{}{
			"NAME":              name,
			"BACKEND":           backend,
			"SCHEME":            scheme,
			"STAGE":             data.Stage,
			"STAGE_LOCKED":      data.StageManuallySet,
			"UNDER_ATTACK":      data.RawAttack || data.BypassAttack,
			"TOTAL_RPS":         data.RequestsPerSecond,
			"BYPASSED_RPS":      data.RequestsBypassedPerSecond,
			"TOTAL_REQUESTS":    data.TotalRequests,
			"BYPASSED_REQUESTS": data.BypassedRequests,
			"RULE_COUNT":        len(settings.RawCustomRules),
		})
	}
	return map[string]interface{}{
		"DOMAINS": list,
	}
}

func domainConfigResponse(domainSettings *domains.DomainSettings) map[string]interface{} {
	backend, scheme, certificate, key := configDomainInfo(domainSettings.Name)
	firewall.Mutex.RLock()
	liveDifficulty := domains.DomainsData[domainSettings.Name].Stage2Difficulty
	firewall.Mutex.RUnlock()
	return map[string]interface{}{
		"NAME":        domainSettings.Name,
		"BACKEND":     backend,
		"SCHEME":      scheme,
		"CERTIFICATE": certificate,
		"KEY":         key,

		"BYPASS_STAGE1":         domainSettings.BypassStage1,
		"BYPASS_STAGE2":         domainSettings.BypassStage2,
		"DISABLE_BYPASS_STAGE3": domainSettings.DisableBypassStage3,
		"DISABLE_RAW_STAGE3":    domainSettings.DisableRawStage3,
		"DISABLE_BYPASS_STAGE2": domainSettings.DisableBypassStage2,
		"DISABLE_RAW_STAGE2":    domainSettings.DisableRawStage2,
		"STAGE2_DIFFICULTY":     liveDifficulty,

		"ADAPTIVE_POW":       domainSettings.AdaptivePow,
		"POW_DIFFICULTY_MIN": domainSettings.PoWDifficultyMin,
		"POW_DIFFICULTY_MAX": domainSettings.PoWDifficultyMax,
		"CHALLENGE_PROVIDER": domainSettings.ChallengeProvider,
		"CHALLENGE_KEYS_CONFIGURED": domainSettings.ChallengeProvider != "" &&
			domainSettings.ChallengeSiteKey != "" &&
			domainSettings.ChallengeSecretKey != "",
		"WAF_MODE":           domainSettings.WAFMode,
		"WAF_MODE_EFFECTIVE": firewall.ResolveWAFMode(domainSettings.WAFMode),
		"WAF_INSPECT_BODY":   domainSettings.WAFInspectBody,
		"WAF_WP_LOGIN_LIMIT": domainSettings.WAFWpLoginLimit,

		"RULES_DRY_RUN": domainSettings.RulesDryRun,

		// Origin lock: configured-bool only. The secret itself is
		// config-file-only and is never accepted or returned.
		"ORIGIN_LOCK_CONFIGURED": domainSettings.OriginLockSecret != "",

		"WEBHOOK_CONFIGURED":  domainSettings.DomainWebhooks.URL != "",
		"TELEGRAM_CONFIGURED": domainSettings.DomainTelegram.BotToken != "" && domainSettings.DomainTelegram.ChatID != "",
		"TELEGRAM_CHAT_ID":    domainSettings.DomainTelegram.ChatID,
		"EMAIL_CONFIGURED":    domainSettings.DomainEmail.SMTPHost != "" && domainSettings.DomainEmail.To != "",
		"EMAIL_SMTP_HOST":     domainSettings.DomainEmail.SMTPHost,
		"EMAIL_SMTP_PORT":     domainSettings.DomainEmail.SMTPPort,
		"EMAIL_USERNAME":      domainSettings.DomainEmail.Username,
		"EMAIL_FROM":          domainSettings.DomainEmail.From,
		"EMAIL_TO":            domainSettings.DomainEmail.To,
		"EMAIL_USE_TLS":       domainSettings.DomainEmail.UseTLS,

		"RULE_COUNT": len(domainSettings.RawCustomRules),
	}
}

// applyDomainConfig validates params against a copy of the domain
// settings, persists the change to config.json, and only then
// applies it to the running proxy. On any invalid input or any
// write failure it returns an error code (and, for write failures,
// a detail message) with nothing changed.
func applyDomainConfig(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string, string) {
	if len(params) == 0 {
		return nil, ERR_PARAMS_REQUIRED, ""
	}

	updated := *domainSettings
	// Config-file keys to write, in the file's own naming.
	pending := map[string]interface{}{}
	stage2Set := false
	stage2Value := 0

	parseNonNegative := func(value string) (int, bool) {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			return 0, false
		}
		return parsed, true
	}

	for key, value := range params {
		switch key {
		case "bypassStage1", "bypassStage2",
			"disableBypassStage3", "disableRawStage3",
			"disableBypassStage2", "disableRawStage2":
			parsed, ok := parseNonNegative(value)
			if !ok {
				return nil, ERR_INVALID_PARAM, ""
			}
			switch key {
			case "bypassStage1":
				updated.BypassStage1 = parsed
			case "bypassStage2":
				updated.BypassStage2 = parsed
			case "disableBypassStage3":
				updated.DisableBypassStage3 = parsed
			case "disableRawStage3":
				updated.DisableRawStage3 = parsed
			case "disableBypassStage2":
				updated.DisableBypassStage2 = parsed
			case "disableRawStage2":
				updated.DisableRawStage2 = parsed
			}
			pending[key] = parsed
		case "stage2Difficulty":
			// 0 means "unset" (Load defaults it to 5); 1..16
			// are explicit difficulties.
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 || parsed > 16 {
				return nil, ERR_INVALID_PARAM, ""
			}
			stage2Set, stage2Value = true, parsed
			pending[key] = parsed
		case "adaptivePow":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, ERR_INVALID_PARAM, ""
			}
			updated.AdaptivePow = parsed
			pending[key] = parsed
		case "powDifficultyMin", "powDifficultyMax":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 || parsed > 16 {
				return nil, ERR_INVALID_PARAM, ""
			}
			if key == "powDifficultyMin" {
				updated.PoWDifficultyMin = parsed
			} else {
				updated.PoWDifficultyMax = parsed
			}
			pending[key] = parsed
		case "wafMode":
			mode := strings.ToLower(strings.TrimSpace(value))
			switch mode {
			case "off", "log", "block":
				updated.WAFMode = mode
			default:
				return nil, ERR_INVALID_PARAM, ""
			}
			pending[key] = mode
		case "wafInspectBody":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, ERR_INVALID_PARAM, ""
			}
			updated.WAFInspectBody = parsed
			pending[key] = parsed
		case "wafWpLoginLimit":
			parsed, ok := parseNonNegative(value)
			if !ok {
				return nil, ERR_INVALID_PARAM, ""
			}
			updated.WAFWpLoginLimit = parsed
			pending[key] = parsed
		case "rulesDryRun":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, ERR_INVALID_PARAM, ""
			}
			updated.RulesDryRun = parsed
			pending[key] = parsed
		default:
			// Unknown keys are rejected: names, backends,
			// schemes, certificate paths, webhooks, alert
			// credentials, and challenge keys are deliberately
			// not settable through the API.
			return nil, ERR_INVALID_PARAM, ""
		}
	}

	if updated.PoWDifficultyMin > 0 && updated.PoWDifficultyMax > 0 &&
		updated.PoWDifficultyMin > updated.PoWDifficultyMax {
		return nil, ERR_INVALID_PARAM, ""
	}

	// Persist first: a failed write must leave the running proxy
	// untouched, so the file and the live settings can never
	// disagree about what was applied.
	if err := updateConfigDomain(updated.Name, func(domain map[string]json.RawMessage) error {
		for key, value := range pending {
			if err := setRawField(domain, key, value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, ERR_CONFIG_WRITE_FAILED, err.Error()
	}

	domains.DomainsMap.Store(updated.Name, updated)
	if stage2Set {
		live := stage2Value
		if live == 0 {
			live = 5
		}
		firewall.Mutex.Lock()
		if data, ok := domains.DomainsData[updated.Name]; ok {
			data.Stage2Difficulty = live
			domains.DomainsData[updated.Name] = data
		}
		firewall.Mutex.Unlock()
	}
	syncDomainConfigMemory(updated.Name, func(domain *domains.Domain) {
		domain.BypassStage1 = updated.BypassStage1
		domain.BypassStage2 = updated.BypassStage2
		domain.DisableBypassStage3 = updated.DisableBypassStage3
		domain.DisableRawStage3 = updated.DisableRawStage3
		domain.DisableBypassStage2 = updated.DisableBypassStage2
		domain.DisableRawStage2 = updated.DisableRawStage2
		if stage2Set {
			domain.Stage2Difficulty = stage2Value
		}
		domain.AdaptivePow = updated.AdaptivePow
		domain.PoWDifficultyMin = updated.PoWDifficultyMin
		domain.PoWDifficultyMax = updated.PoWDifficultyMax
		domain.WAFMode = updated.WAFMode
		domain.WAFInspectBody = updated.WAFInspectBody
		domain.WAFWpLoginLimit = updated.WAFWpLoginLimit
		domain.RulesDryRun = updated.RulesDryRun
	})

	return domainConfigResponse(&updated), "", ""
}
