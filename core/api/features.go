package api

// Authenticated API actions for Batch 1 feature controls.
//
// Purpose: every Batch 1 control must be usable without a terminal.
// Settings are defined in config.json, and these actions let the
// dashboard (or any control-plane client holding the API secret) read
// the live settings and adjust the runtime-tunable ones. No new
// terminal command is the only way to use a Batch 1 feature.
//
// Actions:
//   - GET_PROXY_FEATURES (proxy): quiet mode, auto SSL, Geo database
//     status, reputation feed status and set sizes.
//   - REFRESH_REPUTATION_FEED (proxy): trigger a background feed
//     refresh; fail-open exactly like the scheduled refresh.
//   - GET_DOMAIN_FEATURES (domain): adaptive PoW, challenge provider,
//     WAF-lite settings. Challenge keys are NEVER returned: only the
//     provider name and whether keys are configured.
//   - SET_DOMAIN_FEATURES (domain): adjust adaptivePow,
//     powDifficultyMin/Max, wafMode, wafInspectBody, wafWpLoginLimit.
//     Parameters arrive as v1 "params" or v2 query parameters.
//     Challenge provider/keys are deliberately NOT settable here:
//     secrets stay in config.json only.
//
// SET changes apply to the running proxy only. They are NOT written
// back to config.json: a reload or restart restores the config-file
// values. Persisting dashboard edits to the config file is future
// control-panel work. A full config reload from the API is not
// offered: the existing reload path panics on invalid config, which
// must never be reachable from an API call.

import (
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"strconv"
	"strings"
)

// queryParams converts URL query values to the same parameter map the
// v1 JSON body uses (first value wins per key).
func queryParams(request *http.Request) map[string]string {
	values := request.URL.Query()
	if len(values) == 0 {
		return nil
	}
	params := make(map[string]string, len(values))
	for key, vals := range values {
		if len(vals) > 0 {
			params[key] = vals[0]
		}
	}
	return params
}

func proxyFeaturesResponse() map[string]interface{} {
	quietMode := false
	autoSSL := false
	if domains.Config != nil {
		quietMode = domains.Config.Proxy.QuietMode
		autoSSL = domains.Config.Proxy.AutoSSL
	}
	countryLoaded, asnLoaded := firewall.GeoStatus()
	feedConfigured, feedInterval, localIPs, localNets, feedIPs, feedNets, bump, lastSuccess, lastError := firewall.ReputationStatus()
	return map[string]interface{}{
		"QUIET_MODE":                       quietMode,
		"AUTO_SSL":                         autoSSL,
		"AUTO_SSL_ACTIVE":                  domains.AutoCertActive(),
		"GEO_COUNTRY_LOADED":               countryLoaded,
		"GEO_ASN_LOADED":                   asnLoaded,
		"REPUTATION_FEED_CONFIGURED":       feedConfigured,
		"REPUTATION_FEED_INTERVAL_MINUTES": feedInterval,
		"REPUTATION_LOCAL_IPS":             localIPs,
		"REPUTATION_LOCAL_NETWORKS":        localNets,
		"REPUTATION_FEED_IPS":              feedIPs,
		"REPUTATION_FEED_NETWORKS":         feedNets,
		"REPUTATION_BUMP":                  bump,
		"REPUTATION_FEED_LAST_SUCCESS":     lastSuccess,
		"REPUTATION_FEED_LAST_ERROR":       lastError,
	}
}

func domainFeaturesResponse(domainSettings *domains.DomainSettings) map[string]interface{} {
	return map[string]interface{}{
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
	}
}

// applyDomainFeatures validates params against a copy of the domain
// settings and, only if every param is valid, stores the updated
// settings. It returns the new feature payload, or an error code and
// no change on any invalid input.
func applyDomainFeatures(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	if len(params) == 0 {
		return nil, ERR_PARAMS_REQUIRED
	}

	updated := *domainSettings
	for key, value := range params {
		switch key {
		case "adaptivePow":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, ERR_INVALID_PARAM
			}
			updated.AdaptivePow = parsed
		case "powDifficultyMin", "powDifficultyMax":
			// 0 means "unset" (min defaults to the base difficulty,
			// max to base+3); 1..16 are explicit bounds.
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 || parsed > 16 {
				return nil, ERR_INVALID_PARAM
			}
			if key == "powDifficultyMin" {
				updated.PoWDifficultyMin = parsed
			} else {
				updated.PoWDifficultyMax = parsed
			}
		case "wafMode":
			mode := strings.ToLower(strings.TrimSpace(value))
			switch mode {
			case "off", "log", "block":
				updated.WAFMode = mode
			default:
				return nil, ERR_INVALID_PARAM
			}
		case "wafInspectBody":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, ERR_INVALID_PARAM
			}
			updated.WAFInspectBody = parsed
		case "wafWpLoginLimit":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return nil, ERR_INVALID_PARAM
			}
			updated.WAFWpLoginLimit = parsed
		default:
			// Unknown keys are rejected so typos never silently
			// pass as applied.
			return nil, ERR_INVALID_PARAM
		}
	}

	if updated.PoWDifficultyMin > 0 && updated.PoWDifficultyMax > 0 &&
		updated.PoWDifficultyMin > updated.PoWDifficultyMax {
		return nil, ERR_INVALID_PARAM
	}

	domains.DomainsMap.Store(updated.Name, updated)
	return domainFeaturesResponse(&updated), ""
}
