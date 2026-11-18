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
// values. For the same settings with persistence, use the
// control-panel action SET_DOMAIN_CONFIG, which validates, writes
// config.json atomically, and then applies. A full config reload
// from the API is offered by the RELOAD action, which validates the
// config file before applying it and never runs the panicking reload
// path on invalid input.

import (
	"net/http"
	"sonushield/core/cfguard"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/shared"
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
	redisConfigured := false
	if domains.Config != nil {
		quietMode = domains.Config.Proxy.QuietMode
		autoSSL = domains.Config.Proxy.AutoSSL
		redisConfigured = domains.Config.Proxy.Redis.Enabled
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
		// Redis shared state (Batch 3): configured means
		// proxy.redis.enabled in config.json; active means a
		// shared store was successfully connected at startup
		// or reload. An outage after that fails open to
		// local state while active stays true: it reports
		// configuration, not a live probe. No address or
		// password is ever reported.
		"REDIS_CONFIGURED": redisConfigured,
		"REDIS_ACTIVE":     shared.Enabled(),
		// HTTP/3 (Batch 3): whether proxy.http3 is enabled.
		// It does not prove the UDP listener bound; a bind
		// failure only logs at startup.
		"HTTP3_ENABLED": domains.Config != nil && domains.Config.Proxy.HTTP3.Enabled,
	}
}

func domainFeaturesResponse(domainSettings *domains.DomainSettings) map[string]interface{} {
	return map[string]interface{}{
		"ADAPTIVE_POW":       domainSettings.AdaptivePow,
		"POW_DIFFICULTY_MIN": domainSettings.PoWDifficultyMin,
		"POW_DIFFICULTY_MAX": domainSettings.PoWDifficultyMax,
		// Memory-hard PoW parameters are config-file-only; the API
		// reports them read-only (SET_DOMAIN_FEATURES cannot change
		// them).
		"MEMORY_HARD_POW":           domainSettings.MemoryHardPow,
		"MEMORY_HARD_POW_BITS":      domainSettings.MemoryHardPowBits,
		"MEMORY_HARD_POW_MEMORY_KB": domainSettings.MemoryHardPowMemory,
		"MEMORY_HARD_POW_TIME":      domainSettings.MemoryHardPowTime,
		// Challenge rotation policy, config-file-only like the
		// memory-hard parameters above. The live current type
		// lives in the server package (wave cursor) and is not
		// exposed here; the policy itself is what operators
		// verify through this action.
		"CHALLENGE_ROTATION":      domainSettings.ChallengeRotation,
		"CHALLENGE_ROTATION_MODE": domainSettings.ChallengeRotationMode,
		"CHALLENGE_PROVIDER": domainSettings.ChallengeProvider,
		"CHALLENGE_KEYS_CONFIGURED": domainSettings.ChallengeProvider != "" &&
			domainSettings.ChallengeSiteKey != "" &&
			domainSettings.ChallengeSecretKey != "",
		"WAF_MODE":           domainSettings.WAFMode,
		"WAF_MODE_EFFECTIVE": firewall.ResolveWAFMode(domainSettings.WAFMode),
		"WAF_INSPECT_BODY":   domainSettings.WAFInspectBody,
		"WAF_WP_LOGIN_LIMIT": domainSettings.WAFWpLoginLimit,
		// Behavior signal and canary decoys (Batch 7),
		// read-only here. Canary paths and token values are
		// never returned: only whether any are configured.
		"BEHAVIOR_CHECK":   domainSettings.BehaviorCheck,
		"BEHAVIOR_ENFORCE": domainSettings.BehaviorEnforce,
		"INVISIBLE_MARKERS": domainSettings.InvisibleMarkers,
		// Signed URLs + hotlink protection (Batch 7). The
		// secret is never returned: only whether signing is
		// configured.
		"SIGNED_URL_CONFIGURED": len(domainSettings.SignedURLPaths) > 0 && domainSettings.SignedURLSecret != "",
		"HOTLINK_PROTECT":       domainSettings.HotlinkProtect,
		"CANARY_CONFIGURED": len(domainSettings.CanaryPaths) > 0 || len(domainSettings.CanaryTokens) > 0,
		// Mobile app attestation (Batch 8), read-only here. The
		// secret and JWKS URL are never returned: only whether
		// attestation is active.
		"ATTESTATION_CONFIGURED": domainSettings.Attest != nil,
		// Passkey challenge (Batch 8), read-only here. Only
		// whether the challenge can be served (enabled, RP ID,
		// credentials enrolled); no key material is returned.
		"PASSKEY_CONFIGURED": domainSettings.Passkey.Enabled && domainSettings.Passkey.RPID != "" && domainSettings.Passkeys != nil && domainSettings.Passkeys.Count() > 0,
		// Cloudflare auto Under Attack Mode (Batch 3),
		// read-only here: enabling it is config-file-only
		// (it needs the API token). The state is the last
		// level this process applied, "" when none.
		"CLOUDFLARE_AUTO_UAM": cfAutoUAMEnabled(domainSettings.Name),
		"CLOUDFLARE_UAM_STATE": cfguard.AppliedLevel(domainSettings.Name),
	}
}

// cfAutoUAMEnabled reports whether cloudflareAutoUAM is
// configured for a domain, scanning the live config. The
// token and zone ID are never exposed.
func cfAutoUAMEnabled(domainName string) bool {
	if domains.Config == nil {
		return false
	}
	for _, domain := range domains.Config.Domains {
		if domain.Name == domainName {
			return domain.CloudflareAutoUAM
		}
	}
	return false
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
