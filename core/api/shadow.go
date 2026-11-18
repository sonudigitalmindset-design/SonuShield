package api

// Shadow report API (Batch 7).
//
// GET_SHADOW_REPORT returns the aggregated shadow-vs-live
// comparison for a domain: how many requests were evaluated,
// what the shadow rules would have done (block / challenge /
// allow), how often the shadow outcome disagreed with the live
// outcome, per-rule match tallies, and the most recent
// decisions. Read-only; viewers may call it. With shadow mode
// unconfigured the report is empty and SHADOW_ENABLED is
// false.

import (
	"time"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/privacy"
)

// shadowReportResponse builds the GET_SHADOW_REPORT response.
// No parameters are accepted.
func shadowReportResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}

	report := firewall.ShadowReport(domainSettings.Name)
	recent := make([]map[string]interface{}, 0, len(report.Recent))
	for _, decision := range report.Recent {
		ip := decision.IP
		// Privacy mode (Batch 7): anonymize recent-decision
		// IPs on the way out.
		if privacy.Enabled() {
			ip = privacy.MaskIP(ip)
		}
		recent = append(recent, map[string]interface{}{
			"TIME":           decision.Time.Format(time.RFC3339),
			"IP":             ip,
			"METHOD":         decision.Method,
			"PATH":           decision.Path,
			"LIVE_OUTCOME":   decision.LiveOutcome,
			"SHADOW_OUTCOME": decision.ShadowOutcome,
			"LIVE_SUS_LV":    decision.LiveSusLv,
			"SHADOW_SUS_LV":  decision.ShadowSusLv,
			"MATCHED":        decision.Matched,
			"WAF_RULE":       decision.WAFRule,
		})
	}
	return map[string]interface{}{
		"SHADOW_ENABLED":  len(domainSettings.ShadowRules) > 0 || domainSettings.ShadowWaf,
		"SHADOW_RULES":    len(domainSettings.ShadowRules),
		"SHADOW_WAF":      domainSettings.ShadowWaf,
		"EVALUATED":       report.Evaluated,
		"WOULD_BLOCK":     report.WouldBlock,
		"WOULD_CHALLENGE": report.WouldChallenge,
		"WOULD_ALLOW":     report.WouldAllow,
		"DISAGREEMENTS":   report.Disagreements,
		"RULE_MATCHES":    report.RuleMatches,
		"RECENT":          recent,
	}, ""
}
