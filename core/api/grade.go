package api

// Security grade scan (Batch 7).
//
// GET_SECURITY_GRADE is a self-assessment of the CURRENT
// configuration: secret strength and hygiene, certificate
// validity, header/CORS/WAF coverage, stage thresholds,
// webhook transport security, and a few informational facts
// (post-quantum TLS, privacy mode, SSO, metrics). It is a
// CONFIGURATION AUDIT, not a penetration test: it never
// probes the network, never phones home, never attempts an
// exploit, and never prints a secret value — checks report
// lengths, presence, and boolean facts only.
//
// Grading: each scored check contributes pass=1, warn=0.5,
// fail=0; informational checks do not affect the score.
// Bands: A >= 95, B >= 85, C >= 70, D >= 50, F < 50. Any
// failing high-severity check caps the grade at C; any
// failing check at all caps it at B. The bands and caps are
// documented here so the grade is reproducible, not a black
// box. A good grade does not mean the deployment is secure:
// it means the configuration options the proxy can see look
// sane.

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"sonushield/core/certmon"
	"sonushield/core/domains"
)

// gradeCheck is one audit finding.
type gradeCheck struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"` // "high", "medium", "low", "info"
	Status   string `json:"status"`   // "pass", "warn", "fail", "info"
	Detail   string `json:"detail"`
	Guidance string `json:"guidance"`
}

const (
	gradeMinSecretLen     = 16
	gradeMinFlowSecretLen = 16
	gradeCertWarnDays     = 30
)

// securityGradeResponse builds the GET_SECURITY_GRADE
// response. No parameters are accepted.
func securityGradeResponse(params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	cfg := domains.Config
	if cfg == nil {
		return nil, ERR_CONFIG_WRITE_FAILED
	}
	checks := runGradeChecks(cfg)
	score, grade := gradeScore(checks)
	return map[string]interface{}{
		"GRADE":      grade,
		"SCORE":      score,
		"CHECKS":     checks,
		"DISCLAIMER": "Configuration audit only — not a penetration test. No network probing was performed, and no secret value is included in this report.",
	}, ""
}

// runGradeChecks evaluates every check against the live
// configuration. Check order is fixed so reports are stable.
func runGradeChecks(cfg *domains.Configuration) []gradeCheck {
	proxy := cfg.Proxy
	checks := []gradeCheck{}

	// Secret strength: length and placeholder checks only.
	checks = append(checks, gradeCheck{
		ID: "admin-secret-strength", Title: "Admin secret strength", Severity: "high",
		Status:   secretStatus(proxy.AdminSecret, gradeMinSecretLen),
		Detail:   secretDetail("adminsecret", proxy.AdminSecret, gradeMinSecretLen),
		Guidance: "Set a random adminsecret of at least 16 characters in proxy.adminsecret.",
	})
	checks = append(checks, gradeCheck{
		ID: "api-secret-strength", Title: "API secret strength", Severity: "high",
		Status:   secretStatus(proxy.APISecret, gradeMinSecretLen),
		Detail:   secretDetail("apisecret", proxy.APISecret, gradeMinSecretLen),
		Guidance: "Set a random apisecret of at least 16 characters in proxy.apisecret.",
	})

	flowDetail := []string{}
	flowStatus := "pass"
	for _, key := range []string{"cookie", "javascript", "captcha"} {
		secret := proxy.Secrets[key]
		status := secretStatus(secret, gradeMinFlowSecretLen)
		if status == "fail" {
			flowStatus = "fail"
		} else if status == "warn" && flowStatus == "pass" {
			flowStatus = "warn"
		}
		flowDetail = append(flowDetail, secretDetail(key, secret, gradeMinFlowSecretLen))
	}
	checks = append(checks, gradeCheck{
		ID: "flow-secrets", Title: "Cookie/JS/captcha secrets", Severity: "high",
		Status:   flowStatus,
		Detail:   strings.Join(flowDetail, "; "),
		Guidance: "Set random cookie, javascript, and captcha secrets of at least 16 characters in proxy.secrets.",
	})

	// Distinctness: no two secrets share a value.
	seen := map[string]string{}
	distinct := true
	clash := ""
	consider := func(name, value string) {
		if value == "" || !distinct {
			return
		}
		if prev, ok := seen[value]; ok {
			distinct = false
			clash = prev + " and " + name
			return
		}
		seen[value] = name
	}
	consider("adminsecret", proxy.AdminSecret)
	consider("apisecret", proxy.APISecret)
	for _, key := range []string{"cookie", "javascript", "captcha"} {
		consider(key, proxy.Secrets[key])
	}
	for secret := range proxy.APIRoles {
		consider("apiRoles entry", secret)
	}
	distinctStatus := "pass"
	distinctDetail := "all configured secrets are distinct"
	if !distinct {
		distinctStatus = "fail"
		distinctDetail = "the same secret value is used for " + clash
	}
	checks = append(checks, gradeCheck{
		ID: "secrets-distinct", Title: "Secrets are distinct", Severity: "medium",
		Status:   distinctStatus,
		Detail:   distinctDetail,
		Guidance: "Give every secret its own random value; reusing one value across purposes defeats separation.",
	})

	// Role secrets: length only, never values.
	roleStatus := "pass"
	roleDetail := "no role secrets configured"
	if len(proxy.APIRoles) > 0 {
		short := 0
		for secret := range proxy.APIRoles {
			if len(secret) < gradeMinSecretLen {
				short++
			}
		}
		roleDetail = fmt.Sprintf("%d role secret(s) configured, %d shorter than %d characters", len(proxy.APIRoles), short, gradeMinSecretLen)
		if short > 0 {
			roleStatus = "warn"
		}
	}
	checks = append(checks, gradeCheck{
		ID: "role-secrets", Title: "Role secret strength", Severity: "medium",
		Status:   roleStatus,
		Detail:   roleDetail,
		Guidance: "Use random role secrets of at least 16 characters in proxy.apiRoles.",
	})

	// Certificates: expiry per configured cert file.
	checks = append(checks, certificateCheck(cfg))

	// Per-domain coverage checks.
	hstsMissing, wafOff, thresholdsBad, corsWildcard, providerKeysBad, debugDomain := []string{}, []string{}, []string{}, []string{}, []string{}, false
	for _, domain := range cfg.Domains {
		if domain.Name == "debug" {
			debugDomain = true
		}
		if !hasHSTS(domain.SecurityHeaders) {
			hstsMissing = append(hstsMissing, domain.Name)
		}
		if strings.EqualFold(strings.TrimSpace(domain.WAFMode), "off") {
			wafOff = append(wafOff, domain.Name)
		}
		if domain.BypassStage1 <= 0 || domain.BypassStage2 < domain.BypassStage1 {
			thresholdsBad = append(thresholdsBad, domain.Name)
		}
		if domain.CORS != nil {
			for _, origin := range domain.CORS.AllowedOrigins {
				if origin == "*" {
					corsWildcard = append(corsWildcard, domain.Name)
					break
				}
			}
		}
		if domain.ChallengeProvider != "" && (domain.ChallengeSiteKey == "" || domain.ChallengeSecretKey == "") {
			providerKeysBad = append(providerKeysBad, domain.Name)
		}
	}
	checks = append(checks, listCheck("hsts-configured", "HSTS header configured", "medium", hstsMissing,
		"all domains send Strict-Transport-Security",
		"add \"Strict-Transport-Security\" to securityHeaders for the listed domains"))
	checks = append(checks, listCheck("waf-enabled", "WAF-lite enabled", "medium", wafOff,
		"WAF-lite is active (log or block) on all domains",
		"remove wafMode \"off\" for the listed domains, or accept log-only coverage"))
	checks = append(checks, listCheck("stage-thresholds-sane", "Stage thresholds sane", "low", thresholdsBad,
		"all domains have positive, ordered stage thresholds",
		"set bypassStage1 > 0 and bypassStage2 >= bypassStage1 for the listed domains"))
	checks = append(checks, listCheck("cors-not-wildcard", "CORS without wildcard origin", "medium", corsWildcard,
		"no domain allows CORS origin \"*\"",
		"replace the \"*\" CORS origin with the explicit origins the listed domains serve"))
	checks = append(checks, listCheck("challenge-provider-keys", "Challenge provider keys present", "medium", providerKeysBad,
		"every configured challenge provider has site and secret keys (or no provider is configured, falling back to proof-of-work)",
		"add the missing site/secret keys for the listed domains, or clear the provider to use proof-of-work"))
	debugStatus := "pass"
	debugDetail := "no domain is named \"debug\""
	if debugDomain {
		debugStatus = "fail"
		debugDetail = "a domain is named \"debug\", colliding with the internal pseudo-domain"
	}
	checks = append(checks, gradeCheck{
		ID: "no-debug-domain", Title: "No \"debug\" domain collision", Severity: "low",
		Status:   debugStatus,
		Detail:   debugDetail,
		Guidance: "Rename the \"debug\" domain; the name is reserved for internal use.",
	})

	// Webhook transports: https (or empty/localhost) only.
	httpWebhooks := []string{}
	for _, hook := range proxy.EventWebhooks {
		if isInsecureRemoteURL(hook.URL) {
			httpWebhooks = append(httpWebhooks, "event webhook "+hook.URL)
		}
	}
	for _, domain := range cfg.Domains {
		if isInsecureRemoteURL(domain.Webhook.URL) {
			httpWebhooks = append(httpWebhooks, "discord webhook for "+domain.Name)
		}
	}
	checks = append(checks, listCheck("webhooks-https", "Alert webhooks over HTTPS", "medium", httpWebhooks,
		"all configured alert/event webhooks use HTTPS (or are unset/local)",
		"move the listed webhooks to HTTPS URLs"))
	feedStatus := "pass"
	feedDetail := "no reputation feed URL configured"
	if proxy.ReputationFeed != "" {
		feedDetail = "reputation feed URL uses HTTPS"
		if isInsecureRemoteURL(proxy.ReputationFeed) {
			feedStatus = "warn"
			feedDetail = "reputation feed URL uses plain HTTP"
		}
	}
	checks = append(checks, gradeCheck{
		ID: "reputation-feed-https", Title: "Reputation feed over HTTPS", Severity: "low",
		Status:   feedStatus,
		Detail:   feedDetail,
		Guidance: "Serve the reputation feed over HTTPS so feed contents cannot be tampered with in transit.",
	})

	// Informational facts: no grade impact.
	pqStatus, pqDetail := "info", "post-quantum key exchange (X25519MLKEM768) is enabled (Go default)"
	if proxy.TLSDisablePostQuantum {
		pqDetail = "post-quantum key exchange is disabled by tlsDisablePostQuantum (operator choice)"
	}
	checks = append(checks, gradeCheck{
		ID: "post-quantum-tls", Title: "Post-quantum TLS", Severity: "info",
		Status: pqStatus, Detail: pqDetail,
		Guidance: "No action needed; disabling is a valid choice for middlebox compatibility.",
	})
	// (A privacy-mode informational check is added with
	// privacy mode itself in item 16.)
	privacyDetail := "privacy mode is off"
	if proxy.PrivacyMode {
		privacyDetail = "privacy mode is on: IPs are anonymized and user-agents are not stored"
	}
	checks = append(checks, gradeCheck{
		ID: "privacy-mode", Title: "Privacy mode", Severity: "info",
		Status: "info", Detail: privacyDetail,
		Guidance: "Enable proxy.privacyMode to minimize stored PII.",
	})
	ssoDetail := "SSO/OIDC is not configured"
	if proxy.SSO != nil {
		ssoDetail = "SSO/OIDC is configured"
	}
	checks = append(checks, gradeCheck{
		ID: "sso-configured", Title: "SSO/OIDC", Severity: "info",
		Status: "info", Detail: ssoDetail,
		Guidance: "No action needed.",
	})
	metricsDetail := "Prometheus metrics are disabled"
	if proxy.MetricsEnabled {
		metricsDetail = "Prometheus metrics are enabled on the secret-gated path"
	}
	checks = append(checks, gradeCheck{
		ID: "metrics-exposure", Title: "Metrics exposure", Severity: "info",
		Status: "info", Detail: metricsDetail,
		Guidance: "Metrics are always served behind the admin secret path; no action needed.",
	})

	return checks
}

// secretStatus grades one secret by length and placeholder
// content. Empty or placeholder values fail; short values
// warn; the value itself is never returned.
func secretStatus(secret string, minLen int) string {
	if secret == "" || strings.Contains(secret, "CHANGE_ME") {
		return "fail"
	}
	if len(secret) < minLen {
		return "warn"
	}
	return "pass"
}

// secretDetail describes a secret without revealing it.
func secretDetail(name, secret string, minLen int) string {
	switch {
	case secret == "":
		return name + " is missing"
	case strings.Contains(secret, "CHANGE_ME"):
		return name + " still contains a CHANGE_ME placeholder"
	case len(secret) < minLen:
		return fmt.Sprintf("%s is set but shorter than %d characters", name, minLen)
	default:
		return fmt.Sprintf("%s is set (%d characters)", name, len(secret))
	}
}

// hasHSTS reports whether the security headers include
// Strict-Transport-Security (header names case-insensitive).
func hasHSTS(headers map[string]string) bool {
	for name := range headers {
		if strings.EqualFold(name, "Strict-Transport-Security") {
			return true
		}
	}
	return false
}

// listCheck builds a warn-when-nonempty check over domain
// names. An empty list passes.
func listCheck(id, title, severity string, offenders []string, passDetail, guidance string) gradeCheck {
	if len(offenders) == 0 {
		return gradeCheck{ID: id, Title: title, Severity: severity, Status: "pass", Detail: passDetail, Guidance: guidance}
	}
	sort.Strings(offenders)
	return gradeCheck{
		ID: id, Title: title, Severity: severity, Status: "warn",
		Detail:   "affected: " + strings.Join(offenders, ", "),
		Guidance: guidance,
	}
}

// isInsecureRemoteURL reports whether raw is a non-local
// plain-HTTP URL. Empty, unparsable, HTTPS, and localhost
// URLs are not insecure for this check.
func isInsecureRemoteURL(raw string) bool {
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host != "" && host != "localhost" && host != "127.0.0.1" && host != "[::1]" && host != "::1"
}

// certificateCheck inspects every configured certificate file
// for expiry. AutoSSL-managed and Cloudflare-mode domains are
// skipped: the former renew automatically, the latter
// terminate elsewhere.
func certificateCheck(cfg *domains.Configuration) gradeCheck {
	proxy := cfg.Proxy
	details := []string{}
	status := "pass"
	checked := 0
	for _, domain := range cfg.Domains {
		if proxy.Cloudflare || domain.Certificate == "" {
			continue
		}
		checked++
		days, err := certDaysRemaining(domain.Certificate)
		switch {
		case err != nil:
			status = "fail"
			details = append(details, domain.Name+": unreadable ("+err.Error()+")")
		case days < 0:
			status = "fail"
			details = append(details, fmt.Sprintf("%s: EXPIRED %d day(s) ago", domain.Name, -days))
		case days < gradeCertWarnDays:
			if status == "pass" {
				status = "warn"
			}
			details = append(details, fmt.Sprintf("%s: expires in %d day(s)", domain.Name, days))
		default:
			details = append(details, fmt.Sprintf("%s: valid for %d day(s)", domain.Name, days))
		}
	}
	detail := "no certificate files to check (Cloudflare mode or autoSSL)"
	if checked > 0 {
		sort.Strings(details)
		detail = strings.Join(details, "; ")
	}
	return gradeCheck{
		ID: "certificates-valid", Title: "Certificate validity", Severity: "high",
		Status:   status,
		Detail:   detail,
		Guidance: "Renew certificates expiring within 30 days; replace expired or unreadable certificate files.",
	}
}

// certDaysRemaining returns whole days until the leaf
// certificate in the PEM file expires, or an error when the
// file cannot be read or parsed. Negative values mean the
// certificate already expired.
func certDaysRemaining(path string) (int, error) {
	cert, err := certmon.ReadLeafCert(path)
	if err != nil {
		return 0, err
	}
	return certmon.DaysRemaining(cert, time.Now()), nil
}

// gradeScore converts check outcomes to a 0-100 score and a
// letter grade, applying the documented caps.
func gradeScore(checks []gradeCheck) (int, string) {
	scored := 0
	points := 0.0
	anyFail := false
	highFail := false
	for _, check := range checks {
		if check.Severity == "info" || check.Status == "info" {
			continue
		}
		scored++
		switch check.Status {
		case "pass":
			points++
		case "warn":
			points += 0.5
		case "fail":
			anyFail = true
			if check.Severity == "high" {
				highFail = true
			}
		}
	}
	score := 100
	if scored > 0 {
		score = int(points * 100 / float64(scored))
	}
	grade := "A"
	switch {
	case score >= 95:
		grade = "A"
	case score >= 85:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 50:
		grade = "D"
	default:
		grade = "F"
	}
	if highFail && gradeLessThan(grade, "C") {
		grade = "C"
	}
	if anyFail && gradeLessThan(grade, "B") {
		grade = "B"
	}
	return score, grade
}

// gradeLessThan reports whether grade a is better than b in
// the A-F ordering (A is best). Used for the caps: a grade
// better than the cap is pulled down to the cap.
func gradeLessThan(a, b string) bool {
	order := map[string]int{"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
	return order[a] < order[b]
}
