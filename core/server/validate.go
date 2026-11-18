package server

// Detailed configuration validation (Batch 8).
//
// ValidateConfigDetailed is the `sonushield validate` check.
// It is a superset of ValidateConfig (reload.go), which stays
// the strict subset SafeReload uses: every condition that
// fails ValidateConfig also appears here as an error, plus
// deeper checks that are advisory in a reload context but
// worth reporting to an operator running validate by hand.
// The two must be kept in step: when ValidateConfig gains a
// check, add the same check here.
//
// Errors fail validation (exit 1). Warnings are reported but
// do not fail it: they describe conditions the proxy tolerates
// at runtime (a skipped DLP pattern, a missing GeoIP file,
// an invalid OpenAPI spec that disables validation) or
// operator judgment calls (short secrets, unknown keys).
// Secret VALUES are never printed: messages name fields only.
//
// probeBackends, when true, TCP-dials every domain backend
// (3 second timeout) and reports unreachable backends as
// errors. It is opt-in because backends are routinely down
// when a config is written; CI runs without it.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kor44/gofilter"

	"sonushield/core/domains"
)

const (
	minSecretLengthWarn = 12
	certExpiryWarnDays  = 30
	backendProbeTimeout = 3 * time.Second
)

// ValidateConfigDetailed fully checks a parsed configuration.
// rawJSON is the original file bytes, used only to detect
// unknown top-level keys; it may be nil, in which case that
// check is skipped.
func ValidateConfigDetailed(cfg *domains.Configuration, rawJSON []byte, probeBackends bool) (errors, warnings []string) {
	if cfg == nil {
		return []string{"no configuration"}, nil
	}
	addErr := func(format string, args ...interface{}) {
		errors = append(errors, fmt.Sprintf(format, args...))
	}
	addWarn := func(format string, args ...interface{}) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}

	// Unknown top-level keys: almost always a typo for
	// "proxy" or "domains", which would silently do nothing.
	// "controlPlane" is the platform-model section, used only
	// by `sonushield control`.
	if len(rawJSON) > 0 {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(rawJSON, &doc); err == nil {
			for key := range doc {
				if key != "proxy" && key != "domains" && key != "controlPlane" {
					addWarn("unknown top-level key %q (expected only \"proxy\", \"domains\", and \"controlPlane\")", key)
				}
			}
		}
	}

	// Control-plane-only files (a controlPlane section with
	// no proxy secrets and no domains) are validated as
	// control-plane configs, not proxy configs: requiring
	// proxy secrets there would make every dedicated control
	// host fail validation.
	if cfg.ControlPlane != nil && len(cfg.Domains) == 0 && cfg.Proxy.AdminSecret == "" && cfg.Proxy.APISecret == "" && len(cfg.Proxy.Secrets) == 0 {
		validateControlPlane(cfg.ControlPlane, addErr, addWarn)
		return errors, warnings
	}

	// A controlPlane section alongside a proxy config is
	// validated too, but proxy checks still run below.
	if cfg.ControlPlane != nil {
		validateControlPlane(cfg.ControlPlane, addErr, addWarn)
	}

	// Challenge secrets, admin secret, API secret: the same
	// presence rules as ValidateConfig, plus short-secret
	// warnings. Values are never printed.
	for _, key := range []string{"cookie", "javascript", "captcha"} {
		secret, ok := cfg.Proxy.Secrets[key]
		if !ok || secret == "" {
			addErr("proxy secret %q is missing", key)
			continue
		}
		if strings.Contains(secret, "CHANGE_ME") {
			addErr("proxy secret %q contains 'CHANGE_ME'", key)
		} else if len(secret) < minSecretLengthWarn {
			addWarn("proxy secret %q is short (%d characters); use a longer random value", key, len(secret))
		}
	}
	if cfg.Proxy.AdminSecret == "" {
		addErr("adminsecret is missing")
	} else if strings.Contains(cfg.Proxy.AdminSecret, "CHANGE_ME") {
		addErr("adminsecret contains 'CHANGE_ME'")
	} else if len(cfg.Proxy.AdminSecret) < minSecretLengthWarn {
		addWarn("adminsecret is short (%d characters); use a longer random value", len(cfg.Proxy.AdminSecret))
	}
	if cfg.Proxy.APISecret == "" {
		addErr("apisecret is missing")
	} else if strings.Contains(cfg.Proxy.APISecret, "CHANGE_ME") {
		addErr("apisecret contains 'CHANGE_ME'")
	} else if len(cfg.Proxy.APISecret) < minSecretLengthWarn {
		addWarn("apisecret is short (%d characters); use a longer random value", len(cfg.Proxy.APISecret))
	}

	// Proxy-level file/URL references that fail open at
	// runtime are warnings here: the operator should know
	// the feature will be inert.
	if cfg.Proxy.GeoIPCountryDB != "" {
		if _, err := os.Stat(cfg.Proxy.GeoIPCountryDB); err != nil {
			addWarn("geoipCountryDatabase file not found: %s (GeoIP country lookups will be inert)", cfg.Proxy.GeoIPCountryDB)
		}
	}
	if cfg.Proxy.GeoIPASNDB != "" {
		if _, err := os.Stat(cfg.Proxy.GeoIPASNDB); err != nil {
			addWarn("geoipASNDatabase file not found: %s (GeoIP ASN lookups will be inert)", cfg.Proxy.GeoIPASNDB)
		}
	}
	if cfg.Proxy.ReputationFeed != "" {
		if parsed, err := url.Parse(cfg.Proxy.ReputationFeed); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			addWarn("reputationFeedURL is not a valid http(s) URL: %s", cfg.Proxy.ReputationFeed)
		}
	}
	if cfg.Proxy.SSO != nil && cfg.Proxy.SSO.Enabled {
		if reason := cfg.Proxy.SSO.Validate(); reason != "" {
			addWarn("SSO configuration problem (SSO will be disabled): %s", reason)
		}
	}
	sharing := cfg.Proxy.ThreatSharing
	if sharing.Enabled {
		usable := 0
		for _, peer := range sharing.Peers {
			if peer.Name != "" && peer.URL != "" && peer.SharedSecret != "" {
				usable++
			}
		}
		if usable == 0 {
			addWarn("threatSharing is enabled but no peer has a name, URL, and shared secret; sharing will be inert")
		}
	}
	bgpMonitor := cfg.Proxy.BGPMonitor
	if bgpMonitor.Enabled && (len(bgpMonitor.Prefixes) == 0 || len(bgpMonitor.ExpectedOrigins) == 0) {
		addWarn("bgpMonitor is enabled but has no prefixes or no expected origins; monitoring will be inert")
	}
	oncall := cfg.Proxy.OnCall
	if oncall.Enabled {
		known := map[string]bool{}
		for _, responder := range oncall.Responders {
			known[responder.Name] = true
		}
		for i, entry := range oncall.Schedule {
			if !known[entry.Responder] {
				addWarn("oncall schedule entry %d names unknown responder %q", i, entry.Responder)
			}
		}
		if len(oncall.Responders) == 0 || len(oncall.Schedule) == 0 {
			addWarn("oncall is enabled but has no responders or no schedule entries; delivery will fall back to domain channels")
		}
	}
	if cfg.Proxy.Synthetic.Enabled && len(cfg.Proxy.Synthetic.Checks) == 0 {
		addWarn("synthetic checks are enabled but no checks are configured")
	}

	if len(cfg.Domains) == 0 {
		addErr("no domains configured")
		return errors, warnings
	}
	seenNames := map[string]bool{}
	for i := range cfg.Domains {
		domain := &cfg.Domains[i]
		label := fmt.Sprintf("domain %d", i)
		if domain.Name != "" {
			label = "domain " + domain.Name
		}
		if domain.Name == "" {
			addErr("domain %d has no name", i)
			continue
		}
		if !domains.ValidHostname(domain.Name) {
			addErr("%s: name is not a valid hostname or IP address", label)
		}
		lower := strings.ToLower(domain.Name)
		if seenNames[lower] {
			addErr("%s: duplicate domain name", label)
		}
		seenNames[lower] = true
		if _, _, ok := domains.SplitBackend(domain.Backend); !ok {
			addErr("%s: backend %q must be host:port", label, domain.Backend)
		}
		scheme := strings.ToLower(strings.TrimSpace(domain.Scheme))
		if scheme != "" && scheme != "http" && scheme != "https" {
			addErr("%s: scheme %q must be http or https", label, domain.Scheme)
		}
		for j := range domain.FirewallRules {
			rule := &domain.FirewallRules[j]
			if _, err := gofilter.NewFilter(rule.Expression); err != nil {
				addErr("%s rule %d does not compile: %s", label, j, err.Error())
			}
			if !domains.ValidRuleAction(rule.Action) {
				addErr("%s rule %d has invalid action %q (must be an integer, +N, or -N)", label, j, rule.Action)
			}
			if rule.Schedule != "" {
				if _, err := domains.ParseSchedule(rule.Schedule); err != nil {
					addErr("%s rule %d has invalid schedule %q: %s", label, j, rule.Schedule, err.Error())
				}
			}
		}
		if domain.ScheduleTimezone != "" {
			if _, err := domains.ParseScheduleTimezone(domain.ScheduleTimezone); err != nil {
				addWarn("%s: scheduleTimezone %q is not a valid IANA name; UTC will be used", label, domain.ScheduleTimezone)
			}
		}
		// DLP patterns: invalid regexes are skipped at
		// runtime with a warning, so warn here too.
		for _, pattern := range domain.DLP.Patterns {
			if pattern.Name == "" || pattern.Regex == "" {
				addWarn("%s: DLP pattern with an empty name or regex will be ignored", label)
				continue
			}
			if _, err := regexp.Compile(pattern.Regex); err != nil {
				addWarn("%s: DLP pattern %q has an invalid regex and will be ignored: %s", label, pattern.Name, err.Error())
			}
		}
		// OpenAPI: an unreadable or invalid spec disables
		// validation at runtime with a warning.
		if domain.OpenAPI.SpecFile != "" {
			if err := domains.CheckOpenAPISpec(domain.OpenAPI); err != nil {
				addWarn("%s: OpenAPI spec problem (validation will be disabled): %s", label, err.Error())
			}
		}
		// Attestation: enabled with paths but no verification
		// material fails closed at runtime with a warning.
		if att := domain.Attestation; att.Enabled && len(att.Paths) > 0 && att.JWKSURL == "" && att.Secret == "" {
			addWarn("%s: attestation is enabled with paths but no JWKS URL or secret; matching requests will be rejected", label)
		}
		// Certificates: same conditions as ValidateConfig.
		// Expired certificates are errors; expiry within 30
		// days is a warning.
		if !cfg.Proxy.Cloudflare && !(cfg.Proxy.AutoSSL && domain.Certificate == "" && domain.Key == "") {
			if (domain.Certificate == "") != (domain.Key == "") {
				addErr("%s has only one of certificate/key set", label)
			} else if domain.Certificate != "" {
				pair, err := tls.LoadX509KeyPair(domain.Certificate, domain.Key)
				if err != nil {
					addErr("%s certificates cannot be loaded: %s", label, err.Error())
				} else if len(pair.Certificate) > 0 {
					if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
						now := time.Now()
						if now.After(leaf.NotAfter) {
							addErr("%s certificate expired on %s", label, leaf.NotAfter.Format("2006-01-02"))
						} else if leaf.NotAfter.Sub(now) < certExpiryWarnDays*24*time.Hour {
							addWarn("%s certificate expires on %s (within %d days)", label, leaf.NotAfter.Format("2006-01-02"), certExpiryWarnDays)
						}
					}
				}
			}
		}
		// Optional backend reachability probe.
		if probeBackends {
			host, port, ok := domains.SplitBackend(domain.Backend)
			if ok {
				address := net.JoinHostPort(host, port)
				conn, err := net.DialTimeout("tcp", address, backendProbeTimeout)
				if err != nil {
					addErr("%s: backend %s unreachable: %s", label, domain.Backend, err.Error())
				} else {
					conn.Close()
				}
			}
		}
	}
	return errors, warnings
}

// validateControlPlane checks a controlPlane section: shape
// via ControlPlaneConfig.Validate, plus certificate loadability
// and judgment-call warnings. Secret values are never printed.
func validateControlPlane(cp *domains.ControlPlaneConfig, addErr, addWarn func(string, ...interface{})) {
	if reason := cp.Validate(); reason != "" {
		addErr("controlPlane: %s", reason)
		return
	}
	if cp.SessionSecret == "" {
		addWarn("controlPlane sessionSecret is empty: sessions will not survive a restart")
	} else if len(cp.SessionSecret) < minSecretLengthWarn {
		addWarn("controlPlane sessionSecret is short (%d characters); use a longer random value", len(cp.SessionSecret))
	}
	if cp.Certificate == "" {
		host, _, _ := net.SplitHostPort(cp.ListenAddr())
		if host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
			addWarn("controlPlane has no TLS certificate and listens on a non-loopback address; logins would cross the network in cleartext")
		}
	} else {
		pair, err := tls.LoadX509KeyPair(cp.Certificate, cp.Key)
		if err != nil {
			addErr("controlPlane certificates cannot be loaded: %s", err.Error())
		} else if len(pair.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
				now := time.Now()
				if now.After(leaf.NotAfter) {
					addErr("controlPlane certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
				} else if leaf.NotAfter.Sub(now) < certExpiryWarnDays*24*time.Hour {
					addWarn("controlPlane certificate expires on %s (within %d days)", leaf.NotAfter.Format("2006-01-02"), certExpiryWarnDays)
				}
			}
		}
	}
	for _, node := range cp.Nodes {
		if len(node.APISecret) < minSecretLengthWarn {
			addWarn("controlPlane node %q apiSecret is short (%d characters)", node.Name, len(node.APISecret))
		}
		if node.InsecureSkipVerify {
			addWarn("controlPlane node %q has insecureSkipVerify set: node certificate verification is disabled", node.Name)
		}
		if node.CAFile != "" {
			if _, err := os.Stat(node.CAFile); err != nil {
				addErr("controlPlane node %q caFile cannot be read: %s", node.Name, err.Error())
			}
		}
	}
}
