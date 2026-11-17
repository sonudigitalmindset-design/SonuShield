package server

// Validated configuration reload for the API.
//
// The original ReloadConfig (monitor.go) panics on an unreadable
// file, an uncompilable firewall rule, or an unloadable certificate,
// and the panic handler re-panics after logging, so reaching it with
// a bad config kills the proxy. That path must never be reachable
// from an API call. SafeReload closes the gap:
//
//   1. Read and parse config.json into a fresh struct. The running
//      config is untouched while parsing.
//   2. Validate the parsed config against every hard requirement
//      Load() enforces plus every input that would panic the
//      reload: secrets present and without CHANGE_ME placeholders,
//      at least one named domain, every rule expression compiling
//      with a usable action, and every certificate pair loading
//      (under the same Cloudflare/autoSSL conditions Load uses).
//   3. Only then apply the SAME parsed struct via reloadFromConfig,
//      so there is no re-read gap between validation and apply.
//   4. A deferred recover converts any residual panic into an
//      error return. After validation passes, a panic should be
//      unreachable; the recover exists so a surprise (a file
//      deleted mid-reload, for example) degrades to an error
//      instead of killing the process. If it ever fires, the
//      running config may be partially applied; the operator
//      should fix the file and reload again.
//
// Reload semantics are unchanged from the terminal reload: applying
// a config resets per-domain counters and stage state, and does NOT
// apply adminsecret/apisecret changes (those need a restart, as
// before). SafeReload is registered as the API's RELOAD handler via
// the api.ConfigReloader hook; a direct call is impossible because
// this package imports the api package (import cycle the other way).

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sonushield/core/api"
	"sonushield/core/domains"
	"strings"

	"github.com/kor44/gofilter"
)

func init() {
	api.ConfigReloader = SafeReload
}

// ValidateConfig checks a parsed configuration against every input
// that would make applying it panic or violate Load's hard
// requirements. It never mutates anything. The error message names
// the problem; it never contains a secret value.
func ValidateConfig(cfg *domains.Configuration) error {
	if cfg == nil {
		return errors.New("no configuration")
	}

	for _, key := range []string{"cookie", "javascript", "captcha"} {
		secret, ok := cfg.Proxy.Secrets[key]
		if !ok || secret == "" {
			return fmt.Errorf("proxy secret %q is missing", key)
		}
		if strings.Contains(secret, "CHANGE_ME") {
			return fmt.Errorf("proxy secret %q contains 'CHANGE_ME'", key)
		}
	}
	if cfg.Proxy.AdminSecret == "" {
		return errors.New("adminsecret is missing")
	}
	if strings.Contains(cfg.Proxy.AdminSecret, "CHANGE_ME") {
		return errors.New("adminsecret contains 'CHANGE_ME'")
	}
	if cfg.Proxy.APISecret == "" {
		return errors.New("apisecret is missing")
	}
	if strings.Contains(cfg.Proxy.APISecret, "CHANGE_ME") {
		return errors.New("apisecret contains 'CHANGE_ME'")
	}

	if len(cfg.Domains) == 0 {
		return errors.New("no domains configured")
	}
	for i := range cfg.Domains {
		domain := &cfg.Domains[i]
		if domain.Name == "" {
			return fmt.Errorf("domain %d has no name", i)
		}
		for j := range domain.FirewallRules {
			rule := &domain.FirewallRules[j]
			if _, err := gofilter.NewFilter(rule.Expression); err != nil {
				return fmt.Errorf("domain %s rule %d does not compile: %s", domain.Name, j, err.Error())
			}
			if !domains.ValidRuleAction(rule.Action) {
				return fmt.Errorf("domain %s rule %d has invalid action %q (must be an integer, +N, or -N)", domain.Name, j, rule.Action)
			}
		}
		// Same certificate conditions as Load(): skipped in
		// Cloudflare mode, and skipped for cert-less domains
		// when autoSSL will provide certificates. A domain
		// with only one of the two paths set always fails.
		if !cfg.Proxy.Cloudflare && !(cfg.Proxy.AutoSSL && domain.Certificate == "" && domain.Key == "") {
			if (domain.Certificate == "") != (domain.Key == "") {
				return fmt.Errorf("domain %s has only one of certificate/key set", domain.Name)
			}
			if domain.Certificate != "" {
				if _, err := tls.LoadX509KeyPair(domain.Certificate, domain.Key); err != nil {
					return fmt.Errorf("domain %s certificates cannot be loaded: %s", domain.Name, err.Error())
				}
			}
		}
	}
	return nil
}

// SafeReload validates config.json and, only if it is valid, applies
// it to the running proxy. On any failure it returns an error and
// the running config is untouched. It never panics.
func SafeReload() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("reload failed unexpectedly: %v (running config may be partially applied; fix config.json and reload again)", r)
		}
	}()

	data, err := os.ReadFile("config.json")
	if err != nil {
		return err
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("config.json is not valid JSON: %w", err)
	}
	if err := ValidateConfig(&cfg); err != nil {
		return err
	}
	reloadFromConfig(&cfg)
	return nil
}
