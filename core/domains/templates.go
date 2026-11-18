package domains

// Built-in domain templates (Batch 6): starting-point presets for
// common site kinds. A template fills in WAF, cache, compression,
// and honeypot settings on top of the standard fresh-domain
// thresholds (the same defaults config.Generate() uses); the
// operator's name, backend, scheme, and certificates are never
// touched by a template.
//
// Templates are starting points, not tuned protection: every
// preset is conservative and log-only where a false positive
// could break a site, and the operator is expected to adjust
// from there. In particular:
//
//   - WAF mode is always "log" (log-only), never "block": block
//     mode is opt-in per domain because no pattern set is
//     false-positive free, and a template must never break a
//     site on first deploy.
//   - No template ships firewall rules. A preset rule that fits
//     one site breaks another (a WordPress rule that nudges
//     xmlrpc.php, for example, would also nudge Jetpack's
//     legitimate traffic), and rules deserve the simulator and
//     dry-run workflow rather than a blind preset. The dashboard
//     rules view is where site-specific rules belong.
//   - Edge caching is enabled only for the static-site template:
//     API and e-commerce responses are personalized or
//     transactional, and caching them by default would serve one
//     visitor's data to another. The cache itself excludes
//     authenticated and private responses, but the template
//     default stays off for those kinds.
//   - Honeypot paths are paths no legitimate visitor ever
//     requests directly (configuration and secret files). A hit
//     raises suspicion by 2, the default bump.
//
// Template names are matched case-insensitively; "" means the
// plain template (standard defaults, no presets beyond WAF
// log-only).

import (
	"fmt"
	"strings"
)

// DomainTemplate describes one built-in template.
type DomainTemplate struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// domainTemplates is the ordered template list, plain first.
var domainTemplates = []DomainTemplate{
	{Name: "plain", Title: "Plain", Description: "Standard defaults: WAF log-only, no caching, no presets. A clean starting point for any site."},
	{Name: "wordpress", Title: "WordPress", Description: "WAF log-only with body inspection, a tighter login-flood limit, and honeypot paths for wp-config.php and .env."},
	{Name: "static", Title: "Static site", Description: "Edge caching with stampede guard, Brotli compression, and image optimization for mostly-static content."},
	{Name: "api", Title: "API backend", Description: "WAF log-only with body inspection and Brotli compression. No caching: API responses must not be shared between callers."},
	{Name: "ecommerce", Title: "E-commerce", Description: "WAF log-only with body inspection and Brotli compression, plus a honeypot path for .env. No caching: carts and checkouts are personal."},
}

// DomainTemplates returns the built-in templates in display order.
func DomainTemplates() []DomainTemplate {
	out := make([]DomainTemplate, len(domainTemplates))
	copy(out, domainTemplates)
	return out
}

// TemplatePreset returns the domain a template produces from a
// base carrying the operator's name, backend, scheme, and
// certificates. The base is not modified. An unknown template
// name is an error; "" selects the plain template.
func TemplatePreset(base Domain, name string) (Domain, error) {
	preset := base
	// Standard fresh-domain thresholds (config.Generate()).
	preset.FirewallRules = []JsonRule{}
	preset.BypassStage1 = 75
	preset.Stage2Difficulty = 5
	preset.BypassStage2 = 250
	preset.DisableBypassStage3 = 100
	preset.DisableRawStage3 = 250
	preset.DisableBypassStage2 = 50
	preset.DisableRawStage2 = 75
	preset.WAFMode = "log"

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "plain":
		// No further presets.
	case "wordpress":
		preset.WAFInspectBody = true
		// Login floods: 10 POSTs per minute per IP to
		// wp-login.php/xmlrpc.php (the WAF default is 20).
		// Generous for humans, tight for credential stuffing.
		preset.WAFWpLoginLimit = 10
		preset.HoneypotPaths = []string{"/wp-config.php", "/.env"}
		preset.HoneypotSusLv = 2
	case "static":
		preset.EdgeCache = true
		preset.EdgeCacheTTL = 300
		preset.EdgeCacheMaxMB = 256
		preset.StampedeGuard = true
		preset.Brotli = true
		preset.ImageOptimize = true
	case "api":
		preset.WAFInspectBody = true
		preset.Brotli = true
	case "ecommerce":
		preset.WAFInspectBody = true
		preset.Brotli = true
		preset.HoneypotPaths = []string{"/.env"}
		preset.HoneypotSusLv = 2
	default:
		return Domain{}, fmt.Errorf("unknown template %q (wordpress, static, api, ecommerce, or plain)", name)
	}
	return preset, nil
}
