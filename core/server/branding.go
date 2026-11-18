package server

// Branding resolution and rendering for built-in pages (Batch 6).
//
// resolveBranding merges the per-domain branding over the
// proxy-wide branding and sanitizes the result, so builders
// always receive safe values. The dashboard resolves proxy-wide
// branding only: it serves all domains from one page, so no
// per-domain brand applies to it.

import (
	"html"
	"sonushield/core/domains"
	"strings"
)

// proxyBranding returns the proxy-wide branding from the live
// config, or an empty branding when no config is loaded.
func proxyBranding() domains.Branding {
	if domains.Config == nil {
		return domains.Branding{}
	}
	return domains.Config.Proxy.Branding
}

// resolveBranding returns the effective, sanitized branding for
// a domain: per-domain fields win, proxy-wide fields fill the
// gaps, invalid values drop to empty.
func resolveBranding(settings domains.DomainSettings) domains.Branding {
	return settings.Branding.Resolve(proxyBranding()).Sanitized()
}

// brandBanner renders the optional brand banner for a built-in
// challenge page: the operator's logo and/or display name,
// centered above the page content. It returns "" when neither
// is set, so unbranded pages are byte-identical to before.
// Values are HTML-escaped on output; the logo URL was already
// restricted to http(s) URLs and same-origin paths by
// Sanitized, so no javascript: or data: URL can reach the src.
func brandBanner(b domains.Branding) string {
	if b.DisplayName == "" && b.LogoURL == "" {
		return ""
	}
	out := `<div style="text-align:center;margin-bottom:16px">`
	if b.LogoURL != "" {
		out += `<img src="` + html.EscapeString(b.LogoURL) + `" alt="" style="max-height:48px;max-width:220px">`
	}
	if b.DisplayName != "" {
		out += `<div style="font-weight:700;font-size:18px;color:#333;margin-top:8px">` + html.EscapeString(b.DisplayName) + `</div>`
	}
	return out + `</div>`
}

// brandAccentOverride renders a <style> block with the given
// CSS rules, with every {accent} placeholder replaced by the
// operator's accent color, or "" when no accent is set. The
// color was validated as #rgb/#rrggbb by Sanitized, so
// interpolating it into CSS cannot break out of a declaration.
func brandAccentOverride(b domains.Branding, css string) string {
	if b.AccentColor == "" {
		return ""
	}
	return "<style>" + strings.ReplaceAll(css, "{accent}", b.AccentColor) + "</style>"
}
