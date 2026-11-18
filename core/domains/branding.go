package domains

// Operator branding (Batch 6, white-label).
//
// Branding carries the display name, logo URL, and accent color an
// operator (or reseller) configures for the dashboard and the
// built-in challenge pages. It is config-file-only: proxy-wide
// under proxy.branding, overridable per domain under branding.
// A per-domain field overrides the proxy-wide field only when
// set; empty fields fall back (Resolve).
//
// HARD LIMIT: branding never removes or hides GPL attribution.
// The LICENSE file, the /_bProxy/credits endpoint, the README and
// docs credits, and the dashboard's About footer are not
// brandable and are never altered by these values. Branding
// changes only the dashboard wordmark/title/accent and the
// optional banner on built-in challenge pages. Custom page
// templates are fully operator-controlled and receive no
// branding injection.
//
// Sanitized enforces the safety rules at use time, so an invalid
// value can never break a page or inject markup: the display
// name is trimmed, capped, and stripped of control characters
// (callers HTML-escape it on output as well); the logo URL must
// be an http(s) URL or a same-origin absolute path; the accent
// must be a #rgb/#rrggbb hex color. Invalid values fall back to
// empty (the built-in default), never to an error: a bad branding
// value must not fail config validation or break serving.

import (
	"strings"
	"unicode"
)

// Branding is the operator-configured display identity. The
// struct lives with the other config shapes in domain.go.
func (b Branding) Resolve(fallback Branding) Branding {
	if b.DisplayName == "" {
		b.DisplayName = fallback.DisplayName
	}
	if b.LogoURL == "" {
		b.LogoURL = fallback.LogoURL
	}
	if b.AccentColor == "" {
		b.AccentColor = fallback.AccentColor
	}
	return b
}

// IsEmpty reports whether no branding field is set.
func (b Branding) IsEmpty() bool {
	return b.DisplayName == "" && b.LogoURL == "" && b.AccentColor == ""
}

// Sanitized returns the branding with every field validated.
// Invalid fields become empty; valid fields pass through.
func (b Branding) Sanitized() Branding {
	return Branding{
		DisplayName: sanitizeBrandName(b.DisplayName),
		LogoURL:     sanitizeBrandLogoURL(b.LogoURL),
		AccentColor: sanitizeBrandAccent(b.AccentColor),
	}
}

func sanitizeBrandName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	var out []rune
	for _, r := range name {
		if unicode.IsControl(r) {
			continue
		}
		out = append(out, r)
		if len(out) >= 64 {
			break
		}
	}
	return strings.TrimSpace(string(out))
}

func sanitizeBrandLogoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, " \t\r\n<>\"'") {
		return ""
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return raw
	}
	// Same-origin absolute path. Protocol-relative URLs (//host)
	// are rejected: they would load from an attacker-chosen host
	// if the config value were ever tampered with.
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	return ""
}

func sanitizeBrandAccent(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) != 4 && len(raw) != 7 {
		return ""
	}
	if !strings.HasPrefix(raw, "#") {
		return ""
	}
	for _, r := range raw[1:] {
		if !unicode.IsDigit(r) && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return ""
		}
	}
	return raw
}
