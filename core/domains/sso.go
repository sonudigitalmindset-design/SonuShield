package domains

// SSO/OIDC configuration (Batch 5).
//
// Optional OIDC login for the dashboard, coexisting with the
// existing secret-path auth. All fields are config-file-only;
// the client secret is never logged or returned by the API.
//
// The SSO paths (/_bProxy/sso/login, /_bProxy/sso/callback,
// /_bProxy/sso/logout, /_bProxy/sso/status) are temporary: the
// platform-host work will move the dashboard off protected
// domains, and SSO will move with it. See docs/dashboard.md.

import (
	"net/url"
	"strings"
)

// SSOConfig is the proxy.sso object. A nil pointer (or Enabled
// false) means SSO is not configured.
type SSOConfig struct {
	Enabled      bool              `json:"enabled"`
	Issuer       string            `json:"issuer"`
	ClientID     string            `json:"clientId"`
	ClientSecret string            `json:"clientSecret"`
	RedirectURL  string            `json:"redirectUrl"`
	Scopes       []string          `json:"scopes"`
	DefaultRole  string            `json:"defaultRole"`
	RoleClaim    string            `json:"roleClaim"`
	RoleMapping  map[string]string `json:"roleMapping"`
}

// Validate reports whether the config is usable, returning "" when
// it is or a reason when it is not. The reason never contains a
// secret value. An invalid config disables SSO with a warning;
// it never stops the proxy.
func (c *SSOConfig) Validate() string {
	if c == nil || !c.Enabled {
		return "disabled"
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return "issuer is empty"
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return "clientId is empty"
	}
	if c.ClientSecret == "" {
		return "clientSecret is empty"
	}
	if strings.TrimSpace(c.RedirectURL) == "" {
		return "redirectUrl is empty"
	}
	if !validSSOURL(c.Issuer) {
		return "issuer must be an https URL (http only for loopback hosts)"
	}
	if !validSSOURL(c.RedirectURL) {
		return "redirectUrl must be an https URL (http only for loopback hosts)"
	}
	role := c.DefaultRole
	if role == "" {
		role = "viewer"
	}
	switch role {
	case "viewer", "operator", "admin":
	default:
		return "defaultRole must be viewer, operator, or admin"
	}
	for value, role := range c.RoleMapping {
		switch role {
		case "viewer", "operator", "admin":
		default:
			return "roleMapping for " + value + " has an unknown role"
		}
	}
	return ""
}

// ScopesOrDefault returns the configured scopes, or ["openid"]
// when none are set.
func (c *SSOConfig) ScopesOrDefault() []string {
	if len(c.Scopes) == 0 {
		return []string{"openid"}
	}
	return c.Scopes
}

// validSSOURL requires https, except http on loopback hosts (for
// local testing against a mock identity provider).
func validSSOURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
