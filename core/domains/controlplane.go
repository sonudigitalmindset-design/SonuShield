package domains

// Control-plane configuration (platform model).
//
// The control plane is a separate server mode (`sonushield
// control`) that serves the management UI and API from its own
// host, managing one or more proxy nodes through their existing
// authenticated control API v2. It never proxies visitor
// traffic. Its configuration lives in the top-level
// "controlPlane" section of the same config file format; a
// dedicated control host runs with a file that contains only
// this section.
//
// All secrets here are config-file-only: node API secrets, the
// session-signing secret, and the SSO client secret are never
// logged, never returned by any API, and redacted by `export`
// and backups exactly like proxy secrets. The accounts file
// (usernames + password hashes) is a separate file so it can
// carry stricter permissions and its own backup policy.

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ControlPlaneConfig is the top-level "controlPlane" object. A
// nil pointer means the control plane is not configured; the
// proxy ignores the section entirely.
type ControlPlaneConfig struct {
	// Listen is the control-plane bind address, host:port.
	// Empty means the loopback default (127.0.0.1:8443).
	Listen string `json:"listen"`
	// Certificate and Key are the TLS certificate/key files
	// for the control host. Both empty means plain HTTP,
	// which is only safe on loopback or behind a
	// TLS-terminating reverse proxy; the server warns loudly
	// otherwise. Exactly one of the two is a config error.
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	// Hostname is the control host's public name, used only
	// in operator-facing messages and the dashboard-mode
	// redirect target when the proxy has no explicit
	// controlPlaneUrl. Optional.
	Hostname string `json:"hostname"`
	// AccountsFile is the account store path (usernames and
	// bcrypt password hashes). Empty means
	// "control-accounts.json" next to the config file.
	AccountsFile string `json:"accountsFile"`
	// SessionSecret signs session cookies. Empty means an
	// ephemeral key generated at startup: sessions do not
	// survive a restart, and the server warns. Set a long
	// random value for production.
	SessionSecret string `json:"sessionSecret"`
	// SessionTTLHours bounds session lifetime; <= 0 means 8,
	// clamped to 1..72.
	SessionTTLHours int `json:"sessionTTLHours"`
	// AuditLog is the control-plane audit file (one JSON
	// object per line). Empty means "control-audit.log".
	AuditLog string `json:"auditLog"`
	// Branding replaces the dashboard wordmark/title/accent
	// on the control host, under the same GPL hard limit as
	// proxy branding: attribution is never touched.
	Branding Branding `json:"branding"`
	// SSO is the optional OIDC login for the control host.
	// It reuses the proxy SSO config shape; on the control
	// plane the IdP only authenticates, and the account
	// file decides the role. See docs/control-plane.md.
	SSO *SSOConfig `json:"sso"`
	// Nodes are the proxy nodes this control plane manages.
	// At least one node is required to serve the dashboard.
	Nodes []ControlPlaneNode `json:"nodes"`
}

// ControlPlaneNode is one managed proxy node.
type ControlPlaneNode struct {
	// Name identifies the node in the dashboard switcher
	// and audit log: lowercase letters, digits, hyphens,
	// underscores. Names must be unique.
	Name string `json:"name"`
	// URL is the node's base URL, e.g.
	// "https://203.0.113.10:443". The control plane calls
	// the node's /_bProxy/api/v2/ endpoints under it.
	URL string `json:"url"`
	// APISecret is the node's apisecret (admin). It is sent
	// only as the X-SonuShield-Secret header to this node, and is
	// never logged or returned.
	APISecret string `json:"apiSecret"`
	// AdminSecret is the node's adminsecret, needed only
	// for the live log-tail path. Empty disables log tail
	// for this node through the control plane.
	AdminSecret string `json:"adminSecret,omitempty"`
	// ControlPlaneSecret is the shared secret that lets the
	// node tell control-plane users apart for two-person
	// approval. It must match the node's
	// proxy.controlPlaneSecret. Empty means approvals made
	// through the control plane fail closed at the node
	// (every caller looks identical), which is the safe
	// default.
	ControlPlaneSecret string `json:"controlPlaneSecret,omitempty"`
	// ServerName overrides the TLS ServerName (SNI) sent to
	// the node, for nodes whose certificate does not cover
	// the URL host (e.g. connecting by IP). Empty means the
	// URL hostname.
	ServerName string `json:"serverName,omitempty"`
	// Host is the HTTP Host header sent to the node. A
	// proxy node routes requests by Host, so this must be
	// a domain the node serves. Empty means ServerName
	// when set (the SNI name is already a served domain),
	// else the URL hostname.
	Host string `json:"host,omitempty"`
	// CAFile is a PEM bundle of CAs trusted for this node,
	// for nodes with private-CA certificates. Empty means
	// the system roots.
	CAFile string `json:"caFile,omitempty"`
	// InsecureSkipVerify disables certificate verification
	// for this node. Test setups only; the server warns
	// loudly when it is set.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

var controlPlaneNodeName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Validate reports whether the config is usable, returning ""
// when it is or a reason when it is not. Reasons never contain
// secret values. Shape checks only: file existence and TLS
// usability are checked at server startup with clear errors.
func (c *ControlPlaneConfig) Validate() string {
	if c == nil {
		return "controlPlane section is missing"
	}
	if c.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Listen); err != nil {
			return "listen must be a host:port address"
		}
	}
	if (c.Certificate == "") != (c.Key == "") {
		return "certificate and key must be set together"
	}
	if len(c.Nodes) == 0 {
		return "at least one node is required"
	}
	seen := map[string]bool{}
	for i, node := range c.Nodes {
		if !controlPlaneNodeName.MatchString(node.Name) {
			return "node has an invalid name (use lowercase letters, digits, hyphens, underscores)"
		}
		if seen[node.Name] {
			return "duplicate node name " + node.Name
		}
		seen[node.Name] = true
		parsed, err := url.Parse(strings.TrimSpace(node.URL))
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return "node " + node.Name + " has an invalid url (http or https with a host)"
		}
		if node.APISecret == "" {
			return "node " + node.Name + " has no apiSecret"
		}
		_ = i
	}
	if c.SSO != nil && c.SSO.Enabled {
		if reason := c.SSO.Validate(); reason != "" {
			return "sso: " + reason
		}
	}
	return ""
}

// ListenAddr returns the effective listen address.
func (c *ControlPlaneConfig) ListenAddr() string {
	if c == nil || c.Listen == "" {
		return "127.0.0.1:8443"
	}
	return c.Listen
}

// AccountsFilePath returns the effective accounts file path.
func (c *ControlPlaneConfig) AccountsFilePath() string {
	if c == nil || c.AccountsFile == "" {
		return "control-accounts.json"
	}
	return c.AccountsFile
}

// AuditLogPath returns the effective audit log path.
func (c *ControlPlaneConfig) AuditLogPath() string {
	if c == nil || c.AuditLog == "" {
		return "control-audit.log"
	}
	return c.AuditLog
}

// SessionTTL returns the effective session lifetime in hours,
// clamped to 1..72, defaulting to 8.
func (c *ControlPlaneConfig) SessionTTL() int {
	if c == nil || c.SessionTTLHours <= 0 {
		return 8
	}
	if c.SessionTTLHours > 72 {
		return 72
	}
	return c.SessionTTLHours
}

// DashboardMode values for proxy.dashboardMode. The empty
// value means "local": today's behavior, the dashboard served
// on each protected domain under the admin-secret path.
// "control-plane" answers the dashboard path with a redirect
// to the control host (or a bare 404 when no control-plane URL
// is configured); "off" disables the path entirely. Both keep
// the API itself working: only the page (and its PWA shell)
// is affected.
const (
	DashboardModeLocal        = "local"
	DashboardModeControlPlane = "control-plane"
	DashboardModeOff          = "off"
)

// NormalizeDashboardMode maps a configured value to an
// effective mode. Unknown values fail safe to "off" and report
// false so the caller can warn once.
func NormalizeDashboardMode(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", DashboardModeLocal:
		return DashboardModeLocal, true
	case DashboardModeControlPlane:
		return DashboardModeControlPlane, true
	case DashboardModeOff:
		return DashboardModeOff, true
	default:
		return DashboardModeOff, false
	}
}
