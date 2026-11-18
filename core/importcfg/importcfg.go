package importcfg

// Nginx server-block and Apache vhost import (Batch 8).
//
// Parse converts a documented subset of nginx or Apache
// configuration into SonuShield domain entries:
//
//   - nginx: server_name, listen (recorded, not needed),
//     proxy_pass (server level, or inside location /),
//     ssl_certificate, ssl_certificate_key.
//   - Apache: ServerName, ServerAlias, ProxyPass for "/",
//     SSLCertificateFile, SSLCertificateKeyFile.
//
// Everything else is reported, never silently dropped:
// directives with no SonuShield equivalent (rewrites,
// redirects, document roots, other location blocks) land in
// NotImported; unknown or unparseable directives land in
// Warnings; blocks that cannot become domains (no usable
// server name, no proxy_pass, unix-socket backends, wildcard
// names) land in Skipped with the reason. Include directives
// are never followed — the operator pastes the full text.
//
// One domain entry is produced per server name. The API
// layer validates entries with the same rules as bulk domain
// import (hostname, backend host:port, certificate/key
// pairing, uniqueness), so a preview that lists a domain
// still fails at apply time if the entry is invalid — the
// preview says exactly what would be attempted.

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ImportedDomain is one parsed domain entry.
type ImportedDomain struct {
	Name        string
	Backend     string
	Scheme      string
	Certificate string
	Key         string
	Source      string // e.g. `nginx server #1`, `apache vhost #2`
}

// Report is the full outcome of a parse.
type Report struct {
	Domains     []ImportedDomain
	Skipped     []string
	Warnings    []string
	NotImported []string
}

// Parse dispatches on format ("nginx" or "apache").
func Parse(format, text string) (Report, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "nginx":
		return parseNginx(text), nil
	case "apache":
		return parseApache(text), nil
	default:
		return Report{}, fmt.Errorf("format must be nginx or apache")
	}
}

// proxyURLToBackend converts a proxy_pass / ProxyPass URL
// into (backend host:port, scheme). Unix sockets and
// unparseable URLs are rejected with a reason.
func proxyURLToBackend(raw string) (backend, scheme string, ok bool) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", false
	}
	host := parsed.Host
	if host == "" {
		return "", "", false
	}
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	// The host must split into a non-empty host and a port:
	// this rejects unix-socket URLs (host "unix:") and other
	// malformed authorities that url.Parse tolerates.
	hostPart, portPart, err := net.SplitHostPort(host)
	if err != nil || hostPart == "" || portPart == "" {
		return "", "", false
	}
	return host, parsed.Scheme, true
}

// validServerName reports whether a name is usable as a
// SonuShield domain name for preview purposes. Wildcards,
// the nginx "_" placeholder, and empty names are rejected;
// the API layer applies the full hostname validation.
func validServerName(name string) bool {
	if name == "" || name == "_" || strings.Contains(name, "*") {
		return false
	}
	return true
}

func joinNames(names []string) string {
	return strings.Join(names, ", ")
}
