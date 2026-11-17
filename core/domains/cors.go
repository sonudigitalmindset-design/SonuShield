package domains

// CORS and security-header configuration (Batch 5).
//
// Security headers (securityHeaders) are a plain name/value map
// applied to every proxied response with set/overwrite semantics.
// Entries with invalid names or values (control characters, CR/LF)
// are skipped with a warning at load time and never emitted.
//
// CORS (cors) is an optional per-domain policy. It is OFF when the
// object is absent. An invalid CORS config fails closed for that
// domain: the whole policy is disabled with a warning, no CORS
// headers are emitted, and browsers enforce the same-origin
// policy. Invalid means: no allowed origins; an origin that is not
// "*" and does not parse as scheme://host; or allowCredentials
// combined with origin "*" (browsers reject that combination
// anyway). Allowed methods default to GET, HEAD, POST when unset.
// MaxAge is clamped to 0..86400 seconds.
//
// Preflight (OPTIONS) requests are answered directly by the proxy
// when CORS is configured, without challenge: browsers send
// preflights without credentials, so challenging them would break
// cross-origin access entirely. A preflight from a disallowed
// origin, for a disallowed method, or with disallowed headers is
// answered 403 with no CORS headers.

import (
	"fmt"
	"net/url"
	"strings"
)

// CORSConfig is one domain's CORS policy. A nil pointer means
// CORS is not configured.
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowedOrigins"`
	AllowedMethods   []string `json:"allowedMethods"`
	AllowedHeaders   []string `json:"allowedHeaders"`
	ExposedHeaders   []string `json:"exposedHeaders"`
	AllowCredentials bool     `json:"allowCredentials"`
	MaxAge           int      `json:"maxAge"`
}

// ValidateCORS checks a domain's CORS config and returns a
// normalized copy, or nil (with a warning) when the config is
// absent or invalid.
func ValidateCORS(name string, c *CORSConfig) *CORSConfig {
	if c == nil {
		return nil
	}
	invalid := func(reason string) *CORSConfig {
		fmt.Println("[ ! ] [ disabling CORS for " + name + ": " + reason + " ]")
		return nil
	}
	if len(c.AllowedOrigins) == 0 {
		return invalid("allowedOrigins is empty")
	}
	normalized := *c
	origins := make([]string, 0, len(c.AllowedOrigins))
	seenWildcard := false
	for _, origin := range c.AllowedOrigins {
		if origin == "*" {
			seenWildcard = true
			origins = append(origins, origin)
			continue
		}
		clean, ok := normalizeOrigin(origin)
		if !ok {
			return invalid("invalid origin " + origin)
		}
		origins = append(origins, clean)
	}
	normalized.AllowedOrigins = origins
	if seenWildcard && c.AllowCredentials {
		return invalid("allowCredentials cannot be combined with origin *")
	}
	if len(c.AllowedMethods) == 0 {
		normalized.AllowedMethods = []string{"GET", "HEAD", "POST"}
	} else {
		methods := make([]string, len(c.AllowedMethods))
		for i, m := range c.AllowedMethods {
			methods[i] = strings.ToUpper(strings.TrimSpace(m))
		}
		normalized.AllowedMethods = methods
	}
	if normalized.MaxAge < 0 {
		normalized.MaxAge = 0
	}
	if normalized.MaxAge > 86400 {
		normalized.MaxAge = 86400
	}
	return &normalized
}

// normalizeOrigin reduces an origin to scheme://host (lowercased
// host, no path, query, or fragment). It reports false for values
// that are not usable origins.
func normalizeOrigin(origin string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil {
		return "", false
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), true
}

// AllowOrigin reports whether origin is allowed, and the value to
// emit for Access-Control-Allow-Origin ("*" for wildcard configs,
// otherwise the origin itself, echoed).
func (c *CORSConfig) AllowOrigin(origin string) (string, bool) {
	if c == nil || origin == "" {
		return "", false
	}
	clean, ok := normalizeOrigin(origin)
	if !ok {
		return "", false
	}
	for _, allowed := range c.AllowedOrigins {
		if allowed == "*" {
			return "*", true
		}
		if allowed == clean {
			return clean, true
		}
	}
	return "", false
}

// AllowsMethod reports whether method is in the allowed list.
func (c *CORSConfig) AllowsMethod(method string) bool {
	if c == nil {
		return false
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, allowed := range c.AllowedMethods {
		if allowed == method {
			return true
		}
	}
	return false
}

// AllowsHeaders reports whether every requested header is allowed.
// A "*" in the configured list allows any header. An empty
// configured list allows only an empty request.
func (c *CORSConfig) AllowsHeaders(requested []string) bool {
	if c == nil {
		return false
	}
	for _, allowed := range c.AllowedHeaders {
		if allowed == "*" {
			return true
		}
	}
	for _, header := range requested {
		found := false
		for _, allowed := range c.AllowedHeaders {
			if strings.EqualFold(allowed, header) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// PreflightAllowHeaders returns the value for the
// Access-Control-Allow-Headers preflight response header: the
// requested headers echoed back when the config allows "*", the
// configured list otherwise, or "" when nothing should be sent.
func (c *CORSConfig) PreflightAllowHeaders(requested []string) string {
	if c == nil {
		return ""
	}
	for _, allowed := range c.AllowedHeaders {
		if allowed == "*" {
			return strings.Join(requested, ", ")
		}
	}
	return strings.Join(c.AllowedHeaders, ", ")
}

// ValidSecurityHeader reports whether a configured security
// header name/value pair is safe to emit: the name must be a
// valid header token and the value must contain no CR/LF.
func ValidSecurityHeader(name, value string) bool {
	if name == "" || strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, r := range name {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}
