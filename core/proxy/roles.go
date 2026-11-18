package proxy

// API roles (Batch 4).
//
// The main apisecret always authenticates as admin. Operators may
// configure additional API secrets mapped to roles via the
// proxy.apiRoles config key:
//
//	"apiRoles": { "viewer-secret-here": "viewer", "ops-secret": "operator" }
//
// Roles: viewer (read-only), operator (stage/rules/cache), admin
// (everything, including config writes). Unknown roles are
// ignored with a warning, and empty secrets never match.
//
// Tenant-scoped roles (Batch 5): a value of the form
// "tenant:<name>:<role>" binds the secret to one tenant. The
// caller keeps the named role but only for that tenant's domains:
// domain actions on other tenants' domains are forbidden, and
// proxy actions are limited to GET_DOMAINS (filtered to the
// tenant) and GET_TENANT_USAGE (own tenant only). The tenant
// name is the normalized config value (see domains.NormalizeTenant).
// The last colon separates the role, so tenant names containing
// colons are matched literally up to that colon.
//
// The map is held as an immutable snapshot in an atomic.Value so
// a reload can replace it while requests are in flight without
// risking a concurrent map access.

import (
	"crypto/hmac"
	"fmt"
	"strings"
	"sync/atomic"
)

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// SSOCSRFHeader is the header cookie-authenticated API calls
// must carry (Batch 5). The dashboard sends it on every API
// request; a session cookie alone never authenticates an API
// call, so a cross-site request cannot ride the cookie.
const SSOCSRFHeader = "X-SonuShield-CSRF"

var apiRoles atomic.Value // map[string]string, immutable snapshot

// parseRoleValue parses one apiRoles value into its tenant scope
// ("" when unscoped) and role. It reports false for unknown
// roles, empty tenant names, and malformed values.
func parseRoleValue(value string) (tenant, role string, ok bool) {
	switch value {
	case RoleViewer, RoleOperator, RoleAdmin:
		return "", value, true
	}
	if !strings.HasPrefix(value, "tenant:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(value, "tenant:")
	idx := strings.LastIndex(rest, ":")
	if idx <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(rest[:idx])
	role = rest[idx+1:]
	switch role {
	case RoleViewer, RoleOperator, RoleAdmin:
		if name != "" {
			return name, role, true
		}
	}
	return "", "", false
}

// SetAPIRoles validates and stores the configured secret-to-role
// map. It is called from config.Load at startup and from the
// reload path, so role changes take effect on reload. Invalid
// roles are ignored with a warning; an empty or nil map clears
// all extra roles.
func SetAPIRoles(roles map[string]string) {
	cleaned := map[string]string{}
	for secret, role := range roles {
		if secret == "" {
			continue
		}
		if _, _, ok := parseRoleValue(role); ok {
			cleaned[secret] = role
		} else {
			fmt.Println("[ ! ] [ Unknown apiRoles role \"" + role + "\"; entry ignored ]")
		}
	}
	apiRoles.Store(cleaned)
}

// ScopeForSecret returns the role and tenant scope for a
// presented API secret. The main apisecret is always admin and
// unscoped, and wins over any apiRoles entry with the same value.
// An empty secret never authenticates. Tenant is "" for
// unscoped callers.
func ScopeForSecret(secret string) (role, tenant string, ok bool) {
	if secret == "" {
		return "", "", false
	}
	// Sale-readiness (L-1 fix): compare secrets in constant
	// time. A map lookup and == both leak timing; hmac.Equal
	// compares the full value. Every role secret is compared
	// (no early exit on match) so timing does not reveal
	// which entry matched either.
	if hmac.Equal([]byte(secret), []byte(APISecret)) {
		return RoleAdmin, "", true
	}
	roles, _ := apiRoles.Load().(map[string]string)
	matched := ""
	found := false
	for candidate, raw := range roles {
		if hmac.Equal([]byte(secret), []byte(candidate)) {
			matched, found = raw, true
		}
	}
	if !found {
		return "", "", false
	}
	tenant, role, ok = parseRoleValue(matched)
	return role, tenant, ok
}

// RoleForSecret returns the role for a presented API secret. The
// main apisecret is always admin and wins over any apiRoles entry
// with the same value. An empty secret never authenticates.
func RoleForSecret(secret string) (string, bool) {
	role, _, ok := ScopeForSecret(secret)
	return role, ok
}
