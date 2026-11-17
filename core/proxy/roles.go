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
// The map is held as an immutable snapshot in an atomic.Value so
// a reload can replace it while requests are in flight without
// risking a concurrent map access.

import (
	"fmt"
	"sync/atomic"
)

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

var apiRoles atomic.Value // map[string]string, immutable snapshot

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
		switch role {
		case RoleViewer, RoleOperator, RoleAdmin:
			cleaned[secret] = role
		default:
			fmt.Println("[ ! ] [ Unknown apiRoles role \"" + role + "\"; entry ignored ]")
		}
	}
	apiRoles.Store(cleaned)
}

// RoleForSecret returns the role for a presented API secret. The
// main apisecret is always admin and wins over any apiRoles entry
// with the same value. An empty secret never authenticates.
func RoleForSecret(secret string) (string, bool) {
	if secret == "" {
		return "", false
	}
	if secret == APISecret {
		return RoleAdmin, true
	}
	roles, _ := apiRoles.Load().(map[string]string)
	role, ok := roles[secret]
	return role, ok
}
