package api

// Roles and audit logging for the control-plane API (Batch 4).
//
// Every API action has a minimum role. The main apisecret is
// always admin; additional secrets map to roles via
// proxy.apiRoles. Unknown actions are not in the table: they
// fall through to the handlers, which answer ERR_ACTION_NOT_FOUND
// exactly as before, for every role.
//
// The audit recorder wraps the ResponseWriter so the audit entry
// can report the real outcome (success + error code) of every
// action, including authentication failures. Params are scrubbed
// before logging: keys that look secret-like are dropped and
// values are truncated, so secrets never reach the audit log.

import (
	"encoding/json"
	"net"
	"net/http"
	"sonushield/core/events"
	"sonushield/core/logging"
	"sonushield/core/proxy"
	"strings"
)

const maxAuditParamLen = 200

// actionMinRole is the minimum role for every known API action.
// Roles rank viewer < operator < admin. Keep this table in sync
// with the action switches in api.go: an action missing here is
// treated as unknown and the handler answers ERR_ACTION_NOT_FOUND.
var actionMinRole = map[string]string{
	// Proxy actions: reads are viewer, FILL_IP_CACHE and RELOAD
	// are admin-only, the rest operator.
	"GET_PROXY_STATS":             proxy.RoleViewer,
	"GET_PROXY_STATS_CPU_USAGE":   proxy.RoleViewer,
	"GET_PROXY_STATS_RAM_USAGE":   proxy.RoleViewer,
	"GET_IP_REQUESTS":             proxy.RoleViewer,
	"GET_FINGERPRINT_REQUESTS":    proxy.RoleViewer,
	"GET_IP_CACHE":                proxy.RoleViewer,
	"FILL_IP_CACHE":               proxy.RoleAdmin,
	"RELOAD":                      proxy.RoleAdmin,
	"GET_PROXY_FEATURES":          proxy.RoleViewer,
	"REFRESH_REPUTATION_FEED":     proxy.RoleOperator,
	"GET_DOMAINS":                 proxy.RoleViewer,
	"GET_DOMAIN_TEMPLATES":        proxy.RoleViewer,
	"CREATE_DOMAIN_FROM_TEMPLATE": proxy.RoleAdmin,
	"IMPORT_DOMAINS":              proxy.RoleAdmin,
	"LIST_CONFIG_BACKUPS":         proxy.RoleViewer,
	"RESTORE_CONFIG_BACKUP":       proxy.RoleAdmin,

	// Domain actions: reads are viewer, stage/rules/cache are
	// operator, config writes are admin-only.
	"GET_TOTAL_REQUESTS":               proxy.RoleViewer,
	"GET_BYPASSED_REQUESTS":            proxy.RoleViewer,
	"GET_TOTAL_REQUESTS_PER_SECOND":    proxy.RoleViewer,
	"GET_BYPASSED_REQUESTS_PER_SECOND": proxy.RoleViewer,
	"GET_FIREWALL_RULES":               proxy.RoleViewer,
	"GET_LOGS":                         proxy.RoleViewer,
	"GET_DOMAIN_FEATURES":              proxy.RoleViewer,
	"GET_ATTACK_REPORT":                proxy.RoleViewer,
	"GET_SHADOW_REPORT":                proxy.RoleViewer,
	"GET_LATENCY":                      proxy.RoleViewer,
	"GET_POSTMORTEM":                   proxy.RoleViewer,
	"SET_MAINTENANCE":                  proxy.RoleOperator,
	"GET_MAINTENANCE":                  proxy.RoleOperator,
	"GET_SECURITY_GRADE":               proxy.RoleViewer,
	"GET_CERT_STATUS":                  proxy.RoleViewer,
	"GET_SUBDOMAIN_STATUS":             proxy.RoleViewer,
	"LIST_RULE_PACKS":                  proxy.RoleViewer,
	"IMPORT_RULE_PACK":                 proxy.RoleOperator,
	"CF_PREVIEW_IMPORT":                proxy.RoleOperator,
	"CF_APPLY_IMPORT":                  proxy.RoleAdmin,
	"PURGE_CACHE":                      proxy.RoleOperator,
	"SET_DOMAIN_FEATURES":              proxy.RoleAdmin,
	"GET_STAGE":                        proxy.RoleViewer,
	"SET_STAGE":                        proxy.RoleOperator,
	"CLEAR_LOGS":                       proxy.RoleOperator,
	"GET_DOMAIN_CONFIG":                proxy.RoleViewer,
	"SET_DOMAIN_CONFIG":                proxy.RoleAdmin,
	"ADD_RULE":                         proxy.RoleOperator,
	"UPDATE_RULE":                      proxy.RoleOperator,
	"DELETE_RULE":                      proxy.RoleOperator,
	"SIMULATE_RULE":                    proxy.RoleViewer,
	"EXPORT_RULES":                     proxy.RoleViewer,
	"IMPORT_RULES":                     proxy.RoleOperator,
	"GET_IP_LISTS":                     proxy.RoleViewer,
	"ADD_IP_ENTRY":                     proxy.RoleOperator,
	"REMOVE_IP_ENTRY":                  proxy.RoleOperator,
	"SEARCH_LOGS":                      proxy.RoleViewer,
	"GET_ATTACK_MAP":                   proxy.RoleViewer,
	"GET_TENANTS":                      proxy.RoleViewer,
	"GET_TENANT_USAGE":                 proxy.RoleViewer,
	"GET_STRIPE_STATUS":                proxy.RoleViewer,
	"REPORT_STRIPE_USAGE":              proxy.RoleAdmin,
	"GET_WEBHOOK_STATUS":               proxy.RoleViewer,
	"TEST_WEBHOOKS":                    proxy.RoleAdmin,
	"EXPORT_BACKUP":                    proxy.RoleAdmin,
	"RESTORE_BACKUP":                   proxy.RoleAdmin,
}

func roleLevel(role string) int {
	switch role {
	case proxy.RoleViewer:
		return 1
	case proxy.RoleOperator:
		return 2
	case proxy.RoleAdmin:
		return 3
	default:
		return 0
	}
}

// authorize reports whether an action is known and whether a role
// may run it. Unknown actions return known=false so the caller
// lets the handler answer ERR_ACTION_NOT_FOUND.
func authorize(role, action string) (known, allowed bool) {
	minRole, ok := actionMinRole[action]
	if !ok {
		return false, false
	}
	return true, roleLevel(role) >= roleLevel(minRole)
}

// auditRecorder captures the JSON response body written by
// APIResponse while passing everything through to the real
// writer, so the audit entry can report the actual outcome.
type auditRecorder struct {
	http.ResponseWriter
	captured []byte
}

func (r *auditRecorder) Write(p []byte) (int, error) {
	r.captured = append(r.captured, p...)
	return r.ResponseWriter.Write(p)
}

// auditOutcome parses a captured API response into its success
// flag and error code. An unparseable or empty body reports
// failure with no error code.
func auditOutcome(captured []byte) (success bool, errCode string) {
	if len(captured) == 0 {
		return false, ""
	}
	var response API_RESPONSE
	if err := json.Unmarshal(captured, &response); err != nil {
		return false, ""
	}
	if code, ok := response.Response["ERROR"]; ok {
		if text, ok := code.(string); ok {
			errCode = text
		}
	}
	return response.Success, errCode
}

// auditAction writes one audit entry for a completed API call.
func auditAction(request *http.Request, role, action, domain string, params map[string]string, captured []byte) {
	if len(captured) == 0 {
		return
	}
	success, errCode := auditOutcome(captured)
	scrubbed := scrubParams(params)
	logging.Audit(logging.AuditEntry{
		Role:    role,
		Action:  action,
		Domain:  domain,
		IP:      auditPeerIP(request),
		Params:  scrubbed,
		Success: success,
		Error:   errCode,
	})
	// Signed event webhooks / SIEM export (Batch 6). The event
	// carries the same scrubbed parameters as the audit log.
	events.PublishAudit(role, action, domain, auditPeerIP(request), scrubbed, success, errCode)
}

// auditUnauthenticated writes one audit entry for a rejected API
// call. The presented secret is never logged.
func auditUnauthenticated(request *http.Request, action, domain string) {
	logging.Audit(logging.AuditEntry{
		Role:    "unauthenticated",
		Action:  action,
		Domain:  domain,
		IP:      auditPeerIP(request),
		Success: false,
		Error:   "unauthorized",
	})
	events.PublishAudit("unauthenticated", action, domain, auditPeerIP(request), nil, false, "unauthorized")
}

// auditPeerIP returns the direct peer address of the API caller,
// without the port.
func auditPeerIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

var scrubbedParamSubstrings = []string{"secret", "token", "password", "key", "passphrase"}

// scrubParams drops secret-like params and truncates the rest, so
// the audit log can never carry a credential. A nil or empty map
// stays nil.
func scrubParams(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}
	scrubbed := make(map[string]string, len(params))
	for key, value := range params {
		lower := strings.ToLower(key)
		drop := false
		for _, substring := range scrubbedParamSubstrings {
			if strings.Contains(lower, substring) {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		if len(value) > maxAuditParamLen {
			value = value[:maxAuditParamLen]
		}
		scrubbed[key] = value
	}
	if len(scrubbed) == 0 {
		return nil
	}
	return scrubbed
}
