package controlplane

// Node API proxy with server-side scoping.
//
// The dashboard on the control host talks to proxy nodes only
// through /cp/api/<node>/_bProxy/api/v2/<action> (or
// /cp/api/<node>/_bProxy/api/v2/<domain>/<action>). The
// control plane forwards each call to the node with the
// node's admin API secret, so the node cannot tell control
// plane users apart — all scoping is enforced HERE, before
// forwarding, and never left to the UI:
//
//   - Role: the account role maps to a proxy API role level
//     (owner -> admin, reseller -> operator, tenant ->
//     viewer) and the node's own role table
//     (api.MinRoleFor) decides whether the action is allowed
//     at that level. Unknown actions pass through so the node
//     answers ERR_ACTION_NOT_FOUND exactly as before.
//   - Tenant scope: domain actions are allowed only when the
//     domain's tenant (from the node's domain map) is in the
//     caller's tenant set. Unknown domains are denied for
//     scoped callers (they cannot probe for other tenants'
//     domains) and passed through for the owner (the node
//     answers ERR_DOMAIN_NOT_FOUND).
//   - Proxy actions for scoped callers are limited to an
//     allowlist (domain list, tenant usage, tenant list,
//     approvals). Everything proxy-wide — IP tallies,
//     fingerprints, reload, backups — is owner-only, because
//     it mixes tenants' data or changes shared state.
//   - List responses are filtered to the caller's scope
//     (GET_DOMAINS, GET_TENANTS, GET_TENANT_USAGE,
//     LIST_APPROVALS) so a scoped caller never sees another
//     tenant's entries even in an allowed response.
//   - Approvals: a scoped caller may approve or reject only
//     approvals whose domain is in scope; proxy-wide
//     approvals are owner-only. The node still enforces
//     distinctness via the HMAC-signed caller identity when
//     a control-plane secret is configured.
//
// The proxy remains the source of truth: the control plane
// keeps no shadow copy of proxy config, and every forwarded
// call (allowed or denied) is audit-logged.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"sonushield/core/api"
	"sonushield/core/domains"
)

// scopedProxyActions are the proxy (domain-less) actions a
// reseller or tenant may run. Reads are filtered to scope;
// approvals are additionally domain-checked per request.
var scopedProxyActions = map[string]bool{
	"GET_DOMAINS":      true,
	"GET_TENANT_USAGE": true,
	"GET_TENANTS":      true,
	"LIST_APPROVALS":   true,
	"APPROVE_ACTION":   true,
	"REJECT_ACTION":    true,
}

// apiError writes a v2-shaped error envelope: the dashboard
// parses it exactly like a node error.
func apiError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"success":false,"results":{"ERROR":%q}}`, code)
}

// handleNodeAPI proxies one dashboard API call to a node.
func (s *Server) handleNodeAPI(w http.ResponseWriter, r *http.Request) {
	session, account, ok := s.authenticate(r)
	if !ok {
		apiError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
		return
	}
	if !requireCSRF(r) {
		s.audit.Write(AuditEntry{
			User: account.Username, Role: account.Role, Auth: authMethod(session),
			Node: nodeNameFromPath(r.URL.Path), Action: "CSRF", IP: peerIP(r),
			Success: false, Error: "missing csrf header",
		})
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/cp/api/")
	segments := strings.SplitN(rest, "/", 2)
	if len(segments) != 2 {
		apiError(w, http.StatusNotFound, "ERR_ACTION_NOT_FOUND")
		return
	}
	node, ok := s.nodes[segments[0]]
	if !ok {
		apiError(w, http.StatusNotFound, "ERR_ACTION_NOT_FOUND")
		return
	}
	nodePath := "/" + segments[1]
	if !strings.HasPrefix(nodePath, "/_bProxy/api/v2/") {
		apiError(w, http.StatusNotFound, "ERR_ACTION_NOT_FOUND")
		return
	}
	parts := strings.Split(strings.TrimPrefix(nodePath, "/_bProxy/api/v2/"), "/")
	if len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
		apiError(w, http.StatusNotFound, "ERR_ACTION_NOT_FOUND")
		return
	}
	action, domain := parts[0], ""
	if len(parts) == 2 {
		domain, action = parts[0], parts[1]
		if domain == "" || action == "" {
			apiError(w, http.StatusNotFound, "ERR_ACTION_NOT_FOUND")
			return
		}
	}
	params := firstQueryValues(r.URL.Query())

	allowed, denyCode := s.authorizeCall(r, account, node, action, domain, params)
	if !allowed {
		s.audit.Write(AuditEntry{
			User: account.Username, Role: account.Role, Auth: authMethod(session),
			Node: node.name, Action: action, Domain: domain, IP: peerIP(r),
			Params: scrubParams(params), Success: false, Error: denyCode,
		})
		apiError(w, http.StatusForbidden, denyCode)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, nodeMaxBodyBytes+1))
	if err != nil || len(body) > nodeMaxBodyBytes {
		apiError(w, http.StatusBadRequest, "ERR_BODY_READ_FAILED")
		return
	}
	forwardPath := "/_bProxy/api/v2/"
	if domain != "" {
		forwardPath += url.PathEscape(domain) + "/"
	}
	forwardPath += url.PathEscape(action)
	resp, err := node.call(r.Method, forwardPath, r.URL.RawQuery, body, account.Username)
	if err != nil {
		s.audit.Write(AuditEntry{
			User: account.Username, Role: account.Role, Auth: authMethod(session),
			Node: node.name, Action: action, Domain: domain, IP: peerIP(r),
			Params: scrubParams(params), Success: false, Error: "node unreachable",
		})
		apiError(w, http.StatusBadGateway, "ERR_FETCH_FAILED")
		return
	}

	outBody := resp.body
	if account.Role != RoleOwner && needsFiltering(action) {
		filtered, err := s.filterListResponse(node, account, action, resp.body)
		if err != nil {
			s.audit.Write(AuditEntry{
				User: account.Username, Role: account.Role, Auth: authMethod(session),
				Node: node.name, Action: action, Domain: domain, IP: peerIP(r),
				Params: scrubParams(params), Success: false, Error: "unparseable node response",
			})
			apiError(w, http.StatusBadGateway, "ERR_FETCH_FAILED")
			return
		}
		outBody = filtered
	}

	success, errCode := parseEnvelope(outBody)
	s.audit.Write(AuditEntry{
		User: account.Username, Role: account.Role, Auth: authMethod(session),
		Node: node.name, Action: action, Domain: domain, IP: peerIP(r),
		Params: scrubParams(params), Success: success, Error: errCode,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.status)
	w.Write(outBody)
}

// authorizeCall enforces the role + scope policy for one
// proxied call. It reports (allowed, denyCode).
func (s *Server) authorizeCall(r *http.Request, account *Account, node *nodeClient, action, domain string, params map[string]string) (bool, string) {
	// Role level first: the node's own table decides.
	if minRole, known := api.MinRoleFor(action); known {
		if !api.RoleAtLeast(account.NodeRole(), minRole) {
			return false, api.ERR_FORBIDDEN
		}
	}
	if account.Role == RoleOwner {
		return true, ""
	}
	tenantSet := account.TenantSet()
	if domain != "" {
		mapped, err := node.domainTenantMap(account.Username)
		if err != nil {
			// Fail closed: without the map, scope cannot be
			// proven.
			return false, api.ERR_FORBIDDEN
		}
		tenant, ok := mapped[domain]
		if !ok || !tenantSet[tenant] {
			return false, api.ERR_FORBIDDEN
		}
		return true, ""
	}
	// Proxy action for a scoped caller: allowlist only.
	if !scopedProxyActions[action] {
		return false, api.ERR_FORBIDDEN
	}
	switch action {
	case "GET_TENANT_USAGE":
		// An explicit tenant parameter outside scope is
		// denied outright; without one, the response is
		// filtered to scope below.
		if requested, ok := params["tenant"]; ok && requested != "" {
			if !tenantSet[domains.NormalizeTenant(requested)] {
				return false, api.ERR_FORBIDDEN
			}
		}
	case "APPROVE_ACTION", "REJECT_ACTION":
		if !s.approvalInScope(node, account, params["APPROVAL_ID"]) {
			return false, api.ERR_FORBIDDEN
		}
	}
	return true, ""
}

// approvalInScope reports whether a pending approval belongs
// to the caller's scope: its domain's tenant must be in the
// caller's set, and proxy-wide approvals (no domain) are
// owner-only. Unknown IDs are denied, never forwarded.
func (s *Server) approvalInScope(node *nodeClient, account *Account, approvalID string) bool {
	if approvalID == "" {
		return false
	}
	resp, err := node.call(http.MethodGet, "/_bProxy/api/v2/LIST_APPROVALS", "", nil, account.Username)
	if err != nil || resp.status != http.StatusOK {
		return false
	}
	var envelope struct {
		Success bool `json:"success"`
		Results struct {
			Approvals []struct {
				ID     string `json:"APPROVAL_ID"`
				Domain string `json:"DOMAIN"`
				Tenant string `json:"TENANT"`
			} `json:"APPROVALS"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resp.body, &envelope); err != nil || !envelope.Success {
		return false
	}
	tenantSet := account.TenantSet()
	for _, approval := range envelope.Results.Approvals {
		if approval.ID != approvalID {
			continue
		}
		if approval.Domain == "" {
			return false
		}
		mapped, err := node.domainTenantMap(account.Username)
		if err != nil {
			return false
		}
		tenant, ok := mapped[approval.Domain]
		return ok && tenantSet[tenant]
	}
	return false
}

// needsFiltering reports whether a list action's response must
// be filtered for scoped callers.
func needsFiltering(action string) bool {
	switch action {
	case "GET_DOMAINS", "GET_TENANTS", "GET_TENANT_USAGE", "LIST_APPROVALS":
		return true
	default:
		return false
	}
}

// filterListResponse removes out-of-scope entries from a node
// list response. The envelope shape is preserved; COUNT fields
// are recomputed. A response that cannot be parsed is an error:
// silently passing it through could leak another tenant.
// Approvals are filtered against the live domain map (the
// record's tenant may be empty for control-plane requests,
// since the node sees the admin secret), so a scoped caller
// never even sees another tenant's pending approval.
func (s *Server) filterListResponse(node *nodeClient, account *Account, action string, body []byte) ([]byte, error) {
	tenantSet := account.TenantSet()
	var envelope struct {
		Success bool                   `json:"success"`
		Results map[string]interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success || envelope.Results == nil {
		return body, nil
	}
	switch action {
	case "GET_DOMAINS":
		envelope.Results["DOMAINS"] = filterByTenant(envelope.Results["DOMAINS"], "TENANT", tenantSet)
	case "GET_TENANTS":
		envelope.Results["TENANTS"] = filterByTenant(envelope.Results["TENANTS"], "TENANT", tenantSet)
	case "GET_TENANT_USAGE":
		envelope.Results["USAGE"] = filterByTenant(envelope.Results["USAGE"], "TENANT", tenantSet)
	case "LIST_APPROVALS":
		mapped, err := node.domainTenantMap(account.Username)
		if err != nil {
			return nil, err
		}
		kept := filterApprovals(envelope.Results["APPROVALS"], mapped, tenantSet)
		envelope.Results["APPROVALS"] = kept
		envelope.Results["COUNT"] = len(kept)
	}
	return json.Marshal(envelope)
}

// filterByTenant keeps list entries whose tenant field is in
// the set. Entries without a tenant string are dropped.
func filterByTenant(list interface{}, tenantKey string, tenantSet map[string]bool) []interface{} {
	entries, ok := list.([]interface{})
	if !ok {
		return []interface{}{}
	}
	kept := []interface{}{}
	for _, entry := range entries {
		obj, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		tenant, _ := obj[tenantKey].(string)
		if tenantSet[domains.NormalizeTenant(tenant)] {
			kept = append(kept, entry)
		}
	}
	return kept
}

// filterApprovals keeps approvals whose domain's current
// tenant is in scope. Proxy-wide approvals (no domain) and
// approvals for unknown domains are dropped: they are
// owner-only.
func filterApprovals(list interface{}, mapped map[string]string, tenantSet map[string]bool) []interface{} {
	entries, ok := list.([]interface{})
	if !ok {
		return []interface{}{}
	}
	kept := []interface{}{}
	for _, entry := range entries {
		obj, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		domain, _ := obj["DOMAIN"].(string)
		if domain == "" {
			continue
		}
		tenant, ok := mapped[domain]
		if !ok || !tenantSet[tenant] {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// parseEnvelope extracts the success flag and error code from
// a v2-shaped response body.
func parseEnvelope(body []byte) (success bool, errCode string) {
	var envelope struct {
		Success bool `json:"success"`
		Results map[string]interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false, ""
	}
	if code, ok := envelope.Results["ERROR"].(string); ok {
		errCode = code
	}
	return envelope.Success, errCode
}

// firstQueryValues flattens query values to first-wins, for
// policy checks and audit params.
func firstQueryValues(values url.Values) map[string]string {
	params := make(map[string]string, len(values))
	for key, list := range values {
		if len(list) > 0 {
			params[key] = list[0]
		}
	}
	if len(params) == 0 {
		return nil
	}
	return params
}
