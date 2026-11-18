package api

// Two-person approval (Batch 7).
//
// When proxy.twoPersonApproval is on, sensitive control
// actions do not execute on the first call: the call is
// recorded as a pending approval and answered PENDING, and
// a SECOND, distinct approver must run APPROVE_ACTION with
// the approval ID before the action executes. REJECT_ACTION
// cancels a pending approval; LIST_APPROVALS lists them.
// Pending state is in-memory only (a restart clears it) and
// expires after proxy.approvalExpirySeconds (default 300).
// When the feature is off, the gate is a no-op and every
// action behaves exactly as before.
//
// Gated actions (a domain-set change is included; there is
// no DELETE_DOMAIN action — domain removal is a config
// edit plus reload — so it cannot be gated here):
// RESTORE_CONFIG_BACKUP, RESTORE_BACKUP, IMPORT_RULES,
// IMPORT_DOMAINS, IMPORT_RULE_PACK, CF_APPLY_IMPORT,
// CREATE_DOMAIN_FROM_TEMPLATE.
//
// "Distinct" means a different caller identity: the SHA-256
// of the presented API secret, or, for SSO callers, the
// SHA-256 of the session cookie value (via the
// SSOSessionCookieValue hook the server package registers;
// the cookie value itself is never stored or logged, only
// its hash). The approver must also satisfy the underlying
// action's role requirement and the same tenant scoping as
// the original call. Approval, rejection, request, and
// expiry are all audit-logged.
//
// The gate runs in Process/ProcessV2 after authentication
// and authorization, before dispatch, so it covers both API
// versions. Re-dispatch on approval calls the action
// handlers directly and therefore never re-enters the gate.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/events"
	"sonushield/core/firewall"
	"sonushield/core/logging"
	"sonushield/core/proxy"
)

const defaultApprovalExpirySeconds = 300

// SSOSessionCookieValue, when set by the server package,
// returns the raw SSO session cookie value for a request,
// for caller-identity hashing. Nil means SSO identity is
// unavailable (the server package always sets it, so nil
// only in tests that do not import the server); SSO callers
// then hash to a single shared identity and fail closed —
// they cannot approve each other's requests.
var SSOSessionCookieValue func(r *http.Request) string

// approvalGatedActions is the set of actions that require a
// second approver when two-person approval is enabled.
var approvalGatedActions = map[string]bool{
	"RESTORE_CONFIG_BACKUP":       true,
	"RESTORE_BACKUP":              true,
	"IMPORT_RULES":                true,
	"IMPORT_DOMAINS":              true,
	"IMPORT_RULE_PACK":            true,
	"CF_APPLY_IMPORT":             true,
	"CREATE_DOMAIN_FROM_TEMPLATE": true,
}

// pendingApproval is one recorded request awaiting a second
// approver. Params are a copy of the original call's
// parameters, replayed verbatim on approval.
type pendingApproval struct {
	ID            string
	Action        string
	Domain        string
	Params        map[string]string
	RequesterHash string
	RequesterRole string
	Tenant        string
	RequesterIP   string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

var (
	approvalMu       sync.Mutex
	pendingApprovals = map[string]*pendingApproval{}
)

// approvalEnabled reports whether two-person approval is
// on, reading the live configuration on every call so a
// reload takes effect without a restart.
func approvalEnabled() bool {
	return domains.Config != nil && domains.Config.Proxy.TwoPersonApproval
}

// approvalExpiryDuration returns the pending-approval
// lifetime: the configured value, or 300 seconds when
// unset/invalid.
func approvalExpiryDuration() time.Duration {
	seconds := defaultApprovalExpirySeconds
	if domains.Config != nil && domains.Config.Proxy.ApprovalExpirySeconds > 0 {
		seconds = domains.Config.Proxy.ApprovalExpirySeconds
	}
	return time.Duration(seconds) * time.Second
}

// callerHash identifies the caller for distinctness checks:
// the SHA-256 of the presented secret, or of the SSO
// session cookie value. Only the hash is ever stored.
// Control-plane caller identity (platform model). A control
// plane fronts many operators behind one node API secret, so
// without help every control-plane caller would hash to the
// same identity and two-person approval could never complete
// through it. When proxy.controlPlaneSecret is configured, the
// control plane proves each caller's identity with two
// headers: the caller value (a hash of the control-plane
// username, never the username itself) and an HMAC-SHA256 of
// that value under the shared secret. The headers are trusted
// ONLY when the HMAC verifies under the configured secret, so
// a holder of the API secret alone cannot forge a second
// identity and self-approve. With no secret configured the
// headers are ignored entirely and today's behavior is
// unchanged.
const (
	cpCallerHeader = "X-SonuShield-CP-Caller"
	cpCallerSig    = "X-SonuShield-CP-Signature"
)

// cpCallerIdentity verifies the control-plane caller headers
// and returns the caller value when they prove an identity.
// It reports false when the mechanism is unconfigured, the
// headers are absent, or the signature does not verify. The
// secret itself is never logged.
func cpCallerIdentity(request *http.Request) (string, bool) {
	secret := proxy.ControlPlaneSecret
	if secret == "" {
		return "", false
	}
	caller := request.Header.Get(cpCallerHeader)
	sig := request.Header.Get(cpCallerSig)
	if caller == "" || sig == "" {
		return "", false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(caller))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}
	return caller, true
}

func callerHash(request *http.Request, ssoAuthed bool, secret string) string {
	material := "secret:" + secret
	if caller, ok := cpCallerIdentity(request); ok {
		// A verified control-plane identity wins over the
		// shared node secret: distinct operators behind the
		// control plane hash distinctly.
		material = "cp:" + caller
	} else if ssoAuthed {
		cookieValue := ""
		if SSOSessionCookieValue != nil {
			cookieValue = SSOSessionCookieValue(request)
		}
		if cookieValue == "" {
			// Fail closed: all unidentifiable SSO callers
			// share one identity and cannot approve each
			// other's requests.
			material = "sso:missing"
		} else {
			material = "sso:" + cookieValue
		}
	}
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// newApprovalID returns a random approval identifier.
func newApprovalID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// gateApproval intercepts a sensitive action when
// two-person approval is enabled: it records the request,
// audits it, answers PENDING, and returns true. It returns
// false when the action must dispatch normally (feature
// off, or action not gated).
func gateApproval(writer http.ResponseWriter, request *http.Request, rawRole, tenant, hash, action, domain string, params map[string]string) bool {
	if !approvalEnabled() || !approvalGatedActions[action] {
		return false
	}
	pruneExpiredApprovals(time.Now())

	id, err := newApprovalID()
	if err != nil {
		APIResponse(writer, false, map[string]interface{}{
			"ERROR":        ERR_CONFIG_WRITE_FAILED,
			"ERROR_DETAIL": "could not create an approval request",
		})
		return true
	}
	stored := make(map[string]string, len(params))
	for key, value := range params {
		stored[key] = value
	}
	now := time.Now()
	pending := &pendingApproval{
		ID:            id,
		Action:        action,
		Domain:        domain,
		Params:        stored,
		RequesterHash: hash,
		RequesterRole: rawRole,
		Tenant:        tenant,
		RequesterIP:   auditPeerIP(request),
		CreatedAt:     now,
		ExpiresAt:     now.Add(approvalExpiryDuration()),
	}
	approvalMu.Lock()
	pendingApprovals[id] = pending
	approvalMu.Unlock()

	auditApprovalEvent(rawRole, "APPROVAL_REQUESTED", domain, pending.RequesterIP, id, action, true, "")
	APIResponse(writer, false, map[string]interface{}{
		"ERROR":        ERR_APPROVAL_REQUIRED,
		"ERROR_DETAIL": "this action requires approval by a second, distinct approver",
		"STATUS":       "PENDING",
		"APPROVAL_ID":  id,
		"ACTION":       action,
		"DOMAIN":       domain,
		"EXPIRES_AT":   pending.ExpiresAt.Format(time.RFC3339),
	})
	return true
}

// approvalIntercept handles the approval meta-actions
// (APPROVE_ACTION, REJECT_ACTION, LIST_APPROVALS) in
// Process/ProcessV2, where the request, role, and tenant
// are available. It returns false for any other action.
func approvalIntercept(writer http.ResponseWriter, request *http.Request, rawRole, tenant, hash, action, domain string, params map[string]string) bool {
	switch action {
	case "APPROVE_ACTION":
		approveAction(writer, request, rawRole, tenant, hash, params)
	case "REJECT_ACTION":
		rejectAction(writer, request, rawRole, tenant, hash, params)
	case "LIST_APPROVALS":
		listApprovals(writer, params, tenant)
	default:
		return false
	}
	return true
}

// approveAction executes a pending approval after the
// distinctness, role, and tenant checks, by re-dispatching
// the stored call to the action handlers.
func approveAction(writer http.ResponseWriter, request *http.Request, rawRole, tenant, hash string, params map[string]string) {
	fail := func(code, detail string) {
		results := map[string]interface{}{"ERROR": code}
		if detail != "" {
			results["ERROR_DETAIL"] = detail
		}
		APIResponse(writer, false, results)
	}
	for key := range params {
		if key != "APPROVAL_ID" {
			fail(ERR_INVALID_PARAM, "unknown parameter: "+key)
			return
		}
	}
	id, ok := params["APPROVAL_ID"]
	if !ok || id == "" {
		fail(ERR_PARAMS_REQUIRED, "APPROVAL_ID is required")
		return
	}
	pending, expired := takeApproval(id, time.Now())
	if pending == nil {
		if expired {
			fail(ERR_APPROVAL_NOT_FOUND, "the approval request has expired")
		} else {
			fail(ERR_APPROVAL_NOT_FOUND, "no such approval request")
		}
		return
	}
	// The approver must differ from the requester.
	if hash == pending.RequesterHash {
		restoreApproval(pending)
		fail(ERR_FORBIDDEN, "approval requires a different approver than the requester")
		return
	}
	// The approver must satisfy the underlying action's
	// role requirement.
	if _, allowed := authorize(rawRole, pending.Action); !allowed {
		restoreApproval(pending)
		fail(ERR_FORBIDDEN, "approver role may not run "+pending.Action)
		return
	}
	// Tenant scoping: a tenant-scoped approval needs an
	// approver from the same tenant, and a tenant-scoped
	// approver may only approve actions on their own
	// tenant's domains.
	if pending.Tenant != "" && tenant != pending.Tenant {
		restoreApproval(pending)
		fail(ERR_FORBIDDEN, "approver tenant does not match the request tenant")
		return
	}
	if tenant != "" && pending.Domain != "" {
		uncasted, ok := domains.DomainsMap.Load(pending.Domain)
		if !ok {
			restoreApproval(pending)
			fail(ERR_DOMAIN_NOT_FOUND, "")
			return
		}
		settings, _ := uncasted.(domains.DomainSettings)
		if domains.NormalizeTenant(settings.Tenant) != domains.NormalizeTenant(tenant) {
			restoreApproval(pending)
			fail(ERR_FORBIDDEN, "approver tenant does not match the domain tenant")
			return
		}
	}

	auditApprovalEvent(rawRole, "APPROVAL_APPROVED", pending.Domain, auditPeerIP(request), pending.ID, pending.Action, true, "")
	// Re-dispatch with the stored parameters. The handlers
	// write the response directly; the deferred audit entry
	// for this call reports the underlying outcome.
	if pending.Domain == "" {
		handleProxyActions(pending.Action, writer, pending.Params, tenant)
		return
	}
	uncasted, ok := domains.DomainsMap.Load(pending.Domain)
	if !ok {
		fail(ERR_DOMAIN_NOT_FOUND, "")
		return
	}
	settings, _ := uncasted.(domains.DomainSettings)
	firewall.Mutex.RLock()
	domainData := domains.DomainsData[pending.Domain]
	firewall.Mutex.RUnlock()
	handleDomainActions(pending.Action, writer, &domainData, &settings, pending.Params)
}

// rejectAction cancels a pending approval. The requester
// may cancel their own request; anyone else must satisfy
// the underlying action's role requirement.
func rejectAction(writer http.ResponseWriter, request *http.Request, rawRole, tenant, hash string, params map[string]string) {
	fail := func(code, detail string) {
		results := map[string]interface{}{"ERROR": code}
		if detail != "" {
			results["ERROR_DETAIL"] = detail
		}
		APIResponse(writer, false, results)
	}
	for key := range params {
		if key != "APPROVAL_ID" {
			fail(ERR_INVALID_PARAM, "unknown parameter: "+key)
			return
		}
	}
	id, ok := params["APPROVAL_ID"]
	if !ok || id == "" {
		fail(ERR_PARAMS_REQUIRED, "APPROVAL_ID is required")
		return
	}
	pending, expired := takeApproval(id, time.Now())
	if pending == nil {
		if expired {
			fail(ERR_APPROVAL_NOT_FOUND, "the approval request has expired")
		} else {
			fail(ERR_APPROVAL_NOT_FOUND, "no such approval request")
		}
		return
	}
	if hash != pending.RequesterHash {
		if _, allowed := authorize(rawRole, pending.Action); !allowed {
			restoreApproval(pending)
			fail(ERR_FORBIDDEN, "role may not reject "+pending.Action)
			return
		}
	}
	auditApprovalEvent(rawRole, "APPROVAL_REJECTED", pending.Domain, auditPeerIP(request), pending.ID, pending.Action, true, "")
	APIResponse(writer, true, map[string]interface{}{
		"REJECTED":    true,
		"APPROVAL_ID": pending.ID,
		"ACTION":      pending.Action,
		"DOMAIN":      pending.Domain,
	})
}

// listApprovals returns the pending approvals visible to
// the caller. Tenant-scoped callers see only their own
// tenant's requests. Stored parameters are never returned.
func listApprovals(writer http.ResponseWriter, params map[string]string, tenant string) {
	for range params {
		APIResponse(writer, false, map[string]interface{}{"ERROR": ERR_INVALID_PARAM})
		return
	}
	pruneExpiredApprovals(time.Now())
	approvalMu.Lock()
	defer approvalMu.Unlock()
	approvals := []map[string]interface{}{}
	for _, pending := range pendingApprovals {
		if tenant != "" && pending.Tenant != tenant {
			continue
		}
		approvals = append(approvals, map[string]interface{}{
			"APPROVAL_ID":    pending.ID,
			"ACTION":         pending.Action,
			"DOMAIN":         pending.Domain,
			"REQUESTER_ROLE": pending.RequesterRole,
			"TENANT":         pending.Tenant,
			"CREATED_AT":     pending.CreatedAt.Format(time.RFC3339),
			"EXPIRES_AT":     pending.ExpiresAt.Format(time.RFC3339),
		})
	}
	APIResponse(writer, true, map[string]interface{}{
		"ENABLED":   approvalEnabled(),
		"APPROVALS": approvals,
		"COUNT":     len(approvals),
	})
}

// takeApproval removes and returns a pending approval, or
// (nil, expired) when there is none. Expired approvals are
// audited as expired exactly once, on removal.
func takeApproval(id string, now time.Time) (*pendingApproval, bool) {
	approvalMu.Lock()
	pending, ok := pendingApprovals[id]
	if !ok {
		approvalMu.Unlock()
		return nil, false
	}
	delete(pendingApprovals, id)
	approvalMu.Unlock()
	if !now.Before(pending.ExpiresAt) {
		auditApprovalEvent(pending.RequesterRole, "APPROVAL_EXPIRED", pending.Domain, pending.RequesterIP, pending.ID, pending.Action, false, "expired")
		return nil, true
	}
	return pending, false
}

// restoreApproval puts a pending approval back after a
// failed approve/reject check, so a failed attempt does
// not consume the request.
func restoreApproval(pending *pendingApproval) {
	approvalMu.Lock()
	defer approvalMu.Unlock()
	pendingApprovals[pending.ID] = pending
}

// pruneExpiredApprovals removes expired approvals, auditing
// each expiry once.
func pruneExpiredApprovals(now time.Time) {
	approvalMu.Lock()
	var expired []*pendingApproval
	for id, pending := range pendingApprovals {
		if !now.Before(pending.ExpiresAt) {
			expired = append(expired, pending)
			delete(pendingApprovals, id)
		}
	}
	approvalMu.Unlock()
	for _, pending := range expired {
		auditApprovalEvent(pending.RequesterRole, "APPROVAL_EXPIRED", pending.Domain, pending.RequesterIP, pending.ID, pending.Action, false, "expired")
	}
}

// auditApprovalEvent writes one audit entry for an approval
// lifecycle event, to the audit log and the event webhooks,
// mirroring auditAction. The approval ID is random hex and
// safe to record; no secret or parameter value is included.
func auditApprovalEvent(role, event, domain, ip, approvalID, requestedAction string, success bool, errCode string) {
	params := map[string]string{
		"approval_id":      approvalID,
		"requested_action": requestedAction,
	}
	logging.Audit(logging.AuditEntry{
		Role:    role,
		Action:  event,
		Domain:  domain,
		IP:      ip,
		Params:  params,
		Success: success,
		Error:   errCode,
	})
	events.PublishAudit(role, event, domain, ip, params, success, errCode)
}

// approvalStateForTest returns the number of pending
// approvals. It exists for tests.
func approvalStateForTest() int {
	approvalMu.Lock()
	defer approvalMu.Unlock()
	return len(pendingApprovals)
}
