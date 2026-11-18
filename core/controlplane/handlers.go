package controlplane

// Control-plane web handlers: login, logout, first-owner
// setup, identity/node discovery, and account management.
//
// Login failures are deliberately generic — unknown user,
// wrong password, and disabled account all produce the same
// message and the same timing shape (a dummy bcrypt check
// runs for unknown users) so the login form cannot be used
// to enumerate accounts. Failed attempts are rate-limited
// per client IP. Successful logins, logouts, setup, and
// account changes are audit-logged; passwords and tokens are
// never written to the audit log or any other log.

import (
	_ "embed"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
)

//go:embed login.html
var loginHTML []byte

//go:embed setup.html
var setupHTML []byte

const (
	maxFormBytes      = 32 << 10
	maxJSONBodyBytes  = 64 << 10
	loginMaxFailures  = 5
	loginBlockWindow  = 5 * time.Minute
	loginAttemptTTL   = 15 * time.Minute
	genericLoginError = "Invalid username or password."
)

// loginLimiter counts failed logins per client IP.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

// newLoginLimiter builds an empty limiter.
func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string][]time.Time{}}
}

// blocked reports whether the IP has exhausted its failures
// within the window.
func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := l.failures[ip][:0]
	for _, at := range l.failures[ip] {
		if now.Sub(at) < loginBlockWindow {
			recent = append(recent, at)
		}
	}
	l.failures[ip] = recent
	return len(recent) >= loginMaxFailures
}

// recordFailure notes one failed attempt, pruning stale
// entries opportunistically.
func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.failures[ip] = append(l.failures[ip], now)
	if len(l.failures) > 1024 {
		for key, attempts := range l.failures {
			if len(attempts) == 0 || now.Sub(attempts[len(attempts)-1]) > loginAttemptTTL {
				delete(l.failures, key)
			}
		}
	}
}

// reset clears an IP's failures after a successful login.
func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}

// peerIP returns the direct peer address without the port.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authMethod names the session's login method for the audit
// log.
func authMethod(session sessionPayload) string {
	if session.SSO {
		return "sso"
	}
	return "password"
}

// nodeNameFromPath extracts the node segment of a /cp/api/
// path for audit entries written before routing.
func nodeNameFromPath(path string) string {
	rest := strings.TrimPrefix(path, "/cp/api/")
	segments := strings.SplitN(rest, "/", 2)
	if len(segments) == 0 {
		return ""
	}
	return segments[0]
}

// renderLoginPage writes the sign-in page, with an optional
// error message and SSO button.
func (s *Server) renderLoginPage(w http.ResponseWriter, errorMessage string, status int) {
	page := string(loginHTML)
	if errorMessage != "" {
		page = strings.ReplaceAll(page, "__ERROR__", `<div class="err">`+html.EscapeString(errorMessage)+`</div>`)
	} else {
		page = strings.ReplaceAll(page, "__ERROR__", "")
	}
	if s.ssoEnabled() {
		page = strings.ReplaceAll(page, "__SSO_BUTTON__", `<a class="sso" href="/sso/login">Continue with single sign-on</a>`)
	} else {
		page = strings.ReplaceAll(page, "__SSO_BUTTON__", "")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, page)
}

// renderSetupPage writes the first-owner setup page.
func (s *Server) renderSetupPage(w http.ResponseWriter, errorMessage string, status int) {
	page := string(setupHTML)
	if errorMessage != "" {
		page = strings.ReplaceAll(page, "__ERROR__", `<div class="err">`+html.EscapeString(errorMessage)+`</div>`)
	} else {
		page = strings.ReplaceAll(page, "__ERROR__", "")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, page)
}

// handleLogin serves GET (the form) and POST (the check).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if _, _, ok := s.authenticate(r); ok {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		s.renderLoginPage(w, "", http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := peerIP(r)
	if s.limiter.blocked(ip) {
		s.audit.Write(AuditEntry{User: "", Role: "", Action: "LOGIN", IP: ip, Success: false, Error: "rate limited"})
		w.Header().Set("Retry-After", "60")
		s.renderLoginPage(w, "Too many failed sign-in attempts. Please wait a few minutes and try again.", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderLoginPage(w, genericLoginError, http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" || !s.accounts.CheckPassword(username, password) {
		s.limiter.recordFailure(ip)
		s.audit.Write(AuditEntry{User: username, Role: "", Action: "LOGIN", IP: ip, Success: false, Error: "invalid credentials"})
		s.renderLoginPage(w, genericLoginError, http.StatusUnauthorized)
		return
	}
	account := s.accounts.Get(username)
	if account == nil || account.Disabled {
		s.limiter.recordFailure(ip)
		s.audit.Write(AuditEntry{User: username, Role: "", Action: "LOGIN", IP: ip, Success: false, Error: "invalid credentials"})
		s.renderLoginPage(w, genericLoginError, http.StatusUnauthorized)
		return
	}
	s.limiter.reset(ip)
	s.sessions.setCookie(w, s.sessions.create(username, false))
	s.audit.Write(AuditEntry{User: username, Role: account.Role, Auth: "password", Action: "LOGIN", IP: ip, Success: true})
	http.Redirect(w, r, safeNext(r.Form.Get("next")), http.StatusFound)
}

// safeNext validates a post-login redirect target: a relative
// path on this host only, never an absolute URL or a
// protocol-relative URL (open-redirect protection).
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/dashboard"
	}
	return next
}

// handleLogout clears the session. POST + CSRF only: a GET
// logout would let any site sign the operator out (and a
// CSRF-less POST would let one forge the request).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	session, account, ok := s.authenticate(r)
	if !ok || !requireCSRF(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	s.sessions.clearCookie(w)
	s.audit.Write(AuditEntry{User: account.Username, Role: account.Role, Auth: authMethod(session), Action: "LOGOUT", IP: peerIP(r), Success: true})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleSetup serves the first-owner bootstrap. It answers
// 404 whenever bootstrap is not pending (owner exists, or no
// live setup token), so the endpoint reveals nothing about
// the account state to unauthenticated callers.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	accountsPath := s.cfg.AccountsFilePath()
	if !SetupPending(accountsPath) {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		s.renderSetupPage(w, "", http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderSetupPage(w, "The setup request could not be read.", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	confirm := r.Form.Get("confirm")
	token := r.Form.Get("token")
	// Validate the fields before consuming the token, so a
	// typo does not burn the one-time token.
	if err := validateAccountFields(username, password, RoleOwner, "", nil); err != nil {
		s.renderSetupPage(w, err.Error(), http.StatusBadRequest)
		return
	}
	if password != confirm {
		s.renderSetupPage(w, "The passwords do not match.", http.StatusBadRequest)
		return
	}
	if !verifySetupToken(accountsPath, token) {
		s.audit.Write(AuditEntry{User: username, Role: RoleOwner, Action: "SETUP", IP: peerIP(r), Success: false, Error: "invalid or expired setup token"})
		s.renderSetupPage(w, "The setup token is invalid or has expired. Generate a new one with sonushield control-setup.", http.StatusUnauthorized)
		return
	}
	account, err := s.accounts.Create(username, password, RoleOwner, "", nil)
	if err != nil {
		s.audit.Write(AuditEntry{User: username, Role: RoleOwner, Action: "SETUP", IP: peerIP(r), Success: false, Error: "account creation failed"})
		s.renderSetupPage(w, "The owner account could not be created: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Write(AuditEntry{User: account.Username, Role: account.Role, Action: "SETUP", IP: peerIP(r), Success: true})
	s.sessions.setCookie(w, s.sessions.create(username, false))
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleWhoami reports the caller's identity and scope.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	session, account, ok := s.authenticate(r)
	if !ok {
		apiError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
		return
	}
	if !requireCSRF(r) {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	// Result keys follow the v2 API convention (UPPERCASE),
	// matching what the dashboard parses.
	writeJSON(w, map[string]interface{}{
		"USERNAME": account.Username,
		"ROLE":     account.Role,
		"TENANT":   account.Tenant,
		"TENANTS":  account.Tenants,
		"SSO":      session.SSO,
	})
}

// handleNodes lists managed node names. URLs and secrets are
// never exposed: the dashboard needs only names to build
// /cp/api/<node>/ paths.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.authenticate(r)
	if !ok {
		apiError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
		return
	}
	if !requireCSRF(r) {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	names := make([]string, 0, len(s.nodeOrder))
	for _, name := range s.nodeOrder {
		names = append(names, name)
	}
	writeJSON(w, map[string]interface{}{"NODES": names})
}

// accountView is the safe account shape for list responses:
// no password hash, ever. Keys follow the v2 API convention
// (UPPERCASE), matching what the dashboard parses.
type accountView struct {
	Username string   `json:"USERNAME"`
	Role     string   `json:"ROLE"`
	Tenant   string   `json:"TENANT,omitempty"`
	Tenants  []string `json:"TENANTS,omitempty"`
	Disabled bool     `json:"DISABLED"`
}

func toAccountView(account *Account) accountView {
	return accountView{
		Username: account.Username,
		Role:     account.Role,
		Tenant:   account.Tenant,
		Tenants:  account.Tenants,
		Disabled: account.Disabled,
	}
}

// visibleAccounts returns the accounts the caller may see:
// the owner sees all; a reseller sees itself plus tenant
// accounts within its tenant set; tenants see nothing here
// (the accounts API denies them outright).
func (s *Server) visibleAccounts(caller *Account) []accountView {
	list := []accountView{}
	set := caller.TenantSet()
	for _, account := range s.accounts.List() {
		switch caller.Role {
		case RoleOwner:
			list = append(list, toAccountView(account))
		case RoleReseller:
			if account.Username == caller.Username {
				list = append(list, toAccountView(account))
			} else if account.Role == RoleTenant && set[account.Tenant] {
				list = append(list, toAccountView(account))
			}
		}
	}
	return list
}

// handleAccounts serves account list (GET), create (POST),
// and delete (DELETE).
func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	_, caller, ok := s.authenticate(r)
	if !ok {
		apiError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
		return
	}
	if !requireCSRF(r) {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if caller.Role == RoleTenant {
			apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
			return
		}
		writeJSON(w, map[string]interface{}{"ACCOUNTS": s.visibleAccounts(caller)})
	case http.MethodPost:
		s.createAccount(w, r, caller)
	case http.MethodDelete:
		s.deleteAccount(w, r, caller)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// createAccountRequest is the account-creation payload.
type createAccountRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Role     string   `json:"role"`
	Tenant   string   `json:"tenant"`
	Tenants  []string `json:"tenants"`
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request, caller *Account) {
	var req createAccountRequest
	if err := readJSONBody(w, r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "ERR_JSON_READ_FAILED")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	// Resellers may create tenant accounts only, and only
	// within their own tenant set.
	if caller.Role == RoleReseller {
		if req.Role != RoleTenant {
			s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_CREATE", IP: peerIP(r), Success: false, Error: "reseller may only create tenant accounts"})
			apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
			return
		}
		if !caller.TenantSet()[domains.NormalizeTenant(req.Tenant)] {
			s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_CREATE", IP: peerIP(r), Success: false, Error: "tenant outside reseller scope"})
			apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
			return
		}
	}
	if caller.Role == RoleTenant {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	account, err := s.accounts.Create(req.Username, req.Password, req.Role, req.Tenant, req.Tenants)
	if err != nil {
		s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_CREATE", IP: peerIP(r), Success: false, Error: err.Error()})
		apiError(w, http.StatusBadRequest, "ERR_INVALID_PARAM")
		return
	}
	s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_CREATE", IP: peerIP(r), Params: map[string]string{"username": account.Username, "role": account.Role}, Success: true})
	writeJSON(w, map[string]interface{}{"ACCOUNT": toAccountView(account)})
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request, caller *Account) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		apiError(w, http.StatusBadRequest, "ERR_PARAMS_REQUIRED")
		return
	}
	if username == caller.Username {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	target := s.accounts.Get(username)
	if target == nil {
		apiError(w, http.StatusNotFound, "ERR_INVALID_PARAM")
		return
	}
	if caller.Role == RoleReseller {
		if target.Role != RoleTenant || !caller.TenantSet()[target.Tenant] {
			s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_DELETE", IP: peerIP(r), Success: false, Error: "target outside reseller scope"})
			apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
			return
		}
	}
	if caller.Role == RoleTenant {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	if err := s.accounts.Delete(username); err != nil {
		s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_DELETE", IP: peerIP(r), Success: false, Error: err.Error()})
		apiError(w, http.StatusBadRequest, "ERR_INVALID_PARAM")
		return
	}
	s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_DELETE", IP: peerIP(r), Params: map[string]string{"username": username}, Success: true})
	writeJSON(w, map[string]interface{}{"DELETED": username})
}

// passwordChangeRequest is the password-change payload. An
// owner resetting another account omits currentPassword;
// everyone changing their own must present it.
type passwordChangeRequest struct {
	Username        string `json:"username"`
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// handleAccountPassword serves password changes and resets.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	_, caller, ok := s.authenticate(r)
	if !ok {
		apiError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED")
		return
	}
	if !requireCSRF(r) {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req passwordChangeRequest
	if err := readJSONBody(w, r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "ERR_JSON_READ_FAILED")
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = caller.Username
	}
	if username == caller.Username {
		if !s.accounts.CheckPassword(username, req.CurrentPassword) {
			s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_PASSWORD", IP: peerIP(r), Success: false, Error: "current password mismatch"})
			apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
			return
		}
	} else if caller.Role != RoleOwner {
		apiError(w, http.StatusForbidden, "ERR_FORBIDDEN")
		return
	}
	if err := s.accounts.SetPassword(username, req.NewPassword); err != nil {
		s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_PASSWORD", IP: peerIP(r), Success: false, Error: err.Error()})
		apiError(w, http.StatusBadRequest, "ERR_INVALID_PARAM")
		return
	}
	s.audit.Write(AuditEntry{User: caller.Username, Role: caller.Role, Action: "ACCOUNT_PASSWORD", IP: peerIP(r), Params: map[string]string{"username": username}, Success: true})
	writeJSON(w, map[string]interface{}{"CHANGED": username})
}

// readJSONBody decodes a size-capped JSON request body.
func readJSONBody(w http.ResponseWriter, r *http.Request, target interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

// writeJSON writes a success envelope matching the v2 API
// shape, so dashboard code can reuse its response handling.
func writeJSON(w http.ResponseWriter, results map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	data, _ := json.Marshal(map[string]interface{}{
		"success": true,
		"results": results,
	})
	w.Write(data)
}
