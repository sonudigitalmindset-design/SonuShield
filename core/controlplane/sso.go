package controlplane

// OIDC single sign-on for the control plane.
//
// Optional, coexisting with password login: when
// controlPlane.sso is configured, operators may sign in
// through their identity provider. The flow mirrors the
// proxy SSO implementation (core/server/sso.go) and reuses
// the same security-critical code path — the shared JWT
// verifier (domains.JWTVerifier) — with the same properties:
//
//   - Discovery is fetched without following redirects, and
//     the document's issuer must exactly equal the configured
//     issuer; endpoints must be https (http only for loopback
//     hosts, for local testing).
//   - ID tokens must be RS256/ES256 signed by a JWKS key
//     (HS256 and "alg: none" are rejected by the verifier);
//     iss, aud, exp, sub, and nonce are all checked.
//   - Authorization state is single-use, 10-minute TTL,
//     server-side, and bound to a short-lived cookie; PKCE
//     S256 is required.
//   - Tokens, codes, and secrets are never logged; failures
//     log only a failure class.
//
// The control-plane difference is authorization: the IdP only
// authenticates. The username comes from the ID token
// (email, then preferred_username, then sub) and must match
// an existing, enabled control-plane account; the role and
// tenant scope always come from that account, never from IdP
// claims. The SSO defaultRole/roleClaim/roleMapping settings
// are ignored on the control plane. An SSO login creates the
// same session cookie as a password login, marked SSO in the
// audit log.
//
// Endpoints live on the control host only:
//
//   - GET /sso/login — starts the authorization-code flow.
//   - GET /sso/callback — exchanges the code, verifies the
//     ID token, and sets the session cookie.
//   - GET /sso/logout — clears the session cookie.
//   - GET /sso/status — {"enabled": bool}, so the login page
//     can offer SSO only when it is configured.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sonushield/core/domains"
)

const (
	cpSSOStateCookie = "__sonushield_cp_sso_state"
	cpSSOStateTTL    = 10 * time.Minute
	cpSSOStateCap    = 4096
	cpSSOHTTPTimeout = 10 * time.Second
	cpSSOMaxBody     = 1 << 20
)

// cpSSOHTTP never follows redirects: a redirect could point
// the code exchange (and the client secret) at an attacker's
// endpoint.
var cpSSOHTTP = &http.Client{
	Timeout: cpSSOHTTPTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// cpOIDCProvider is a discovered identity provider with its
// cached JWKS verifier.
type cpOIDCProvider struct {
	issuer   string
	authURL  string
	tokenURL string
	jwksURL  string
	verifier *domains.JWTVerifier
	fetched  time.Time
}

// cpSSOState is one in-flight login attempt, held server-side
// and bound to the browser by the state cookie.
type cpSSOState struct {
	state    string
	nonce    string
	verifier string
	created  time.Time
}

// ssoConfig returns the live SSO config when SSO is enabled
// and valid.
func (s *Server) ssoConfig() (*domains.SSOConfig, bool) {
	if s.cfg.SSO == nil || !s.cfg.SSO.Enabled {
		return nil, false
	}
	if s.cfg.SSO.Validate() != "" {
		return nil, false
	}
	return s.cfg.SSO, true
}

// ssoEndpointOK requires https endpoints, except http on
// loopback hosts (local testing). It mirrors the config
// validation rule for endpoints learned from discovery.
func ssoEndpointOK(raw string) bool {
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

// getOIDCProvider returns the cached provider for the
// configured issuer, discovering it when absent, stale (1
// hour), or for a different issuer.
func (s *Server) getOIDCProvider(cfg *domains.SSOConfig) (*cpOIDCProvider, error) {
	s.ssoProviderMu.Lock()
	defer s.ssoProviderMu.Unlock()
	if s.ssoProvider != nil && s.ssoProvider.issuer == cfg.Issuer && time.Since(s.ssoProvider.fetched) < time.Hour {
		return s.ssoProvider, nil
	}
	discoveryURL := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	resp, err := cpSSOHTTP.Get(discoveryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cpSSOMaxBody))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Issuer   string `json:"issuer"`
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
		JWKSURL  string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("discovery issuer mismatch")
	}
	if !ssoEndpointOK(doc.AuthURL) || !ssoEndpointOK(doc.TokenURL) || !ssoEndpointOK(doc.JWKSURL) {
		return nil, fmt.Errorf("discovery endpoints are not usable URLs")
	}
	provider := &cpOIDCProvider{
		issuer:   doc.Issuer,
		authURL:  doc.AuthURL,
		tokenURL: doc.TokenURL,
		jwksURL:  doc.JWKSURL,
		verifier: domains.NewJWTVerifier("cp-sso", "", doc.JWKSURL),
		fetched:  time.Now(),
	}
	s.ssoProvider = provider
	return provider, nil
}

// storeSSOState records a login attempt. It reports false
// when the store is full even after purging expired entries;
// the login then fails closed.
func (s *Server) storeSSOState(id string, st *cpSSOState) bool {
	s.ssoStateMu.Lock()
	defer s.ssoStateMu.Unlock()
	if len(s.ssoStates) >= cpSSOStateCap {
		now := time.Now()
		for key, old := range s.ssoStates {
			if now.Sub(old.created) > cpSSOStateTTL {
				delete(s.ssoStates, key)
			}
		}
		if len(s.ssoStates) >= cpSSOStateCap {
			return false
		}
	}
	s.ssoStates[id] = st
	return true
}

// takeSSOState consumes a login attempt exactly once.
// Expired or unknown attempts fail.
func (s *Server) takeSSOState(id string) (*cpSSOState, bool) {
	s.ssoStateMu.Lock()
	defer s.ssoStateMu.Unlock()
	st, ok := s.ssoStates[id]
	delete(s.ssoStates, id)
	if !ok || time.Since(st.created) > cpSSOStateTTL {
		return nil, false
	}
	return st, true
}

// ssoRandom returns hex-encoded random bytes for state, nonce,
// PKCE verifier, and state-cookie IDs.
func ssoRandom() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// ssoFail writes a generic sign-in failure page. Details stay
// in the server log (failure class only); the page reveals
// nothing.
func (s *Server) ssoFail(w http.ResponseWriter, r *http.Request, logClass string) {
	fmt.Println("[ ! ] [ control-plane sso: " + logClass + " ]")
	s.audit.Write(AuditEntry{User: "", Role: "", Auth: "sso", Action: "LOGIN", IP: peerIP(r), Success: false, Error: logClass})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign-in failed</title><style>body{font-family:Arial,sans-serif;background:#0b1220;color:#e6ebf2;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#0d1729;border:1px solid #1e2c47;border-radius:8px;padding:32px;max-width:420px;text-align:center}h1{font-size:20px;margin:0 0 8px}p{margin:8px 0;color:#9aa7bc}a{color:#f6821f}</style></head><body><div class="box"><h1>Sign-in failed</h1><p>Something went wrong during sign-in. Please try again.</p><p><a href="/login">Back to sign-in</a></p></div></body></html>`)
}

// handleSSO routes /sso/* requests. The status endpoint
// always answers; login, callback, and logout only when SSO
// is configured.
func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/sso/status":
		_, enabled := s.ssoConfig()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"enabled":%v}`, enabled)
		return
	case "/sso/login", "/sso/callback", "/sso/logout":
		cfg, ok := s.ssoConfig()
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/sso/login":
			s.handleSSOLogin(w, r, cfg)
		case "/sso/callback":
			s.handleSSOCallback(w, r, cfg)
		case "/sso/logout":
			s.handleSSOLogout(w, r)
		}
		return
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request, cfg *domains.SSOConfig) {
	// Already signed in: go straight to the dashboard.
	if _, _, ok := s.authenticate(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	provider, err := s.getOIDCProvider(cfg)
	if err != nil {
		s.ssoFail(w, r, "discovery failed")
		return
	}
	state, err1 := ssoRandom()
	nonce, err2 := ssoRandom()
	verifier, err3 := ssoRandom()
	id, err4 := ssoRandom()
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		s.ssoFail(w, r, "randomness failed")
		return
	}
	if !s.storeSSOState(id, &cpSSOState{state: state, nonce: nonce, verifier: verifier, created: time.Now()}) {
		s.ssoFail(w, r, "state store full")
		return
	}
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	http.SetCookie(w, &http.Cookie{
		Name:     cpSSOStateCookie,
		Value:    id,
		Path:     "/sso/",
		HttpOnly: true,
		Secure:   s.tlsEnabled,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cpSSOStateTTL.Seconds()),
	})
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {cfg.RedirectURL},
		"scope":                 {strings.Join(cfg.ScopesOrDefault(), " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, provider.authURL+"?"+params.Encode(), http.StatusFound)
}

func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request, cfg *domains.SSOConfig) {
	query := r.URL.Query()
	if query.Get("error") != "" {
		s.ssoFail(w, r, "provider returned an error")
		return
	}
	cookie, err := r.Cookie(cpSSOStateCookie)
	if err != nil || cookie.Value == "" {
		s.ssoFail(w, r, "state cookie missing")
		return
	}
	stored, ok := s.takeSSOState(cookie.Value)
	if !ok {
		s.ssoFail(w, r, "state missing or expired")
		return
	}
	// The state cookie is single-use: clear it now.
	http.SetCookie(w, &http.Cookie{
		Name:     cpSSOStateCookie,
		Value:    "",
		Path:     "/sso/",
		HttpOnly: true,
		Secure:   s.tlsEnabled,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	if !hmac.Equal([]byte(query.Get("state")), []byte(stored.state)) {
		s.ssoFail(w, r, "state mismatch")
		return
	}
	code := query.Get("code")
	if code == "" {
		s.ssoFail(w, r, "code missing")
		return
	}
	provider, err := s.getOIDCProvider(cfg)
	if err != nil {
		s.ssoFail(w, r, "discovery failed")
		return
	}
	idToken, err := exchangeCode(provider, cfg, code, stored.verifier)
	if err != nil {
		s.ssoFail(w, r, "code exchange failed")
		return
	}
	claims, ok := provider.verifier.VerifyClaims(idToken)
	if !ok {
		s.ssoFail(w, r, "id token invalid")
		return
	}
	if !ssoClaimsOK(cfg, claims, stored.nonce) {
		s.ssoFail(w, r, "claim check failed")
		return
	}
	// Authorization comes from the account file, never from
	// claims: the username must match an existing, enabled
	// account. Unknown SSO users are denied with the same
	// generic page as every other failure.
	username := ssoUsernameFromClaims(claims)
	account := s.accounts.Get(username)
	if username == "" || account == nil || account.Disabled {
		s.ssoFail(w, r, "no matching account")
		return
	}
	s.sessions.setCookie(w, s.sessions.create(account.Username, true))
	s.audit.Write(AuditEntry{User: account.Username, Role: account.Role, Auth: "sso", Action: "LOGIN", IP: peerIP(r), Success: true})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// ssoUsernameFromClaims resolves the control-plane username
// from ID token claims: email, then preferred_username, then
// sub. Email is lowercased (account usernames are lowercase).
// A value that cannot be a username matches no account and is
// denied at lookup.
func ssoUsernameFromClaims(claims map[string]interface{}) string {
	if email, _ := claims["email"].(string); email != "" {
		return strings.ToLower(strings.TrimSpace(email))
	}
	if name, _ := claims["preferred_username"].(string); name != "" {
		return strings.TrimSpace(name)
	}
	sub, _ := claims["sub"].(string)
	return strings.TrimSpace(sub)
}

// exchangeCode trades an authorization code for tokens and
// returns the ID token. Tokens are never logged.
func exchangeCode(provider *cpOIDCProvider, cfg *domains.SSOConfig, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURL},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequest(http.MethodPost, provider.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	resp, err := cpSSOHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cpSSOMaxBody))
	if err != nil {
		return "", err
	}
	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.IDToken == "" {
		return "", fmt.Errorf("token response has no id_token")
	}
	return tokenResp.IDToken, nil
}

// ssoClaimsOK checks iss, aud, sub, and nonce on verified
// claims. Signature and expiry were already checked by the
// verifier.
func ssoClaimsOK(cfg *domains.SSOConfig, claims map[string]interface{}, nonce string) bool {
	if iss, _ := claims["iss"].(string); iss != cfg.Issuer {
		return false
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return false
	}
	if n, _ := claims["nonce"].(string); n != nonce {
		return false
	}
	switch aud := claims["aud"].(type) {
	case string:
		return aud == cfg.ClientID
	case []interface{}:
		for _, item := range aud {
			if s, ok := item.(string); ok && s == cfg.ClientID {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleSSOLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}
