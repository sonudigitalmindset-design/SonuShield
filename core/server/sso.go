package server

// SSO/OIDC login for the dashboard (Batch 5).
//
// Optional, coexisting with the existing secret-path auth: when
// proxy.sso is configured, operators may sign in through their
// identity provider instead of presenting the API secret. The
// secret-path auth keeps working alone, and SSO adds no new
// paths on protected domains outside the existing /_bProxy/
// prefix:
//
//   - GET /_bProxy/sso/login — starts the authorization-code flow
//     (PKCE S256, state, nonce).
//   - GET /_bProxy/sso/callback — exchanges the code, verifies
//     the ID token (signature via the provider JWKS, iss, aud,
//     exp, nonce), and sets the session cookie.
//   - GET /_bProxy/sso/logout — clears the session cookie.
//   - GET /_bProxy/sso/status — {"enabled": bool}, so the
//     dashboard can offer SSO only when it is configured.
//
// These paths serve the on-domain dashboard. They are
// superseded by the control plane's own SSO endpoints once the
// dashboard moves to the control host; see
// docs/control-plane.md.
//
// Sessions are HMAC-signed cookies (key derived from the
// configured cookie secret with domain separation; no new secret
// to configure), HttpOnly + Secure + SameSite=Lax, scoped to
// /_bProxy/, valid for 8 hours. The API accepts a valid session
// cookie as an alternative to the X-SonuShield-Secret header, but only
// when the request also carries the CSRF header the dashboard
// sends (see api.SSOSessionValidator and proxy.SSOCSRFHeader):
// a bare cookie must never authenticate a cross-site request.
// Sessions carry a role only (viewer/operator/admin, from
// defaultRole or the roleClaim mapping); they are never
// tenant-scoped.
//
// Security properties, all enforced here:
//   - Discovery is fetched without following redirects, and the
//     document's issuer must exactly equal the configured
//     issuer; endpoints must be https (http only for loopback
//     hosts, for local testing).
//   - ID tokens must be RS256/ES256 signed by a JWKS key
//     (HS256 and "alg: none" are rejected by the shared JWT
//     verifier); iss, aud, exp, and nonce are all checked.
//   - Authorization state is single-use, 10-minute TTL,
//     server-side, and bound to a short-lived cookie.
//   - Tokens, codes, and secrets are never logged; failures log
//     only a failure class.

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
	"sonushield/core/api"
	"sonushield/core/domains"
	"sonushield/core/proxy"
	"strings"
	"sync"
	"time"
)

const (
	ssoSessionCookie = "__bProxy_sso"
	ssoStateCookie   = "__bProxy_sso_state"
	ssoSessionTTL    = 8 * time.Hour
	ssoStateTTL      = 10 * time.Minute
	ssoStateCap      = 4096
	ssoHTTPTimeout   = 10 * time.Second
	ssoMaxBodyBytes  = 1 << 20
)

func init() {
	api.SSOSessionValidator = ssoSessionRole
	// Two-person approval (Batch 7): the API hashes the
	// session cookie value to tell SSO callers apart. The
	// value itself never leaves this function.
	api.SSOSessionCookieValue = func(r *http.Request) string {
		cookie, err := r.Cookie(ssoSessionCookie)
		if err != nil {
			return ""
		}
		return cookie.Value
	}
}

// ssoHTTP is the client for discovery and token requests. It
// never follows redirects: a redirect could point the code
// exchange (and the client secret) at an attacker's endpoint.
var ssoHTTP = &http.Client{
	Timeout: ssoHTTPTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// ssoConfig returns the live SSO config when SSO is enabled and
// valid, reading the current config on every call so a reload
// takes effect without a restart.
func ssoConfig() (*domains.SSOConfig, bool) {
	if domains.Config == nil || domains.Config.Proxy.SSO == nil {
		return nil, false
	}
	cfg := domains.Config.Proxy.SSO
	if cfg.Validate() != "" {
		return nil, false
	}
	return cfg, true
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

// oidcProvider is a discovered identity provider with its
// cached JWKS verifier.
type oidcProvider struct {
	issuer   string
	authURL  string
	tokenURL string
	jwksURL  string
	verifier *domains.JWTVerifier
	fetched  time.Time
}

var (
	ssoProviderMu sync.Mutex
	ssoProvider   *oidcProvider
)

// getOIDCProvider returns the cached provider for the configured
// issuer, discovering it when absent, stale (1 hour), or for a
// different issuer.
func getOIDCProvider(cfg *domains.SSOConfig) (*oidcProvider, error) {
	ssoProviderMu.Lock()
	defer ssoProviderMu.Unlock()
	if ssoProvider != nil && ssoProvider.issuer == cfg.Issuer && time.Since(ssoProvider.fetched) < time.Hour {
		return ssoProvider, nil
	}
	discoveryURL := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	resp, err := ssoHTTP.Get(discoveryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ssoMaxBodyBytes))
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
	provider := &oidcProvider{
		issuer:   doc.Issuer,
		authURL:  doc.AuthURL,
		tokenURL: doc.TokenURL,
		jwksURL:  doc.JWKSURL,
		verifier: domains.NewJWTVerifier("sso", "", doc.JWKSURL),
		fetched:  time.Now(),
	}
	ssoProvider = provider
	return provider, nil
}

// ssoAuthState is one in-flight login attempt, held server-side
// and bound to the browser by the state cookie.
type ssoAuthState struct {
	state    string
	nonce    string
	verifier string
	created  time.Time
}

var (
	ssoStateMu sync.Mutex
	ssoStates  = map[string]*ssoAuthState{}
)

// storeSSOState records a login attempt. It reports false when
// the store is full even after purging expired entries; the
// login then fails closed.
func storeSSOState(id string, st *ssoAuthState) bool {
	ssoStateMu.Lock()
	defer ssoStateMu.Unlock()
	if len(ssoStates) >= ssoStateCap {
		now := time.Now()
		for key, old := range ssoStates {
			if now.Sub(old.created) > ssoStateTTL {
				delete(ssoStates, key)
			}
		}
		if len(ssoStates) >= ssoStateCap {
			return false
		}
	}
	ssoStates[id] = st
	return true
}

// takeSSOState consumes a login attempt exactly once. Expired or
// unknown attempts fail.
func takeSSOState(id string) (*ssoAuthState, bool) {
	ssoStateMu.Lock()
	defer ssoStateMu.Unlock()
	st, ok := ssoStates[id]
	delete(ssoStates, id)
	if !ok || time.Since(st.created) > ssoStateTTL {
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

// ssoSession is the signed-cookie session payload.
type ssoSession struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

// ssoSessionKey derives the session-signing key from the
// configured cookie secret with domain separation, so SSO needs
// no additional secret.
func ssoSessionKey() []byte {
	sum := sha256.Sum256([]byte("sonushield-sso-v1:" + proxy.CookieSecret))
	return sum[:]
}

// createSSOSession builds a signed session cookie value.
func createSSOSession(sub, role string, now time.Time) string {
	payload, _ := json.Marshal(ssoSession{Sub: sub, Role: role, Exp: now.Add(ssoSessionTTL).Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, ssoSessionKey())
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig
}

// ValidateSSOSession checks the request's session cookie and
// returns the session. It never logs the cookie value.
func ValidateSSOSession(r *http.Request) (ssoSession, bool) {
	var session ssoSession
	cookie, err := r.Cookie(ssoSessionCookie)
	if err != nil || cookie.Value == "" {
		return session, false
	}
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return session, false
	}
	mac := hmac.New(sha256.New, ssoSessionKey())
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return session, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return session, false
	}
	if err := json.Unmarshal(payload, &session); err != nil {
		return session, false
	}
	if session.Sub == "" || session.Exp <= time.Now().Unix() {
		return session, false
	}
	switch session.Role {
	case proxy.RoleViewer, proxy.RoleOperator, proxy.RoleAdmin:
	default:
		return session, false
	}
	return session, true
}

// ssoSessionRole adapts session validation to the API hook: it
// reports the session's role for cookie-authenticated API calls.
func ssoSessionRole(r *http.Request) (string, bool) {
	session, ok := ValidateSSOSession(r)
	if !ok {
		return "", false
	}
	return session.Role, true
}

// ssoRoleForClaims resolves the session role from the ID token
// claims: the roleClaim mapping wins, defaultRole otherwise.
func ssoRoleForClaims(cfg *domains.SSOConfig, claims map[string]interface{}) string {
	defaultRole := cfg.DefaultRole
	if defaultRole == "" {
		defaultRole = proxy.RoleViewer
	}
	if cfg.RoleClaim == "" || len(cfg.RoleMapping) == 0 {
		return defaultRole
	}
	raw, ok := claims[cfg.RoleClaim]
	if !ok {
		return defaultRole
	}
	var values []string
	switch v := raw.(type) {
	case string:
		values = []string{v}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
	}
	for _, value := range values {
		if role, ok := cfg.RoleMapping[value]; ok {
			return role
		}
	}
	return defaultRole
}

// ssoDashboardURL is where a successful login lands: the
// existing secret-path dashboard. The path secret is inherent to
// the on-domain dashboard design; SSO only removes the need to
// present the API secret for API calls. The control plane has
// its own login and dashboard URL.
func ssoDashboardURL() string {
	return "/_bProxy/" + proxy.AdminSecret + "/dashboard"
}

// ssoFail writes a generic sign-in failure page. Details stay in
// the server log (failure class only); the page reveals nothing.
func ssoFail(writer http.ResponseWriter, logClass string) {
	fmt.Println("[ ! ] [ sso: " + logClass + " ]")
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(writer, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign-in failed</title><style>body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f8fafc;color:#020617;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fff;border:1px solid #e2e8f0;border-radius:4px;padding:32px;max-width:420px;text-align:center}h1{font-size:20px;margin:0 0 8px}p{margin:8px 0;color:#475569}a{color:#0369a1}</style></head><body><div class="box"><h1>Sign-in failed</h1><p>Something went wrong during sign-in. Please try again.</p><p><a href="/_bProxy/sso/login">Try again</a></p></div></body></html>`)
}

// HandleSSO routes SSO requests. It reports whether the request
// was handled; unhandled requests fall through exactly as
// before. The status endpoint always answers; login, callback,
// and logout only when SSO is configured.
func HandleSSO(writer http.ResponseWriter, request *http.Request) bool {
	switch request.URL.Path {
	case "/_bProxy/sso/status":
		_, enabled := ssoConfig()
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(writer, `{"enabled":%v}`, enabled)
		return true
	case "/_bProxy/sso/login", "/_bProxy/sso/callback", "/_bProxy/sso/logout":
		cfg, ok := ssoConfig()
		if !ok {
			return false
		}
		switch request.URL.Path {
		case "/_bProxy/sso/login":
			handleSSOLogin(writer, request, cfg)
		case "/_bProxy/sso/callback":
			handleSSOCallback(writer, request, cfg)
		case "/_bProxy/sso/logout":
			handleSSOLogout(writer, request)
		}
		return true
	default:
		return false
	}
}

func handleSSOLogin(writer http.ResponseWriter, request *http.Request, cfg *domains.SSOConfig) {
	// Already signed in: go straight to the dashboard.
	if _, ok := ValidateSSOSession(request); ok {
		http.Redirect(writer, request, ssoDashboardURL(), http.StatusFound)
		return
	}
	provider, err := getOIDCProvider(cfg)
	if err != nil {
		ssoFail(writer, "discovery failed")
		return
	}
	state, err1 := ssoRandom()
	nonce, err2 := ssoRandom()
	verifier, err3 := ssoRandom()
	id, err4 := ssoRandom()
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		ssoFail(writer, "randomness failed")
		return
	}
	if !storeSSOState(id, &ssoAuthState{state: state, nonce: nonce, verifier: verifier, created: time.Now()}) {
		ssoFail(writer, "state store full")
		return
	}
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	http.SetCookie(writer, &http.Cookie{
		Name:     ssoStateCookie,
		Value:    id,
		Path:     "/_bProxy/sso/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ssoStateTTL.Seconds()),
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
	http.Redirect(writer, request, provider.authURL+"?"+params.Encode(), http.StatusFound)
}

func handleSSOCallback(writer http.ResponseWriter, request *http.Request, cfg *domains.SSOConfig) {
	query := request.URL.Query()
	if query.Get("error") != "" {
		ssoFail(writer, "provider returned an error")
		return
	}
	cookie, err := request.Cookie(ssoStateCookie)
	if err != nil || cookie.Value == "" {
		ssoFail(writer, "state cookie missing")
		return
	}
	stored, ok := takeSSOState(cookie.Value)
	if !ok {
		ssoFail(writer, "state missing or expired")
		return
	}
	// The state cookie is single-use: clear it now.
	http.SetCookie(writer, &http.Cookie{
		Name:     ssoStateCookie,
		Value:    "",
		Path:     "/_bProxy/sso/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	if !hmac.Equal([]byte(query.Get("state")), []byte(stored.state)) {
		ssoFail(writer, "state mismatch")
		return
	}
	code := query.Get("code")
	if code == "" {
		ssoFail(writer, "code missing")
		return
	}
	provider, err := getOIDCProvider(cfg)
	if err != nil {
		ssoFail(writer, "discovery failed")
		return
	}
	idToken, err := exchangeCode(provider, cfg, code, stored.verifier)
	if err != nil {
		ssoFail(writer, "code exchange failed")
		return
	}
	claims, ok := provider.verifier.VerifyClaims(idToken)
	if !ok {
		ssoFail(writer, "id token invalid")
		return
	}
	if !ssoClaimsOK(cfg, claims, stored.nonce) {
		ssoFail(writer, "claim check failed")
		return
	}
	sub, _ := claims["sub"].(string)
	role := ssoRoleForClaims(cfg, claims)
	http.SetCookie(writer, &http.Cookie{
		Name:     ssoSessionCookie,
		Value:    createSSOSession(sub, role, time.Now()),
		Path:     "/_bProxy/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ssoSessionTTL.Seconds()),
	})
	http.Redirect(writer, request, ssoDashboardURL(), http.StatusFound)
}

// exchangeCode trades an authorization code for tokens and
// returns the ID token. Tokens are never logged.
func exchangeCode(provider *oidcProvider, cfg *domains.SSOConfig, code, verifier string) (string, error) {
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
	resp, err := ssoHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ssoMaxBodyBytes))
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

func handleSSOLogout(writer http.ResponseWriter, request *http.Request) {
	http.SetCookie(writer, &http.Cookie{
		Name:     ssoSessionCookie,
		Value:    "",
		Path:     "/_bProxy/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(writer, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Signed out</title><style>body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f8fafc;color:#020617;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fff;border:1px solid #e2e8f0;border-radius:4px;padding:32px;max-width:420px;text-align:center}h1{font-size:20px;margin:0 0 8px}p{margin:8px 0;color:#475569}a{color:#0369a1}</style></head><body><div class="box"><h1>Signed out</h1><p>You have been signed out of the dashboard.</p><p><a href="/_bProxy/sso/login">Sign in again</a></p></div></body></html>`)
}
