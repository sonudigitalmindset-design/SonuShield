package controlplane

// Control-plane sessions.
//
// Sessions are HMAC-signed cookies carrying only a username,
// an expiry, and whether the login came from SSO. Roles,
// tenants, and disabled state always come from the live
// account store, so deleting, disabling, or re-scoping an
// account takes effect immediately without waiting for
// sessions to expire. The signing key derives from the
// configured session secret with domain separation; with no
// secret configured an ephemeral key is generated at startup
// (sessions do not survive a restart) and the server warns.
//
// Cookies are HttpOnly + SameSite=Lax, scoped to /, and
// Secure whenever the control plane serves TLS. Every API
// call made with a session cookie must also carry the CSRF
// header (X-SonuShield-CSRF: 1, the same header the proxy SSO
// flow uses): a bare cookie never authenticates a request, so
// a cross-site form post cannot drive the API.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"sonushield/core/proxy"
)

const (
	sessionCookieName = "__sonushield_cp"
	csrfHeader        = proxy.SSOCSRFHeader
)

// sessionPayload is the signed cookie payload: a username and
// an expiry only. Authorization state lives in the store.
type sessionPayload struct {
	Username string `json:"u"`
	SSO      bool   `json:"sso,omitempty"`
	Exp      int64  `json:"exp"`
}

// sessionManager signs and validates session cookies.
type sessionManager struct {
	key       []byte
	ttl       time.Duration
	secure    bool
	ephemeral bool
}

// newSessionManager builds the signer from the configured
// secret. An empty secret generates an ephemeral key and
// reports ephemeral=true so the server can warn.
func newSessionManager(secret string, ttlHours int, secure bool) *sessionManager {
	if secret == "" {
		var raw [32]byte
		rand.Read(raw[:])
		sum := sha256.Sum256(append([]byte("sonushield-cp-ephemeral-v1:"), raw[:]...))
		return &sessionManager{key: sum[:], ttl: time.Duration(ttlHours) * time.Hour, secure: secure, ephemeral: true}
	}
	sum := sha256.Sum256([]byte("sonushield-cp-v1:" + secret))
	return &sessionManager{key: sum[:], ttl: time.Duration(ttlHours) * time.Hour, secure: secure}
}

// create builds a signed session cookie value for a username.
func (m *sessionManager) create(username string, sso bool) string {
	payload, _ := json.Marshal(sessionPayload{Username: username, SSO: sso, Exp: time.Now().Add(m.ttl).Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig
}

// validate checks a cookie value and returns the payload. The
// caller must still resolve the username against the account
// store (existence, disabled state, current role).
func (m *sessionManager) validate(value string) (sessionPayload, bool) {
	var payload sessionPayload
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return payload, false
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return payload, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return payload, false
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, false
	}
	if payload.Username == "" || payload.Exp <= time.Now().Unix() {
		return payload, false
	}
	return payload, true
}

// setCookie writes the session cookie onto a response.
func (m *sessionManager) setCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttl.Seconds()),
	})
}

// clearCookie expires the session cookie.
func (m *sessionManager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// requireCSRF reports whether the request carries the CSRF
// header session-cookie API calls must send.
func requireCSRF(r *http.Request) bool {
	return r.Header.Get(csrfHeader) == "1"
}

// callerIdentity derives the value the control plane sends as
// the node's caller identity for two-person approval: a hash
// of the username, never the username itself.
func callerIdentity(username string) string {
	sum := sha256.Sum256([]byte("sonushield-cp-user:" + username))
	return hex.EncodeToString(sum[:])
}
