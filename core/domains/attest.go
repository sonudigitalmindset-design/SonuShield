package domains

// Mobile app attestation (Batch 8).
//
// API paths used by a mobile app can require an app-integrity
// token: a JWT issued by the platform's attestation service
// (Google Play Integrity or an Apple App Attest style issuer
// that returns JWTs) and presented in a request header. The
// proxy verifies the token's signature, expiry, issuer, and
// audience, and optionally a verdict claim inside the payload,
// before the request reaches the backend.
//
// Verification reuses the JWT machinery from jwt.go: HS256 with
// an operator-supplied shared secret, or RS256/ES256 with keys
// from an operator-supplied JWKS URL. "alg": "none" and every
// other algorithm are rejected, exactly as for API JWTs. The
// token itself is never logged.
//
// Configuration is per domain (domain.attestation) and
// config-file-only: the secret and the JWKS URL are never
// accepted via the API and never returned by any action. With
// nothing configured the feature is inert. When attestation is
// enabled for paths but no verification material is configured,
// those paths reject every request (fail closed) with a startup
// warning, mirroring the JWT protected-paths behavior.
//
// Real-device attestation is unverifiable in this environment:
// the verification path is exercised against locally signed
// tokens and a mock JWKS endpoint. What the proxy checks —
// signature, exp, iss, aud, and the configured verdict claim —
// is exactly what the operator configures; the meaning of a
// verdict value is the issuer's, and operators must confirm the
// claim shape against their own provider's documentation.
// Apple App Attest's CBOR attestation objects are NOT parsed:
// only JWT-form assertions are supported.

import (
	"fmt"
	"strings"
)

// AttestationConfig is the per-domain attestation configuration
// (domain.attestation). Paths lists the path prefixes that
// require a token; Header names the request header carrying it
// (default "X-Attestation-Token"); Mode is "block" (default,
// reject unverified requests with a generic 403) or "log" (log
// failures and let the request through). VerdictClaim is a
// dot-separated claim path inside the token payload (for
// example "deviceIntegrity.deviceRecognitionVerdict"); when set
// with VerdictValues, the claim's value (a string, or any
// element of a string list) must be one of the values.
type AttestationConfig struct {
	Enabled       bool     `json:"enabled"`
	JWKSURL       string   `json:"jwksUrl"`
	Secret        string   `json:"secret"`
	Issuer        string   `json:"issuer"`
	Audience      string   `json:"audience"`
	Header        string   `json:"header"`
	Paths         []string `json:"paths"`
	Mode          string   `json:"mode"`
	VerdictClaim  string   `json:"verdictClaim"`
	VerdictValues []string `json:"verdictValues"`
}

// AttestationVerifier validates attestation tokens for one
// domain. A nil verifier means the feature is disabled.
type AttestationVerifier struct {
	jwt           *JWTVerifier
	issuer        string
	audience      string
	header        string
	paths         []string
	logOnly       bool
	verdictClaim  string
	verdictValues []string
}

// NewAttestationVerifier builds a verifier from the domain
// config, or returns nil when attestation is disabled. When
// enabled with paths but no verification material, it returns a
// verifier that rejects everything (fail closed) and logs a
// warning at startup.
func NewAttestationVerifier(domainName string, cfg AttestationConfig) *AttestationVerifier {
	if !cfg.Enabled || len(cfg.Paths) == 0 {
		return nil
	}
	header := cfg.Header
	if header == "" {
		header = "X-Attestation-Token"
	}
	v := &AttestationVerifier{
		issuer:        cfg.Issuer,
		audience:      cfg.Audience,
		header:        header,
		paths:         cfg.Paths,
		logOnly:       strings.ToLower(strings.TrimSpace(cfg.Mode)) == "log",
		verdictClaim:  cfg.VerdictClaim,
		verdictValues: cfg.VerdictValues,
	}
	if cfg.Secret == "" && cfg.JWKSURL == "" {
		fmt.Println("[ ! ] [ attestation enabled for " + domainName + " but no secret/jwksUrl configured; attested paths will reject all requests ]")
		return v
	}
	v.jwt = NewJWTVerifier(domainName, cfg.Secret, cfg.JWKSURL)
	return v
}

// Required reports whether path needs an attestation token.
func (v *AttestationVerifier) Required(path string) bool {
	if v == nil {
		return false
	}
	for _, prefix := range v.paths {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// HeaderName reports the request header carrying the token.
func (v *AttestationVerifier) HeaderName() string {
	if v == nil {
		return ""
	}
	return v.header
}

// LogOnly reports whether failures are logged without blocking.
func (v *AttestationVerifier) LogOnly() bool {
	return v != nil && v.logOnly
}

// Verify checks a token: signature and expiry via the JWT
// verifier, then issuer, audience, and the verdict claim when
// configured. It returns false for every malformed, expired,
// badly signed, or mismatched token, and never logs the token.
func (v *AttestationVerifier) Verify(token string) bool {
	if v == nil || v.jwt == nil || token == "" {
		return false
	}
	claims, ok := v.jwt.VerifyClaims(token)
	if !ok {
		return false
	}
	if v.issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != v.issuer {
			return false
		}
	}
	if v.audience != "" && !audienceMatches(claims["aud"], v.audience) {
		return false
	}
	if v.verdictClaim != "" && len(v.verdictValues) > 0 {
		if !verdictMatches(claims, v.verdictClaim, v.verdictValues) {
			return false
		}
	}
	return true
}

// audienceMatches reports whether an "aud" claim (a string or a
// list of strings) contains the expected audience.
func audienceMatches(claim interface{}, expected string) bool {
	switch value := claim.(type) {
	case string:
		return value == expected
	case []interface{}:
		for _, item := range value {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// verdictMatches walks a dot-separated claim path through the
// payload and reports whether the value found (a string, or any
// element of a string list) is one of the allowed values.
func verdictMatches(claims map[string]interface{}, path string, allowed []string) bool {
	var current interface{} = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		current, ok = m[part]
		if !ok {
			return false
		}
	}
	switch value := current.(type) {
	case string:
		for _, allowedValue := range allowed {
			if value == allowedValue {
				return true
			}
		}
	case []interface{}:
		for _, item := range value {
			if s, ok := item.(string); ok {
				for _, allowedValue := range allowed {
					if s == allowedValue {
						return true
					}
				}
			}
		}
	}
	return false
}
