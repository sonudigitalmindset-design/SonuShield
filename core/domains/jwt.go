package domains

// JWT validation for protected API routes (Batch 4).
//
// Hand-rolled with the standard library only; go.mod has no JWT
// dependency and adding one for this would be disproportionate.
// Supported: HS256 with an operator-supplied shared secret, and
// RS256 / ES256 with keys from an operator-supplied JWKS URL.
//
// Rules, enforced for every token:
//   - The token must have three base64url parts and a JSON header
//     and payload.
//   - "exp" is required and must be in the future. "nbf", when
//     present, must not be in the future. Timestamps are seconds
//     since the epoch; fractional values are rejected.
//   - HS256 is used only when a secret is configured; RS256 and
//     ES256 only when a JWKS URL is configured. "alg": "none"
//     and every other algorithm are rejected, and an algorithm
//     confusion between the two modes is impossible because each
//     mode accepts only its own algorithms.
//   - With JWKS, the "kid" header selects the key when present;
//     when the token carries no kid and the set holds exactly one
//     key, that key is used. Unknown kids fail closed.
//
// JWKS keys are fetched when the verifier is built and refreshed
// at most hourly. A failed refresh keeps the previous keys; a
// failed initial fetch leaves the verifier with no keys, so
// protected routes fail closed with a startup log line. Tokens
// are never logged.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const jwksRefreshInterval = time.Hour

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

// JWTVerifier validates tokens for one domain's protected routes.
type JWTVerifier struct {
	secret  []byte
	jwksURL string

	mu         sync.Mutex
	keys       []jwk
	lastFetch  time.Time
	fetchTried bool
}

// NewJWTVerifier builds a verifier, or returns nil when neither a
// secret nor a JWKS URL is configured. When a JWKS URL is set, the
// key set is fetched immediately; a failure is logged and the
// verifier starts empty (fail closed), retrying on first use.
func NewJWTVerifier(domainName, secret, jwksURL string) *JWTVerifier {
	if secret == "" && jwksURL == "" {
		return nil
	}
	v := &JWTVerifier{jwksURL: jwksURL}
	if secret != "" {
		v.secret = []byte(secret)
	}
	if jwksURL != "" {
		if err := v.refreshLocked(); err != nil {
			fmt.Println("[ ! ] [ JWT JWKS fetch failed for " + domainName + " (" + jwksURL + "): " + err.Error() + "; protected routes fail closed until keys load ]")
		}
	}
	return v
}

var jwksClient = &http.Client{Timeout: 5 * time.Second}

// refreshLocked fetches the JWKS document and replaces the key
// set. The caller must hold v.mu. On any failure the previous
// keys are kept and the error is returned.
func (v *JWTVerifier) refreshLocked() error {
	req, err := http.NewRequest(http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := jwksClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	v.keys = doc.Keys
	v.lastFetch = time.Now()
	v.fetchTried = true
	return nil
}

// maybeRefresh reloads the JWKS document when the cached set is
// older than the refresh interval. Failures are silent here: the
// previous keys stay in use.
func (v *JWTVerifier) maybeRefresh() {
	if v.jwksURL == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fetchTried && time.Since(v.lastFetch) < jwksRefreshInterval {
		return
	}
	_ = v.refreshLocked()
}

func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Verify checks a token. It returns false for every malformed,
// expired, or badly signed token, and never logs the token.
func (v *JWTVerifier) Verify(token string) bool {
	if v == nil {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	headerJSON, err := b64decode(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false
	}
	payloadJSON, err := b64decode(parts[1])
	if err != nil {
		return false
	}
	var payload struct {
		Exp json.Number `json:"exp"`
		Nbf json.Number `json:"nbf"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadJSON)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return false
	}
	// exp is required; nbf is honored when present.
	exp, err := payload.Exp.Int64()
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if exp <= now {
		return false
	}
	if payload.Nbf.String() != "" {
		nbf, err := payload.Nbf.Int64()
		if err != nil || nbf > now {
			return false
		}
	}
	signingInput := parts[0] + "." + parts[1]
	signature, err := b64decode(parts[2])
	if err != nil {
		return false
	}

	switch header.Alg {
	case "HS256":
		if len(v.secret) == 0 {
			return false
		}
		mac := hmac.New(sha256.New, v.secret)
		mac.Write([]byte(signingInput))
		return hmac.Equal(mac.Sum(nil), signature)
	case "RS256", "ES256":
		if v.jwksURL == "" {
			return false
		}
		v.maybeRefresh()
		v.mu.Lock()
		keys := v.keys
		v.mu.Unlock()
		key := selectJWK(keys, header.Kid)
		if key == nil {
			return false
		}
		return verifyWithJWK(key, header.Alg, signingInput, signature)
	default:
		return false
	}
}

// VerifyClaims verifies a token like Verify and, on success,
// returns the decoded payload claims. Claims are only returned
// for a verified token, so callers (OIDC) can trust iss, aud,
// and nonce checks run against them.
func (v *JWTVerifier) VerifyClaims(token string) (map[string]interface{}, bool) {
	if !v.Verify(token) {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payloadJSON, err := b64decode(parts[1])
	if err != nil {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadJSON)))
	decoder.UseNumber()
	var claims map[string]interface{}
	if err := decoder.Decode(&claims); err != nil {
		return nil, false
	}
	return claims, true
}

func selectJWK(keys []jwk, kid string) *jwk {
	if kid != "" {
		for i := range keys {
			if keys[i].Kid == kid {
				return &keys[i]
			}
		}
		return nil
	}
	if len(keys) == 1 {
		return &keys[0]
	}
	return nil
}

func verifyWithJWK(key *jwk, alg, signingInput string, signature []byte) bool {
	digest := sha256.Sum256([]byte(signingInput))
	switch alg {
	case "RS256":
		if key.Kty != "RSA" {
			return false
		}
		nBytes, err := b64decode(key.N)
		if err != nil {
			return false
		}
		eBytes, err := b64decode(key.E)
		if err != nil {
			return false
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes)}
		pub.E = 0
		for _, b := range eBytes {
			pub.E = pub.E<<8 | int(b)
		}
		if pub.E == 0 {
			return false
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) == nil
	case "ES256":
		if key.Kty != "EC" || key.Crv != "P-256" {
			return false
		}
		xBytes, err := b64decode(key.X)
		if err != nil {
			return false
		}
		yBytes, err := b64decode(key.Y)
		if err != nil {
			return false
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		if len(signature) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(pub, digest[:], r, s)
	default:
		return false
	}
}
