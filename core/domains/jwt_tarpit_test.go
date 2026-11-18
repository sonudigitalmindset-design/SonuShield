package domains

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// hsToken builds an HS256 JWT with the given header/payload, signed
// with secret. Tests use it to exercise the verifier without any
// network (JWKS mode is not covered here: it needs an HTTP fetch).
func hsToken(t *testing.T, secret string, header, payload map[string]interface{}) string {
	t.Helper()
	b64 := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := b64(header) + "." + b64(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hsHeader() map[string]interface{} { return map[string]interface{}{"alg": "HS256", "typ": "JWT"} }

func TestJWTVerifyHS256(t *testing.T) {
	v := NewJWTVerifier("example.com", "test-secret-do-not-use", "")
	if v == nil {
		t.Fatal("HS256 verifier is nil")
	}
	now := time.Now().Unix()
	good := hsToken(t, "test-secret-do-not-use", hsHeader(), map[string]interface{}{
		"sub": "user-1", "exp": now + 3600,
	})
	if !v.Verify(good) {
		t.Fatal("valid HS256 token rejected")
	}
	claims, ok := v.VerifyClaims(good)
	if !ok || claims["sub"] != "user-1" {
		t.Fatalf("VerifyClaims = (%v, %v), want sub=user-1", claims, ok)
	}
}

func TestJWTVerifyRejects(t *testing.T) {
	v := NewJWTVerifier("example.com", "test-secret-do-not-use", "")
	now := time.Now().Unix()
	cases := map[string]string{
		"wrong secret": hsToken(t, "other-secret", hsHeader(), map[string]interface{}{"exp": now + 3600}),
		"expired":      hsToken(t, "test-secret-do-not-use", hsHeader(), map[string]interface{}{"exp": now - 10}),
		"missing exp":  hsToken(t, "test-secret-do-not-use", hsHeader(), map[string]interface{}{"sub": "x"}),
		"nbf future":   hsToken(t, "test-secret-do-not-use", hsHeader(), map[string]interface{}{"exp": now + 3600, "nbf": now + 3600}),
		"alg none":     hsToken(t, "test-secret-do-not-use", map[string]interface{}{"alg": "none"}, map[string]interface{}{"exp": now + 3600}),
		"alg RS256":    hsToken(t, "test-secret-do-not-use", map[string]interface{}{"alg": "RS256"}, map[string]interface{}{"exp": now + 3600}),
		"two parts":    "aaa.bbb",
		"bad b64":      "!!!.@@@.###",
		"empty":        "",
	}
	for name, tok := range cases {
		if v.Verify(tok) {
			t.Fatalf("%s: token accepted, want rejection", name)
		}
	}
	// Tampered payload (re-signed header, original signature).
	good := hsToken(t, "test-secret-do-not-use", hsHeader(), map[string]interface{}{"exp": now + 3600, "sub": "a"})
	parts := strings.Split(good, ".")
	other := hsToken(t, "test-secret-do-not-use", hsHeader(), map[string]interface{}{"exp": now + 3600, "sub": "b"})
	tampered := parts[0] + "." + strings.Split(other, ".")[1] + "." + parts[2]
	if v.Verify(tampered) {
		t.Fatal("tampered payload accepted")
	}
}

func TestJWTVerifierNil(t *testing.T) {
	if v := NewJWTVerifier("example.com", "", ""); v != nil {
		t.Fatal("verifier without secret or JWKS URL should be nil")
	}
	var v *JWTVerifier
	if v.Verify("a.b.c") {
		t.Fatal("nil verifier accepted a token")
	}
}

func TestTarpitLimiter(t *testing.T) {
	if NewTarpitLimiter(0, 5, 0) != nil {
		t.Fatal("zero delay should disable the tarpit")
	}
	if NewTarpitLimiter(100, 0, 0) != nil {
		t.Fatal("zero threshold should disable the tarpit")
	}
	// Nil limiter: Apply is a no-op.
	var nilLimiter *TarpitLimiter
	nilLimiter.Apply(99)

	l := NewTarpitLimiter(1, 5, 2)
	if l == nil {
		t.Fatal("configured tarpit limiter is nil")
	}
	// Below threshold: returns immediately.
	start := time.Now()
	l.Apply(4)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("below-threshold Apply slept")
	}
	// At threshold: sleeps roughly the configured delay.
	start = time.Now()
	l.Apply(5)
	if elapsed := time.Since(start); elapsed < time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("at-threshold Apply took %v, want ~1ms", elapsed)
	}
	// Delay is capped at 30s (constructor clamps; verify the field).
	capped := NewTarpitLimiter(60000, 5, 0)
	if capped.delay != 30*time.Second {
		t.Fatalf("delay cap = %v, want 30s", capped.delay)
	}
}
