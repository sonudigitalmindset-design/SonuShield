package firewall

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func signedRequest(t *testing.T, signed string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://example.com"+signed, nil)
	return req
}

func TestSignedURLRoundTrip(t *testing.T) {
	secret := "test-secret-do-not-use"
	signed := SignURL(secret, "/files/report.pdf", time.Now().Add(time.Hour).Unix(), nil)
	if !VerifySignedURL(secret, signedRequest(t, signed)) {
		t.Fatalf("freshly signed URL failed verification: %s", signed)
	}
	// Extra query parameters survive signing and verification.
	signed = SignURL(secret, "/files/report.pdf", time.Now().Add(time.Hour).Unix(), url.Values{"dl": {"1"}})
	req := signedRequest(t, signed)
	if req.URL.Query().Get("dl") != "1" {
		t.Fatal("extra query parameter lost in signing")
	}
	if !VerifySignedURL(secret, req) {
		t.Fatal("signed URL with extra parameters failed verification")
	}
}

func TestSignedURLRejects(t *testing.T) {
	secret := "test-secret-do-not-use"
	good := SignURL(secret, "/files/a.pdf", time.Now().Add(time.Hour).Unix(), nil)

	// Wrong secret.
	if VerifySignedURL("other-secret", signedRequest(t, good)) {
		t.Fatal("wrong secret verified")
	}
	// Empty secret never verifies.
	if VerifySignedURL("", signedRequest(t, good)) {
		t.Fatal("empty secret verified")
	}
	// Expired.
	expired := SignURL(secret, "/files/a.pdf", time.Now().Add(-time.Hour).Unix(), nil)
	if VerifySignedURL(secret, signedRequest(t, expired)) {
		t.Fatal("expired URL verified")
	}
	// Tampered path: the signature covers the path.
	tampered := strings.Replace(good, "/files/a.pdf", "/files/b.pdf", 1)
	if VerifySignedURL(secret, signedRequest(t, tampered)) {
		t.Fatal("tampered path verified")
	}
	// Tampered signature: flip the last hex digit.
	q := signedRequest(t, good).URL.Query()
	sig := q.Get("sig")
	last := sig[63]
	if last == '0' {
		last = '1'
	} else {
		last = '0'
	}
	bad := "/files/a.pdf?exp=" + q.Get("exp") + "&sig=" + sig[:63] + string(last)
	if VerifySignedURL(secret, signedRequest(t, bad)) {
		t.Fatal("tampered signature verified")
	}
	// Missing parameters.
	if VerifySignedURL(secret, signedRequest(t, "/files/a.pdf")) {
		t.Fatal("unsigned URL verified")
	}
	if VerifySignedURL(secret, signedRequest(t, "/files/a.pdf?exp=abc&sig="+strings.Repeat("0", 64))) {
		t.Fatal("non-numeric exp verified")
	}
}

func TestSignedURLRequired(t *testing.T) {
	if !SignedURLRequired("s", []string{"/files/"}, "/files/a.pdf") {
		t.Fatal("protected path did not require a signature")
	}
	if SignedURLRequired("s", []string{"/files/"}, "/other/a.pdf") {
		t.Fatal("unprotected path required a signature")
	}
	if SignedURLRequired("", []string{"/files/"}, "/files/a.pdf") {
		t.Fatal("empty secret required a signature")
	}
}

func TestHotlinkBlocked(t *testing.T) {
	paths := []string{"/img/"}
	mk := func(method, referer string) *http.Request {
		req := httptest.NewRequest(method, "https://example.com/img/pic.png", nil)
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		return req
	}
	if !HotlinkBlocked(mk("GET", "https://hotlink.example/pic"), paths, nil) {
		t.Fatal("foreign referer was not blocked")
	}
	if HotlinkBlocked(mk("GET", "https://example.com/page"), paths, nil) {
		t.Fatal("same-host referer was blocked")
	}
	if HotlinkBlocked(mk("GET", ""), paths, nil) {
		t.Fatal("missing referer was blocked")
	}
	if HotlinkBlocked(mk("GET", "https://hotlink.example/pic"), paths, []string{"hotlink.example"}) {
		t.Fatal("allowlisted referer was blocked")
	}
	if HotlinkBlocked(mk("POST", "https://hotlink.example/pic"), paths, nil) {
		t.Fatal("POST was hotlink-blocked (GET/HEAD only)")
	}
	unprotected := httptest.NewRequest(http.MethodGet, "https://example.com/page", nil)
	unprotected.Header.Set("Referer", "https://hotlink.example/pic")
	if HotlinkBlocked(unprotected, paths, nil) {
		t.Fatal("unprotected path was hotlink-blocked")
	}
}
