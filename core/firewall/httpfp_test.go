package firewall

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestComputeHTTPFingerprintFormat(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	got := ComputeHTTPFingerprint(req)
	parts := strings.Split(got, "_")
	if len(parts) != 5 || parts[0] != "sh1" {
		t.Fatalf("fingerprint = %q, want sh1_<a>_<b>_<c>_<d>", got)
	}
	// "ge" (GET) + "11" (HTTP/1.1) + no cookie + no referer + header
	// count 2 + language "enus".
	if parts[1] != "ge11nn02enus" {
		t.Fatalf("a-section = %q, want ge11nn02enus", parts[1])
	}
	for _, h := range parts[2:] {
		if len(h) != 12 {
			t.Fatalf("hash section %q is %d chars, want 12", h, len(h))
		}
	}
}

func TestComputeHTTPFingerprintDeterministic(t *testing.T) {
	mk := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/x", nil)
		req.Header.Set("User-Agent", "ua")
		req.Header.Set("Cookie", "a=1; b=2")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		return req
	}
	if ComputeHTTPFingerprint(mk()) != ComputeHTTPFingerprint(mk()) {
		t.Fatal("same request produced different fingerprints")
	}
}

func TestComputeHTTPFingerprintSensitivity(t *testing.T) {
	base := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	base.Header.Set("User-Agent", "ua-one")
	other := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	other.Header.Set("User-Agent", "ua-two")
	// Header names are identical, so sections a/b match; the
	// fingerprint never hashes header values, so the two are
	// equal. That is by design: values are not part of sh1.
	if ComputeHTTPFingerprint(base) != ComputeHTTPFingerprint(other) {
		t.Fatal("header VALUE changed the fingerprint (values must not be hashed)")
	}
	withCookie := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	withCookie.Header.Set("Cookie", "session=abc")
	if ComputeHTTPFingerprint(base) == ComputeHTTPFingerprint(withCookie) {
		t.Fatal("cookie presence did not change the fingerprint")
	}
}

func TestComputeHTTPFingerprintNil(t *testing.T) {
	if got := ComputeHTTPFingerprint(nil); got != "" {
		t.Fatalf("nil request = %q, want empty", got)
	}
}

func TestNormaliseEncodingList(t *testing.T) {
	a := normaliseEncodingList("gzip, deflate, br;q=0.9")
	b := normaliseEncodingList("br, gzip, deflate")
	if a != b {
		t.Fatalf("encoding order/q-values not normalised: %q vs %q", a, b)
	}
	if normaliseEncodingList("") != "" {
		t.Fatal("empty encoding list did not normalise to empty")
	}
}

func TestNormaliseLanguageList(t *testing.T) {
	a := normaliseLanguageList("en-US,en;q=0.9,fr;q=0.8")
	b := normaliseLanguageList("en-US, en, fr")
	if a != b {
		t.Fatalf("language q-values not normalised: %q vs %q", a, b)
	}
	// Order is significant for language preference.
	if normaliseLanguageList("fr,en") == normaliseLanguageList("en,fr") {
		t.Fatal("language order was lost")
	}
}

func TestComputeHTTP2Fingerprint(t *testing.T) {
	// Non-HTTP/2 requests get no fingerprint.
	http1 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if got := ComputeHTTP2Fingerprint(http1); got != "" {
		t.Fatalf("HTTP/1.1 request = %q, want empty", got)
	}
	if got := ComputeHTTP2Fingerprint(nil); got != "" {
		t.Fatalf("nil request = %q, want empty", got)
	}

	h2 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	h2.ProtoMajor, h2.ProtoMinor = 2, 0
	h2.TLS = &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
	}
	h2.Header.Set("User-Agent", "ua")
	got := ComputeHTTP2Fingerprint(h2)
	if !strings.HasPrefix(got, "h2_20_13-1301_h2_") {
		t.Fatalf("h2 fingerprint = %q, want h2_20_13-1301_h2_ prefix", got)
	}
	parts := strings.Split(got, "_")
	if len(parts) != 6 {
		t.Fatalf("h2 fingerprint = %q, want 6 underscore-separated parts", got)
	}
	// Flags: accept 0, accept-encoding 0, accept-language 0,
	// user-agent 1, cookie 0, referer 0, upgrade-insecure 0,
	// sec-fetch-site 0.
	if parts[5] != "00010000" {
		t.Fatalf("h2 flags = %q, want 00010000", parts[5])
	}
	if ComputeHTTP2Fingerprint(h2) != got {
		t.Fatal("same request produced different h2 fingerprints")
	}
}
