package server

import (
	"strings"
	"testing"

	"sonushield/core/domains"
)

// safeRedirectTarget: only same-origin relative paths survive.
func TestSafeRedirectTarget(t *testing.T) {
	cases := map[string]string{
		"/dashboard":            "/dashboard",
		"/a/b?x=1&y=2":          "/a/b?x=1&y=2",
		"/":                     "/",
		"":                      "/",
		"//evil.com/x":          "/evil.com/x", // collapsed to a same-origin path
		"///evil.com/x":         "/evil.com/x",
		"//evil.com":            "/evil.com",
		"https://evil.com/x":    "/",
		"http://evil.com/x":     "/",
		"javascript:alert(1)":   "/",
		"data:text/html,<h1>x":  "/",
		"/\\evil.com":           "/evil.com", // backslash treated as a separator
		"/path\\to":             "/path/to",
		"/a\n/b":                "/a/b", // control characters stripped
		"/a\rb":                 "/ab",
		"/a\tb":                 "/ab",
		"relative/path":         "/",
		"/%2e%2e/admin":         "/%2e%2e/admin", // encoded dots stay encoded: a path, not a traversal
	}
	for in, want := range cases {
		if got := safeRedirectTarget(in); got != want {
			t.Fatalf("safeRedirectTarget(%q) = %q, want %q", in, got, want)
		}
	}
	// Idempotent: sanitizing twice changes nothing.
	for in := range cases {
		once := safeRedirectTarget(in)
		if twice := safeRedirectTarget(once); twice != once {
			t.Fatalf("safeRedirectTarget not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}

func TestClientIPFromRemoteAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:12345":         "203.0.113.7",
		"[2001:db8::1]:443":         "2001:db8::1",
		"[::1]:8080":                "::1",
		"203.0.113.7":               "203.0.113.7", // unparseable: raw fallback
		"":                          "",
		"unix-socket":               "unix-socket",
	}
	for in, want := range cases {
		if got := clientIPFromRemoteAddr(in); got != want {
			t.Fatalf("clientIPFromRemoteAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func validTestConfig() *domains.Configuration {
	return &domains.Configuration{
		Proxy: domains.Proxy{
			Secrets: map[string]string{
				"cookie":     "cookie-secret-long-enough-12345",
				"javascript": "javascript-secret-long-enough-1",
				"captcha":    "captcha-secret-long-enough-1234",
			},
			AdminSecret: "admin-secret-long-enough-12345",
			APISecret:   "api-secret-long-enough-123456",
			Cloudflare:  true, // skips certificate checks: no files needed
		},
		Domains: []domains.Domain{
			{Name: "example.com", Backend: "127.0.0.1:8080", Scheme: "http"},
		},
	}
}

func containsMsg(msgs []string, substr string) bool {
	for _, m := range msgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func TestValidateConfigDetailedValid(t *testing.T) {
	errs, _ := ValidateConfigDetailed(validTestConfig(), nil, false)
	if len(errs) != 0 {
		t.Fatalf("valid config produced errors: %v", errs)
	}
}

func TestValidateConfigDetailedErrors(t *testing.T) {
	// Nil config.
	if errs, _ := ValidateConfigDetailed(nil, nil, false); len(errs) == 0 {
		t.Fatal("nil config produced no errors")
	}
	// Missing challenge secret.
	cfg := validTestConfig()
	delete(cfg.Proxy.Secrets, "cookie")
	if errs, _ := ValidateConfigDetailed(cfg, nil, false); !containsMsg(errs, `proxy secret "cookie" is missing`) {
		t.Fatalf("missing cookie secret: errors = %v", errs)
	}
	// CHANGE_ME placeholder.
	cfg = validTestConfig()
	cfg.Proxy.AdminSecret = "CHANGE_ME_admin"
	if errs, _ := ValidateConfigDetailed(cfg, nil, false); !containsMsg(errs, "contains 'CHANGE_ME'") {
		t.Fatalf("CHANGE_ME admin secret: errors = %v", errs)
	}
	// No domains.
	cfg = validTestConfig()
	cfg.Domains = nil
	if errs, _ := ValidateConfigDetailed(cfg, nil, false); !containsMsg(errs, "no domains configured") {
		t.Fatalf("no domains: errors = %v", errs)
	}
	// Bad rule expression.
	cfg = validTestConfig()
	cfg.Domains[0].FirewallRules = []domains.JsonRule{{Expression: "ip.country ==", Action: "4"}}
	if errs, _ := ValidateConfigDetailed(cfg, nil, false); !containsMsg(errs, "does not compile") {
		t.Fatalf("bad rule expression: errors = %v", errs)
	}
	// Invalid rule action.
	cfg = validTestConfig()
	cfg.Domains[0].FirewallRules = []domains.JsonRule{{Expression: `ip.country eq "US"`, Action: "bogus"}}
	if errs, _ := ValidateConfigDetailed(cfg, nil, false); !containsMsg(errs, "invalid action") {
		t.Fatalf("bad rule action: errors = %v", errs)
	}
	// Duplicate domain.
	cfg = validTestConfig()
	cfg.Domains = append(cfg.Domains, cfg.Domains[0])
	if errs, _ := ValidateConfigDetailed(cfg, nil, false); !containsMsg(errs, "duplicate domain name") {
		t.Fatalf("duplicate domain: errors = %v", errs)
	}
	// Bad backend shape.
	cfg = validTestConfig()
	cfg.Domains[0].Backend = "no-port-here"
	if errs, _ := ValidateConfigDetailed(cfg, nil, false); !containsMsg(errs, "must be host:port") {
		t.Fatalf("bad backend: errors = %v", errs)
	}
	// Unknown top-level key is a warning, not an error.
	cfg = validTestConfig()
	_, warns := ValidateConfigDetailed(cfg, []byte(`{"proxy":{},"domains":[],"typo":{}}`), false)
	if !containsMsg(warns, `unknown top-level key "typo"`) {
		t.Fatalf("unknown top-level key: warnings = %v", warns)
	}
}
