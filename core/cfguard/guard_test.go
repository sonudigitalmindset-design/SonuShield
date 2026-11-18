package cfguard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockCF records security-level PATCH requests.
type mockCF struct {
	mu       sync.Mutex
	requests []cfRequest
	fail     bool // answer success:false
	status   int  // HTTP status, 0 means 200
}

type cfRequest struct {
	method string
	path   string
	auth   string
	value  string
}

func (m *mockCF) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var payload struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal(body, &payload)
	m.mu.Lock()
	m.requests = append(m.requests, cfRequest{
		method: r.Method,
		path:   r.URL.Path,
		auth:   r.Header.Get("Authorization"),
		value:  payload.Value,
	})
	fail := m.fail
	status := m.status
	m.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if fail {
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"zone not found"}]}`))
		return
	}
	_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"value":"` + payload.Value + `"}}`))
}

func (m *mockCF) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

func (m *mockCF) last() cfRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests[len(m.requests)-1]
}

// waitFor polls until cond is true or the test times out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func testSettings(base string) Settings {
	return Settings{
		Enabled:      true,
		Token:        "test-token-123",
		ZoneID:       "zone-abc",
		APIBase:      base,
		RestoreLevel: "medium",
	}
}

func TestRaiseAndRestore(t *testing.T) {
	Reset()
	mock := &mockCF{}
	server := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer server.Close()
	settings := testSettings(server.URL)

	// Attack starts: exactly one PATCH to under_attack.
	Report("example.com", true, settings)
	waitFor(t, "raise", func() bool { return mock.count() == 1 })
	req := mock.last()
	if req.method != http.MethodPatch {
		t.Fatalf("method = %s, want PATCH", req.method)
	}
	if req.path != "/client/v4/zones/zone-abc/settings/security_level" {
		t.Fatalf("path = %s", req.path)
	}
	if req.auth != "Bearer test-token-123" {
		t.Fatalf("auth = %q, want Bearer token", req.auth)
	}
	if req.value != "under_attack" {
		t.Fatalf("value = %q, want under_attack", req.value)
	}
	if got := AppliedLevel("example.com"); got != "under_attack" {
		t.Fatalf("AppliedLevel = %q, want under_attack", got)
	}

	// Repeated attack ticks: no duplicate calls.
	for i := 0; i < 5; i++ {
		Report("example.com", true, settings)
	}
	time.Sleep(100 * time.Millisecond)
	if mock.count() != 1 {
		t.Fatalf("requests after repeated ticks = %d, want 1", mock.count())
	}

	// Attack ends: one PATCH restoring the level.
	Report("example.com", false, settings)
	waitFor(t, "restore", func() bool { return mock.count() == 2 })
	if req := mock.last(); req.value != "medium" {
		t.Fatalf("restore value = %q, want medium", req.value)
	}
	if got := AppliedLevel("example.com"); got != "medium" {
		t.Fatalf("AppliedLevel = %q, want medium", got)
	}

	// Further calm ticks: nothing more.
	Report("example.com", false, settings)
	time.Sleep(100 * time.Millisecond)
	if mock.count() != 2 {
		t.Fatalf("requests after calm ticks = %d, want 2", mock.count())
	}
}

func TestRestoreLevelDefault(t *testing.T) {
	if got := RestoreLevel(""); got != "medium" {
		t.Fatalf("RestoreLevel(\"\") = %q, want medium", got)
	}
	if got := RestoreLevel("high"); got != "high" {
		t.Fatalf("RestoreLevel(\"high\") = %q, want high", got)
	}
	// An invalid level never reaches the API.
	if got := RestoreLevel("paranoid"); got != "medium" {
		t.Fatalf("RestoreLevel(\"paranoid\") = %q, want medium", got)
	}
	for _, level := range []string{"off", "essentially_off", "low", "medium", "high", "under_attack"} {
		if !ValidLevel(level) {
			t.Fatalf("ValidLevel(%q) = false", level)
		}
	}
	if ValidLevel("bogus") {
		t.Fatal("ValidLevel(\"bogus\") = true")
	}
}

func TestDisabledOrUnconfiguredIsSilent(t *testing.T) {
	Reset()
	mock := &mockCF{}
	server := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer server.Close()

	Report("example.com", true, Settings{Enabled: false, Token: "t", ZoneID: "z", APIBase: server.URL})
	Report("example.com", true, Settings{Enabled: true, Token: "", ZoneID: "z", APIBase: server.URL})
	Report("example.com", true, Settings{Enabled: true, Token: "t", ZoneID: "", APIBase: server.URL})
	Report("", true, testSettings(server.URL))
	time.Sleep(100 * time.Millisecond)
	if mock.count() != 0 {
		t.Fatalf("disabled/unconfigured settings produced %d API calls", mock.count())
	}
}

func TestFailureRetriesAfterInterval(t *testing.T) {
	Reset()
	oldInterval := retryInterval
	retryInterval = 100 * time.Millisecond
	defer func() { retryInterval = oldInterval }()

	mock := &mockCF{fail: true}
	server := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer server.Close()
	settings := testSettings(server.URL)

	Report("example.com", true, settings)
	waitFor(t, "failed raise", func() bool { return mock.count() == 1 })
	if got := AppliedLevel("example.com"); got != "" {
		t.Fatalf("AppliedLevel after failure = %q, want empty", got)
	}
	// Immediate retry is throttled.
	Report("example.com", true, settings)
	time.Sleep(50 * time.Millisecond)
	if mock.count() != 1 {
		t.Fatalf("requests before retry interval = %d, want 1", mock.count())
	}
	// After the interval, a tick retries; the mock now
	// succeeds, so the raise lands.
	mock.mu.Lock()
	mock.fail = false
	mock.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	Report("example.com", true, settings)
	waitFor(t, "retry raise", func() bool { return mock.count() == 2 })
	if got := AppliedLevel("example.com"); got != "under_attack" {
		t.Fatalf("AppliedLevel after retry = %q, want under_attack", got)
	}
}

func TestHTTPErrorFailsOpen(t *testing.T) {
	Reset()
	mock := &mockCF{status: http.StatusForbidden}
	server := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer server.Close()
	Report("example.com", true, testSettings(server.URL))
	waitFor(t, "failed call", func() bool { return mock.count() == 1 })
	if got := AppliedLevel("example.com"); got != "" {
		t.Fatalf("AppliedLevel after HTTP error = %q, want empty", got)
	}
}

func TestTokenNeverInErrorPath(t *testing.T) {
	// An unreachable API base: setSecurityLevel must fail
	// without the token in the error.
	err := setSecurityLevel(Settings{Token: "s3cr3t-token", ZoneID: "z", APIBase: "http://127.0.0.1:1"}, "under_attack")
	if err == nil {
		t.Fatal("unreachable API base succeeded")
	}
	if strings.Contains(err.Error(), "s3cr3t-token") {
		t.Fatalf("error leaks the token: %v", err)
	}
}
