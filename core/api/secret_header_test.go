package api

import (
	"net/http/httptest"
	"testing"
)

func TestSecretFromRequest(t *testing.T) {
	t.Run("canonical header", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/_bProxy/api/v2/GET_PROXY_STATS", nil)
		request.Header.Set(SecretHeader, "canonical-secret")
		if got := SecretFromRequest(request); got != "canonical-secret" {
			t.Fatalf("got %q, want %q", got, "canonical-secret")
		}
	})

	t.Run("legacy header fallback", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/_bProxy/api/v2/GET_PROXY_STATS", nil)
		request.Header.Set(legacySecretHeader, "legacy-secret")
		if got := SecretFromRequest(request); got != "legacy-secret" {
			t.Fatalf("got %q, want %q", got, "legacy-secret")
		}
	})

	t.Run("canonical wins when both present", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/_bProxy/api/v2/GET_PROXY_STATS", nil)
		request.Header.Set(legacySecretHeader, "legacy-secret")
		request.Header.Set(SecretHeader, "canonical-secret")
		if got := SecretFromRequest(request); got != "canonical-secret" {
			t.Fatalf("got %q, want %q", got, "canonical-secret")
		}
	})

	t.Run("empty when neither present", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/_bProxy/api/v2/GET_PROXY_STATS", nil)
		if got := SecretFromRequest(request); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
}
