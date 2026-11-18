package backup

import (
	"encoding/json"
	"strings"
	"testing"
)

const testDoc = `{
	"proxy": {
		"adminsecret": "adm-123",
		"apisecret": "api-456",
		"secrets": {"cookie": "c1", "javascript": "j1"},
		"apiRoles": {"role-secret-1": "viewer"},
		"sso": {"clientSecret": "sso-1", "clientId": "id-1"},
		"stripe": {"secretKey": "sk-1"},
		"publicApiKeys": [{"key": "pk-1", "name": "n1"}],
		"controlPlaneSecret": "cps-1",
		"cloudflare": false
	},
	"domains": [
		{"name": "example.com", "backend": "127.0.0.1:8080", "jwtSecret": "jwt-1", "signedURLSecret": "su-1", "apiKeys": [{"key": "dk-1"}]},
		{"name": "other.example", "backend": "127.0.0.1:8081"}
	]
}`

// Redaction must remove every secret value in the path table while
// leaving ordinary config untouched.
func TestRedactDocument(t *testing.T) {
	redacted, err := RedactDocument([]byte(testDoc))
	if err != nil {
		t.Fatal(err)
	}
	text := string(redacted)
	for _, secret := range []string{"adm-123", "api-456", "c1", "j1", "role-secret-1", "sso-1", "sk-1", "pk-1", "cps-1", "jwt-1", "su-1", "dk-1"} {
		if strings.Contains(text, secret) {
			t.Fatalf("redacted document still contains secret %q", secret)
		}
	}
	for _, kept := range []string{"example.com", "127.0.0.1:8080", "id-1", "n1", "other.example", "viewer"} {
		if !strings.Contains(text, kept) {
			t.Fatalf("redacted document lost non-secret value %q", kept)
		}
	}
	if !strings.Contains(text, Placeholder) {
		t.Fatal("redacted document has no placeholder")
	}
	// The redacted document is still valid JSON with the same shape.
	var doc map[string]interface{}
	if err := json.Unmarshal(redacted, &doc); err != nil {
		t.Fatalf("redacted document is not valid JSON: %v", err)
	}
	proxy := doc["proxy"].(map[string]interface{})
	if proxy["adminsecret"] != Placeholder {
		t.Fatalf("adminsecret = %v, want %q", proxy["adminsecret"], Placeholder)
	}
	if proxy["cloudflare"] != false {
		t.Fatal("non-secret proxy field changed")
	}
}

// collectSecrets + mergeSecrets round-trip: secrets pulled out of
// a document merge back into the redacted form unchanged.
func TestSecretsRoundTrip(t *testing.T) {
	secrets, err := collectSecrets([]byte(testDoc))
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RedactDocument([]byte(testDoc))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(redacted, &doc); err != nil {
		t.Fatal(err)
	}
	mergeSecrets(doc, secrets)
	merged, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Compare semantically: re-parse both and compare maps.
	var want, got map[string]interface{}
	if err := json.Unmarshal([]byte(testDoc), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Fatalf("round-trip mismatch:\nwant %s\n got %s", wantJSON, gotJSON)
	}
}

func TestRedactDocumentInvalid(t *testing.T) {
	if _, err := RedactDocument([]byte("{not json")); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
