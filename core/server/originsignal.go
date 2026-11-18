package server

// Origin-signal endpoint (Batch 8).
//
// POST /_bProxy/origin-signal accepts failure signals from
// origin servers (for example the WordPress plugin's
// wp_login_failed hook) so the proxy's credential-stuffing
// detector can count failures the origin saw but the proxy
// could not distinguish from ordinary responses. The request
// carries the shared secret in the X-SonuShield-Signal
// header and a JSON body:
//
//	{"domain": "example.com", "type": "login_failure",
//	 "ip": "203.0.113.5", "path": "/wp-login.php"}
//
// The endpoint is handled before the challenge flow — origin
// servers are machines — and does not exist while no secret
// is configured. The signal is recorded under the longest
// matching watched path in the domain's stuffing
// configuration, exactly like a failure observed in a
// response; when the path matches no watched path the signal
// is accepted (204) but has no effect, so the origin plugin
// needs the operator to configure stuffing paths. No
// usernames or credentials are accepted: unknown body fields
// are ignored, and the only accepted type is "login_failure".
// Bodies are capped at 4 KiB.

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"strings"
)

const maxOriginSignalBytes = 4 << 10

// HandleOriginSignal answers POST /_bProxy/origin-signal.
// It reports whether it handled the request.
func HandleOriginSignal(writer http.ResponseWriter, request *http.Request) bool {
	if request.URL.Path != "/_bProxy/origin-signal" {
		return false
	}
	secret := ""
	if domains.Config != nil {
		secret = domains.Config.Proxy.OriginSignals.Secret
	}
	if secret == "" {
		return false
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		writer.Write([]byte("404 Not Found"))
		return true
	}
	provided := request.Header.Get("X-SonuShield-Signal")
	if len(provided) != len(secret) || subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Unauthorized"))
		return true
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxOriginSignalBytes+1))
	if err != nil || int64(len(body)) > maxOriginSignalBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	var signal struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
		IP     string `json:"ip"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(body, &signal); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	if signal.Type != "login_failure" || net.ParseIP(signal.IP) == nil {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	settings, err := domains.Get(signal.Domain)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	path := stripURIQuery(signal.Path)
	if !strings.HasPrefix(path, "/") {
		writer.WriteHeader(http.StatusBadRequest)
		return true
	}
	matched := ""
	for _, prefix := range settings.CredentialStuffing.Paths {
		if prefix != "" && strings.HasPrefix(path, prefix) && len(prefix) > len(matched) {
			matched = prefix
		}
	}
	if matched != "" {
		firewall.RecordStuffingFailure(signal.Domain, matched, signal.IP)
	}
	writer.WriteHeader(http.StatusNoContent)
	return true
}
