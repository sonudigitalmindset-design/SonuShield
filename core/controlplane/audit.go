package controlplane

// Control-plane audit log.
//
// Every control-plane action — login, logout, setup, account
// change, and every proxied node API call — appends one JSON
// object per line to the configured audit file. The format
// mirrors the proxy audit log (role, action, domain, IP,
// success, error) plus the control-plane user and node, so
// both logs can be read with the same tooling. Parameters are
// scrubbed exactly like the proxy audit log: secret-like keys
// are dropped and values truncated, so credentials can never
// reach the file. Passwords, tokens, and session cookies are
// never written: login entries record only the outcome.

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// AuditEntry is one control-plane audit record.
type AuditEntry struct {
	Timestamp time.Time         `json:"ts"`
	User      string            `json:"user"`
	Role      string            `json:"role"`
	Auth      string            `json:"auth,omitempty"`
	Node      string            `json:"node,omitempty"`
	Action    string            `json:"action"`
	Domain    string            `json:"domain,omitempty"`
	IP        string            `json:"ip"`
	Params    map[string]string `json:"params,omitempty"`
	Success   bool              `json:"success"`
	Error     string            `json:"error,omitempty"`
}

// AuditWriter appends audit entries to a file, serialized.
type AuditWriter struct {
	mu   sync.Mutex
	file *os.File
}

// NewAuditWriter opens (or creates, 0600) the audit file for
// appending. Audit is a security control: failing to open the
// file fails control-plane startup rather than running
// silently unaudited.
func NewAuditWriter(path string) (*AuditWriter, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &AuditWriter{file: file}, nil
}

// Write appends one entry. A write failure is reported to
// stderr but never fails the action being audited: the audit
// log must not become a denial-of-service vector.
func (w *AuditWriter) Write(entry AuditEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')
	w.mu.Lock()
	_, err = w.file.Write(data)
	w.mu.Unlock()
	if err != nil {
		println("[ ! ] [ control-plane audit write failed: " + err.Error() + " ]")
	}
}

// Close flushes and closes the audit file.
func (w *AuditWriter) Close() error {
	return w.file.Close()
}

var auditScrubSubstrings = []string{"secret", "token", "password", "key", "passphrase"}

const maxAuditParamLen = 200

// scrubParams drops secret-like params and truncates the rest.
// It mirrors api.scrubParams; the two lists are kept in step
// deliberately so neither log can carry a credential.
func scrubParams(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}
	scrubbed := make(map[string]string, len(params))
	for key, value := range params {
		lower := strings.ToLower(key)
		drop := false
		for _, substring := range auditScrubSubstrings {
			if strings.Contains(lower, substring) {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		if len(value) > maxAuditParamLen {
			value = value[:maxAuditParamLen]
		}
		scrubbed[key] = value
	}
	if len(scrubbed) == 0 {
		return nil
	}
	return scrubbed
}
