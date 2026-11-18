package events

// SIEM payload encodings (Batch 6).
//
// Every endpoint receives one of three encodings of the same
// event, delivered by HTTP POST with HMAC signature headers
// (see deliver.go):
//
//   - JSON (format "" or "json"): the compact JSON envelope.
//   - Syslog (format "syslog"): one RFC 5424 line. Priority
//     132 (local0.warning) for attack starts, 134
//     (local0.info) otherwise; app-name SonuShield; msgid is
//     the event type; the message is the compact JSON
//     envelope. This is the "JSON syslog" shape SIEM HTTP
//     collectors and syslog relays commonly ingest.
//   - CEF (format "cef"): one CEF:0 line. The signature id
//     and name are the event type; severity is 7 for attack
//     starts, 3 for attack ends, 5 for failed audits, 1
//     otherwise. Extensions carry the domain, tenant, and the
//     event's known scalar fields; unknown data fields are
//     dropped (the JSON encoding carries everything).
//
// No encoding includes secrets: event data is already
// secret-free by construction (see events.go).

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// EncodeJSON renders the compact JSON envelope.
func EncodeJSON(ev Event) ([]byte, string) {
	body, err := json.Marshal(ev)
	if err != nil {
		return []byte(`{}`), "application/json"
	}
	return body, "application/json"
}

// syslogHostname is resolved once; a missing or malformed
// hostname degrades to the NILVALUE-safe "-".
var syslogHostname = computeSyslogHostname()

func computeSyslogHostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" || strings.ContainsAny(name, " \t\r\n") {
		return "-"
	}
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}

// EncodeSyslog renders one RFC 5424 line with the JSON
// envelope as the message.
func EncodeSyslog(ev Event) ([]byte, string) {
	priority := 134
	if ev.Type == TypeAttackStart {
		priority = 132
	}
	body, _ := EncodeJSON(ev)
	line := fmt.Sprintf("<%d>1 %s %s SonuShield - %s - %s",
		priority, ev.Timestamp.Format(time.RFC3339), syslogHostname, ev.Type, body)
	return []byte(line), "text/plain"
}

// escapeCEF escapes a CEF header or extension value: backslash,
// pipe, equals, and line breaks.
func escapeCEF(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "=", "\\=")
	value = strings.ReplaceAll(value, "\r", "\\r")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return value
}

// cefSeverity maps an event to its CEF severity (0-10).
func cefSeverity(ev Event) int {
	switch ev.Type {
	case TypeAttackStart:
		return 7
	case TypeAttackStop:
		return 3
	case TypeAudit:
		if success, _ := ev.Data["success"].(bool); !success {
			return 5
		}
		return 1
	default:
		return 1
	}
}

// cefSummary builds the human-readable msg extension.
func cefSummary(ev Event) string {
	switch ev.Type {
	case TypeAttackStart:
		return fmt.Sprintf("Attack started on %s (%v, stage %v)", ev.Domain, ev.Data["kind"], ev.Data["stage"])
	case TypeAttackStop:
		return fmt.Sprintf("Attack ended on %s", ev.Domain)
	case TypeAudit:
		outcome := "succeeded"
		if success, _ := ev.Data["success"].(bool); !success {
			outcome = "failed"
			if errCode, _ := ev.Data["error"].(string); errCode != "" {
				outcome += " (" + errCode + ")"
			}
		}
		domain := ev.Domain
		if domain == "" {
			domain = "proxy"
		}
		return fmt.Sprintf("%v ran %v on %s: %s", ev.Data["role"], ev.Data["action"], domain, outcome)
	case TypeTest:
		return "SonuShield webhook test event"
	default:
		return ev.Type
	}
}

// EncodeCEF renders one CEF:0 line. Extension keys are sorted
// so identical events encode identically.
func EncodeCEF(ev Event) ([]byte, string) {
	ext := map[string]string{
		"msg": cefSummary(ev),
	}
	if ev.Domain != "" {
		ext["dhost"] = ev.Domain
	}
	if ev.Tenant != "" {
		ext["cs1Label"] = "tenant"
		ext["cs1"] = ev.Tenant
	}
	// Known scalar fields, in fixed label slots.
	if action, ok := ev.Data["action"].(string); ok && action != "" {
		ext["cs2Label"] = "action"
		ext["cs2"] = action
	}
	if role, ok := ev.Data["role"].(string); ok && role != "" {
		ext["cs3Label"] = "role"
		ext["cs3"] = role
	}
	if kind, ok := ev.Data["kind"].(string); ok && kind != "" {
		ext["cs4Label"] = "kind"
		ext["cs4"] = kind
	}
	if stage, ok := ev.Data["stage"]; ok {
		ext["cn1Label"] = "stage"
		ext["cn1"] = fmt.Sprintf("%v", stage)
	}
	keys := make([]string, 0, len(ext))
	for k := range ext {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+escapeCEF(ext[k]))
	}
	line := fmt.Sprintf("CEF:0|SonuShield|SonuShield|1.0|%s|%s|%d|%s",
		escapeCEF(ev.Type), escapeCEF(ev.Type), cefSeverity(ev), strings.Join(parts, " "))
	return []byte(line), "text/plain"
}

// Encode renders an event in the named format ("json",
// "syslog", or "cef"). Unknown formats fall back to JSON.
func Encode(ev Event, format string) ([]byte, string) {
	switch format {
	case "syslog":
		return EncodeSyslog(ev)
	case "cef":
		return EncodeCEF(ev)
	default:
		return EncodeJSON(ev)
	}
}
