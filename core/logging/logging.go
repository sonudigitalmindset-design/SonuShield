package logging

// Structured (JSON) logging (Batch 2).
//
// Disabled by default: the existing text output and in-memory logs
// are unchanged unless the operator sets proxy.logFormat to "json"
// AND proxy.logFile to a writable path. JSON is never written to
// stdout, because the terminal HUD redraws there and JSON lines
// would garble it.
//
// Retention: size-based rotation. When the current file would grow
// past logMaxBytes (default 10 MiB), it is renamed to <file>.1 and
// older files shift up; logMaxFiles (default 5) counts every kept
// file including the current one, so disk use is bounded near
// logMaxBytes * logMaxFiles. Rotation and write failures disable
// logging (with one warning) instead of filling the disk or
// crashing the proxy.
//
// Privacy: entries carry metadata only — timestamps, domain, IP,
// action, rule, fingerprints, stage, method, path, truncated
// user-agent, and GeoIP country/ASN. Request bodies, cookies,
// headers, query strings, and secrets are NEVER logged: the path is
// stripped of its query string here as a second line of defence,
// and the user-agent is truncated to 200 characters. Country/ASN
// are resolved inside Log via the firewall's GeoIP readers only
// when logging is enabled, and stay empty when no database is
// loaded (fail-open).

import (
	"encoding/json"
	"fmt"
	"os"
	"sonushield/core/firewall"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults and clamps for the rotation settings. The minimum file
// size prevents pathological rotate-on-every-write configs; the
// maximum file count bounds the rename loop during rotation.
const (
	DefaultMaxBytes = 10 << 20 // 10 MiB
	DefaultMaxFiles = 5
	minMaxBytes     = 64 << 10 // 64 KiB
	maxMaxFiles     = 100
	maxUserAgentLen = 200
)

// Entry is one JSON log line. Optional fields use omitempty so
// entries stay compact; every entry always carries ts, level,
// event, and domain.
type Entry struct {
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`
	Event     string    `json:"event"`
	Domain    string    `json:"domain"`

	IP     string `json:"ip,omitempty"`
	Action string `json:"action,omitempty"`
	Rule   string `json:"rule,omitempty"`
	// Rules lists every firewall rule expression that matched this
	// request, when firewall rules were evaluated.
	Rules []string `json:"rules,omitempty"`

	Fingerprint     string `json:"fingerprint,omitempty"`
	JA4             string `json:"ja4,omitempty"`
	HTTPFingerprint string `json:"http_fingerprint,omitempty"`
	Engine          string `json:"engine,omitempty"`
	Bot             string `json:"bot,omitempty"`

	Stage    int `json:"stage,omitempty"`
	SusLevel int `json:"sus_level,omitempty"`
	// WouldBeSusLevel is set only on "dryrun" entries: the
	// suspicion level the rules would have produced had dry-run
	// mode been off. SusLevel stays the level actually applied.
	WouldBeSusLevel int `json:"would_be_sus_level,omitempty"`

	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	Country string `json:"country,omitempty"`
	ASN     int    `json:"asn,omitempty"`

	RPS            int `json:"rps,omitempty"`
	RPSAllowed     int `json:"rps_allowed,omitempty"`
	PeakRPS        int `json:"peak_rps,omitempty"`
	PeakRPSAllowed int `json:"peak_rps_allowed,omitempty"`
}

var (
	mu       sync.Mutex
	enabled  atomic.Bool
	failed   atomic.Bool
	file     *os.File
	filePath string
	maxBytes int64
	maxFiles int
	written  int64
)

// Enabled reports whether JSON logging is currently active. Callers
// use it to skip work that only exists for the log, such as
// re-evaluating firewall rules to find which ones matched.
func Enabled() bool {
	return enabled.Load() && !failed.Load()
}

// Configure (re)configures structured logging from the proxy
// settings. It is called from config.Load() at startup and from
// ReloadConfig() on reload, so a reload picks up new log settings
// without a restart. Any problem — unknown format, JSON without a
// file, an unwritable path — disables logging with a warning and
// never panics, so a bad log config can never stop the proxy.
func Configure(format, path string, maxBytesSetting int64, maxFilesSetting int) {
	mu.Lock()
	defer mu.Unlock()

	if file != nil {
		file.Close()
		file = nil
	}
	enabled.Store(false)
	failed.Store(false)
	filePath = ""
	written = 0

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "text" {
		return
	}
	if format != "json" {
		fmt.Println("[ ! ] [ Unknown logFormat \"" + format + "\"; structured logging disabled ]")
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		fmt.Println("[ ! ] [ JSON logging needs logFile set; structured logging disabled ]")
		return
	}

	maxBytes = maxBytesSetting
	if maxBytes < minMaxBytes {
		maxBytes = DefaultMaxBytes
	}
	maxFiles = maxFilesSetting
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFiles
	}
	if maxFiles > maxMaxFiles {
		maxFiles = maxMaxFiles
	}

	opened, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Println("[ ! ] [ Cannot open log file, structured logging disabled:", err, "]")
		return
	}
	if stat, statErr := opened.Stat(); statErr == nil {
		written = stat.Size()
	}
	file = opened
	filePath = path
	enabled.Store(true)
}

func levelFor(event string) string {
	switch event {
	case "block", "waf", "attack_start", "attack_end":
		return "warn"
	default:
		return "info"
	}
}

// Log appends one JSON entry to the log file. It returns immediately
// when logging is disabled, and never panics: serialization and
// write problems disable logging instead of affecting the request.
func Log(entry Entry) {
	if !Enabled() {
		return
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.Level == "" {
		entry.Level = levelFor(entry.Event)
	}
	// Defence in depth: never log a query string, even if a caller
	// passes a full URI by mistake.
	if i := strings.IndexByte(entry.Path, '?'); i >= 0 {
		entry.Path = entry.Path[:i]
	}
	if len(entry.UserAgent) > maxUserAgentLen {
		entry.UserAgent = entry.UserAgent[:maxUserAgentLen]
	}
	if entry.IP != "" && entry.Country == "" {
		entry.Country, entry.ASN = firewall.LookupGeo(entry.IP)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	writeLine(data)
}

// writeLine appends one serialized line to the log file, rotating
// first when the size limit would be exceeded. It is shared by
// Log and Audit so both use the same rotation and failure
// handling. It silently drops the line when logging is disabled
// or has failed.
func writeLine(data []byte) {
	mu.Lock()
	defer mu.Unlock()
	if file == nil || failed.Load() {
		return
	}
	if written+int64(len(data)) > maxBytes {
		rotateLocked()
		if file == nil || failed.Load() {
			return
		}
	}
	n, err := file.Write(data)
	if err != nil {
		disableLocked(err)
		return
	}
	written += int64(n)
}

// AuditEntry is one control-plane audit record (Batch 4). Params
// are scrubbed by the caller: secret-like keys are dropped and
// values truncated, so secrets are never written here.
type AuditEntry struct {
	Timestamp time.Time         `json:"ts"`
	Level     string            `json:"level"`
	Event     string            `json:"event"`
	Role      string            `json:"role"`
	Action    string            `json:"action"`
	Domain    string            `json:"domain,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
	Success   bool              `json:"success"`
	Error     string            `json:"error,omitempty"`
}

// Audit records one control-plane action. When structured logging
// is configured, the entry goes to the log file (same rotation
// as request entries); otherwise a compact line is printed to
// stdout, matching the existing warning output. Operators who
// use the dashboard heavily should configure logFile to keep
// stdout clean.
func Audit(entry AuditEntry) {
	entry.Event = "audit"
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	entry.Level = "info"
	if !entry.Success {
		entry.Level = "warn"
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if Enabled() {
		writeLine(data)
		return
	}
	params := ""
	if len(entry.Params) > 0 {
		parts := make([]string, 0, len(entry.Params))
		for key, value := range entry.Params {
			parts = append(parts, key+"="+value)
		}
		params = " params=" + strings.Join(parts, ",")
		if len(params) > 500 {
			params = params[:500]
		}
	}
	fmt.Println("[ audit ] [ role=" + entry.Role + " action=" + entry.Action + " domain=" + entry.Domain + " ip=" + entry.IP + " success=" + fmt.Sprint(entry.Success) + " error=" + entry.Error + params + " ]")
}

// rotateLocked renames the current file aside and opens a fresh one.
// The caller must hold mu. With maxFiles == 1 there is no rotated
// file to keep, so the current file is truncated instead.
func rotateLocked() {
	file.Close()
	file = nil
	written = 0

	if maxFiles <= 1 {
		opened, err := os.OpenFile(filePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			disableLocked(err)
			return
		}
		file = opened
		return
	}

	oldest := fmt.Sprintf("%s.%d", filePath, maxFiles-1)
	os.Remove(oldest)
	for i := maxFiles - 2; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", filePath, i), fmt.Sprintf("%s.%d", filePath, i+1))
	}
	os.Rename(filePath, filePath+".1")

	opened, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		disableLocked(err)
		return
	}
	file = opened
}

// disableLocked stops logging after a persistent failure. The
// caller must hold mu. One warning is printed; the proxy keeps
// serving exactly as before, minus the log file.
func disableLocked(err error) {
	if file != nil {
		file.Close()
		file = nil
	}
	failed.Store(true)
	enabled.Store(false)
	fmt.Println("[ ! ] [ Structured logging disabled after log file failure:", err, "]")
}
