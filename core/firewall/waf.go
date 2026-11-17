package firewall

// WAF-lite: conservative request inspection for common web attacks.
//
// Modes (per domain, wafMode): "" (unset) and "log" mean log-only —
// matches are logged and the request continues, so legitimate visitors
// notice nothing. "block" answers matches with a generic unbranded 403.
// "off" disables inspection entirely. Unknown values fall back to
// log-only, never to blocking.
//
// What is inspected: the URL path and query (both raw and URL-decoded),
// and optionally small request bodies (wafInspectBody, POST/PUT/PATCH up
// to 1 MB; chunked or larger bodies are skipped, never buffered). Bodies
// are restored after inspection so proxying is unaffected. Matched
// requests are logged with the rule name, IP, method, and a truncated
// path only — never with the request body, which may contain secrets.
//
// Patterns are deliberately conservative: each one targets a shape that
// is essentially never legitimate in a URL. They are a first line of
// defense, not a full WAF, and block mode is opt-in precisely because no
// pattern set is false-positive free.
//
// WordPress login flood: POSTs to /wp-login.php and /xmlrpc.php are
// counted per IP in 60-second windows; exceeding wafWpLoginLimit
// (default 20) counts as a match under the rule name "wp-login-flood".

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type wafRule struct {
	name    string
	pattern *regexp.Regexp
}

var wafRules = []wafRule{
	{"sqli-union-select", regexp.MustCompile(`(?i)\bunion\b[\s\S]{0,40}?\bselect\b`)},
	{"sqli-select-from-where", regexp.MustCompile(`(?i)\bselect\b[\s\S]{0,40}?\bfrom\b[\s\S]{0,40}?\bwhere\b`)},
	{"sqli-information-schema", regexp.MustCompile(`(?i)information_schema\b`)},
	{"sqli-sleep", regexp.MustCompile(`(?i)\bsleep\s*\(\s*\d`)},
	{"sqli-benchmark", regexp.MustCompile(`(?i)\bbenchmark\s*\(\s*\d`)},
	{"sqli-or-tautology", regexp.MustCompile(`(?i)('\s*or\s+['"]?\w+['"]?\s*=\s*['"]?\w*|\bor\s+\d+\s*=\s*\d+)`)},
	{"sqli-drop-table", regexp.MustCompile(`(?i)\bdrop\s+table\b`)},
	{"xss-script-tag", regexp.MustCompile(`(?i)<\s*script\b`)},
	{"xss-javascript-uri", regexp.MustCompile(`(?i)javascript\s*:`)},
	{"xss-img-onerror", regexp.MustCompile(`(?i)<\s*img[^>]*\bonerror\s*=`)},
	{"xss-svg-handler", regexp.MustCompile(`(?i)<\s*svg[^>]*\bon\w+\s*=`)},
	{"xss-document-cookie", regexp.MustCompile(`(?i)document\s*\.\s*cookie\b`)},
	{"traversal", regexp.MustCompile(`(?i)(\.\./|\.\.\\)`)},
	{"traversal-encoded", regexp.MustCompile(`(?i)(%2e%2e|%252e|%c0%ae)`)},
	{"null-byte", regexp.MustCompile(`(?i)(%00|\x00)`)},
}

const maxWAFBodyBytes = 1 << 20 // 1 MB

// ResolveWAFMode normalizes the configured mode. Unknown values fall back
// to log-only, never to blocking. Exported so the API can report the
// effective mode for a domain.
func ResolveWAFMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off":
		return "off"
	case "block":
		return "block"
	default:
		return "log"
	}
}

func decodeLenient(unescaped func(string) (string, error), s string) string {
	if decoded, err := unescaped(s); err == nil {
		return decoded
	}
	return s
}

// CheckRequest inspects a request and reports whether it must be blocked.
// In log mode matches are logged and false is returned. In off mode
// nothing is inspected. The request body, when read, is restored.
func CheckRequest(request *http.Request, mode string, inspectBody bool, wpLoginLimit int, ip string) (blocked bool, ruleName string) {
	resolved := ResolveWAFMode(mode)
	if resolved == "off" {
		return false, ""
	}

	rawTarget := request.URL.EscapedPath()
	if request.URL.RawQuery != "" {
		rawTarget += "?" + request.URL.RawQuery
	}
	decodedTarget := decodeLenient(url.PathUnescape, request.URL.EscapedPath())
	if request.URL.RawQuery != "" {
		decodedTarget += "?" + decodeLenient(url.QueryUnescape, request.URL.RawQuery)
	}

	if inspectBody {
		if body := readAndRestoreBody(request); body != "" {
			rawTarget += "\n" + body
			decodedTarget += "\n" + decodeLenient(url.QueryUnescape, body)
		}
	}

	for _, rule := range wafRules {
		if rule.pattern.MatchString(rawTarget) || rule.pattern.MatchString(decodedTarget) {
			logWAFMatch(rule.name, request, ip)
			return resolved == "block", rule.name
		}
	}

	if wpLoginFlood(request, wpLoginLimit, ip) {
		logWAFMatch("wp-login-flood", request, ip)
		return resolved == "block", "wp-login-flood"
	}

	return false, ""
}

func readAndRestoreBody(request *http.Request) string {
	if request.Body == nil {
		return ""
	}
	switch request.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return ""
	}
	if request.ContentLength <= 0 || request.ContentLength > maxWAFBodyBytes {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxWAFBodyBytes+1))
	if err != nil {
		return ""
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) > maxWAFBodyBytes {
		return ""
	}
	return string(body)
}

func logWAFMatch(ruleName string, request *http.Request, ip string) {
	target := request.URL.RequestURI()
	if len(target) > 200 {
		target = target[:200] + "..."
	}
	fmt.Println("[ ! ] [ WAF " + ruleName + " ] [ " + ip + " ] " + request.Method + " " + target)
}

type wpWindow struct {
	start time.Time
	count int
}

var wpLoginHits = struct {
	sync.Mutex
	counts map[string]*wpWindow
}{counts: map[string]*wpWindow{}}

func wpLoginFlood(request *http.Request, limit int, ip string) bool {
	if request.Method != http.MethodPost {
		return false
	}
	switch strings.ToLower(request.URL.Path) {
	case "/wp-login.php", "/xmlrpc.php":
	default:
		return false
	}
	if limit <= 0 {
		limit = 20
	}

	now := time.Now()
	wpLoginHits.Lock()
	defer wpLoginHits.Unlock()

	window, ok := wpLoginHits.counts[ip]
	if !ok || now.Sub(window.start) >= time.Minute {
		wpLoginHits.counts[ip] = &wpWindow{start: now, count: 1}
		if len(wpLoginHits.counts) > 10000 {
			for key, entry := range wpLoginHits.counts {
				if now.Sub(entry.start) >= 2*time.Minute {
					delete(wpLoginHits.counts, key)
				}
			}
		}
		return false
	}
	window.count++
	return window.count > limit
}
