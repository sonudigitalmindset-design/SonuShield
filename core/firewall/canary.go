package firewall

// Canary tokens (Batch 7).
//
// The operator configures decoys — fake paths (e.g. a fake
// admin URL) and fake credential values (e.g. a fake API key)
// — that no legitimate visitor should ever touch. Any request
// that uses one is treated as automated/hostile: it is blocked
// immediately with a generic 403, logged, and (rate-limited)
// reported to the operator's alert channels. The token VALUES
// are secrets: they are compared in constant time, and are
// never logged, never returned by any API, and never included
// in alert text — only the kind of hit and the path are
// reported.
//
// Matching:
//   - Paths: exact, case-sensitive match against the request
//     path (no query string), like the honeypot paths.
//   - Tokens: exact match against the Authorization: Bearer
//     value, the X-API-Key header, or the "api_key" /
//     "apikey" query parameter. Header and query values are
//     compared in constant time against every configured
//     token.
//
// With nothing configured the check is a no-op. Alert
// rate-limiting is one notice per IP per hour so a flood of
// canary hits cannot spam the operator's channels; every hit
// is still blocked and logged.

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CanaryMatch describes what kind of decoy was tripped.
type CanaryMatch struct {
	// Kind is "path" or "token".
	Kind string
	// Path is the request path that tripped a path decoy, or
	// the path on which a token decoy was presented.
	Path string
}

// CheckCanary reports whether the request tripped a configured
// decoy. Empty configuration never matches.
func CheckCanary(request *http.Request, paths, tokens []string) (CanaryMatch, bool) {
	path := request.URL.Path
	for _, decoy := range paths {
		if decoy != "" && path == decoy {
			return CanaryMatch{Kind: "path", Path: path}, true
		}
	}
	if len(tokens) == 0 {
		return CanaryMatch{}, false
	}
	candidates := canaryCandidates(request)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		for _, token := range tokens {
			if token != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
				return CanaryMatch{Kind: "token", Path: path}, true
			}
		}
	}
	return CanaryMatch{}, false
}

// canaryCandidates extracts the values a credential decoy could
// hide in: Bearer token, X-API-Key header, and the api_key /
// apikey query parameters.
func canaryCandidates(request *http.Request) []string {
	candidates := make([]string, 0, 4)
	if auth := request.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		candidates = append(candidates, strings.TrimPrefix(auth, "Bearer "))
	}
	if key := request.Header.Get("X-API-Key"); key != "" {
		candidates = append(candidates, key)
	}
	query := request.URL.Query()
	if key := query.Get("api_key"); key != "" {
		candidates = append(candidates, key)
	}
	if key := query.Get("apikey"); key != "" {
		candidates = append(candidates, key)
	}
	return candidates
}

const canaryAlertEvery = time.Hour

var (
	canaryAlertMu   sync.Mutex
	canaryAlertLast = map[string]time.Time{}
)

// CanaryShouldAlert reports whether a canary hit from ip
// should fire an operator notice: at most one per IP per hour.
// It records the hit when it reports true.
func CanaryShouldAlert(ip string) bool {
	if ip == "" {
		return false
	}
	now := time.Now()
	canaryAlertMu.Lock()
	defer canaryAlertMu.Unlock()
	if last, ok := canaryAlertLast[ip]; ok && now.Sub(last) < canaryAlertEvery {
		return false
	}
	canaryAlertLast[ip] = now
	// Opportunistic bound: drop stale entries when the map
	// grows large, so it cannot grow without limit.
	if len(canaryAlertLast) > 50000 {
		for key, at := range canaryAlertLast {
			if now.Sub(at) >= canaryAlertEvery {
				delete(canaryAlertLast, key)
			}
		}
	}
	return true
}
