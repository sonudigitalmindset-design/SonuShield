package firewall

// Per-session rate limits (Batch 5).
//
// Limits are keyed to the challenge cookie a verified client
// presents, instead of to the client IP, so one abusive session
// behind shared NAT (a mobile network, a corporate egress) is
// limited without punishing every user sharing that IP. The
// session key is the SHA-256 of the cookie value: the raw cookie
// is never stored or logged.
//
// A session is allowed sessionRatelimit requests per rate-limit
// window (the proxy-wide ratelimit_time setting, in seconds).
// The limit is per domain and disabled (0) by default; requests
// without a session cookie — unverified requests and whitelisted
// (susLv 0) requests — are never limited here.
//
// Counting uses fixed windows per session, like the existing
// IP windows. State is bounded (100k sessions) and swept every
// minute; an over-cap session is allowed through (fail-open)
// rather than tracked without bound.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const sessionMaxEntries = 100000

type sessionCounter struct {
	windowStart time.Time
	count       int
}

var (
	sessionMu    sync.Mutex
	sessionCounts = map[string]*sessionCounter{}
	sessionSweep sync.Once
)

// SessionKeyFromRequest derives the session key from the
// challenge cookie the request carries, or "" when the request
// has no challenge cookie. Cookie names are the existing
// __bProxy_v family (including the _1_/_2_ stage prefixes and
// the captcha form); only the value hash is ever returned.
func SessionKeyFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, cookie := range r.Cookies() {
		if strings.HasSuffix(cookie.Name, "__bProxy_v") && cookie.Value != "" {
			sum := sha256.Sum256([]byte(cookie.Value))
			return hex.EncodeToString(sum[:])
		}
	}
	return ""
}

// SessionCheck records one request for a session and reports
// whether the session is still within its limit for the current
// window. A non-positive limit disables the check (always
// allowed); a non-positive window falls back to 120 seconds.
func SessionCheck(key string, limit, windowSeconds int) bool {
	if key == "" || limit <= 0 {
		return true
	}
	if windowSeconds <= 0 {
		windowSeconds = 120
	}
	sessionSweep.Do(func() { go sessionSweepLoop() })
	window := time.Duration(windowSeconds) * time.Second
	now := time.Now()

	sessionMu.Lock()
	defer sessionMu.Unlock()

	counter, ok := sessionCounts[key]
	if !ok {
		if len(sessionCounts) >= sessionMaxEntries {
			return true
		}
		counter = &sessionCounter{windowStart: now}
		sessionCounts[key] = counter
	}
	if now.Sub(counter.windowStart) >= window {
		counter.windowStart = now
		counter.count = 0
	}
	counter.count++
	return counter.count <= limit
}

// sessionSweepLoop drops counters whose window has long expired,
// so the map stays bounded for sessions that never return.
func sessionSweepLoop() {
	for {
		time.Sleep(time.Minute)
		cutoff := time.Now().Add(-2 * time.Hour)
		sessionMu.Lock()
		for key, counter := range sessionCounts {
			if counter.windowStart.Before(cutoff) {
				delete(sessionCounts, key)
			}
		}
		sessionMu.Unlock()
	}
}
