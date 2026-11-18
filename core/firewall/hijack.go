package firewall

// Session hijack detection (Batch 8).
//
// The detector binds each observed application session cookie
// to the signals seen when the session first appeared: client
// IP, TLS fingerprint, HTTP fingerprint, and country. A later
// request presenting the same cookie with a different signal
// set is suspicious — but any ONE signal can change
// legitimately (a phone switching networks changes IP and
// sometimes country; a browser update changes fingerprints).
// A session is therefore flagged only when TWO OR MORE signals
// differ from the binding. A single signal change is never
// acted on, in either mode.
//
// The signal is LOG-ONLY by default: a flagged session gets
// one log entry per hour. In "block" mode a flagged request
// gets a suspicion bump of 2 (toward the captcha challenge),
// never an outright block.
//
// Cookie values are never stored: bindings are keyed by the
// SHA-256 hash of (domain, cookie name, cookie value), and the
// API reports counts only. Bindings expire after 24 hours
// without a matching request, and the table is capped; the
// oldest binding is evicted when the cap is hit. A reload
// discards all state. The binding is never updated from a
// flagged request, so an attacker cannot rebind a stolen
// session by replaying it; matching requests refresh the
// last-seen time only.

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const (
	maxHijackBindings   = 100000
	hijackBindingTTL    = 24 * time.Hour
	hijackFlagLogWindow = time.Hour
)

type hijackBinding struct {
	ip       string
	tlsFp    string
	httpFp   string
	country  string
	lastSeen time.Time
	lastFlag time.Time
}

var (
	hijackMu       sync.Mutex
	hijackBindings = map[string]*hijackBinding{}
)

// hijackKey hashes the session identity. The raw cookie value
// never leaves this function.
func hijackKey(domain, cookieName, cookieValue string) string {
	sum := sha256.Sum256([]byte(domain + "\x00" + cookieName + "\x00" + cookieValue))
	return hex.EncodeToString(sum[:])
}

// HijackVerdict is the outcome of checking one request.
type HijackVerdict struct {
	Flagged bool
	Changed int  // number of differing signals (0-4)
	LogThis bool // log once per flag window per binding
}

// CheckSessionHijack evaluates one request's session cookie
// against its binding. An empty cookie value (no session)
// reports unflagged. The first sighting of a session creates
// the binding and reports unflagged.
func CheckSessionHijack(domain, cookieName, cookieValue, ip, tlsFp, httpFp, country string) HijackVerdict {
	if cookieName == "" || cookieValue == "" {
		return HijackVerdict{}
	}
	key := hijackKey(domain, cookieName, cookieValue)
	now := time.Now()
	hijackMu.Lock()
	defer hijackMu.Unlock()
	binding, ok := hijackBindings[key]
	if !ok || now.Sub(binding.lastSeen) > hijackBindingTTL {
		if len(hijackBindings) >= maxHijackBindings {
			var oldest string
			var oldestAt time.Time
			for k, b := range hijackBindings {
				if oldestAt.IsZero() || b.lastSeen.Before(oldestAt) {
					oldest, oldestAt = k, b.lastSeen
				}
			}
			delete(hijackBindings, oldest)
		}
		hijackBindings[key] = &hijackBinding{ip: ip, tlsFp: tlsFp, httpFp: httpFp, country: country, lastSeen: now}
		return HijackVerdict{}
	}
	changed := 0
	if binding.ip != ip {
		changed++
	}
	if binding.tlsFp != tlsFp {
		changed++
	}
	if binding.httpFp != httpFp {
		changed++
	}
	if binding.country != country {
		changed++
	}
	if changed < 2 {
		// Matching (or single-change) request: refresh
		// last-seen, keep the original binding.
		binding.lastSeen = now
		return HijackVerdict{Changed: changed}
	}
	logThis := false
	if now.Sub(binding.lastFlag) > hijackFlagLogWindow {
		binding.lastFlag = now
		logThis = true
	}
	return HijackVerdict{Flagged: true, Changed: changed, LogThis: logThis}
}

// HijackStats reports detector counts: live bindings and
// sessions flagged within the last hour. Counts only.
func HijackStats() (bindings, flaggedRecent int) {
	now := time.Now()
	hijackMu.Lock()
	defer hijackMu.Unlock()
	for _, b := range hijackBindings {
		if now.Sub(b.lastSeen) > hijackBindingTTL {
			continue
		}
		bindings++
		if now.Sub(b.lastFlag) <= hijackFlagLogWindow {
			flaggedRecent++
		}
	}
	return bindings, flaggedRecent
}
