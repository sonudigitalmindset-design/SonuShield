package domains

// Waiting room (Batch 4).
//
// When enabled and bypassed traffic exceeds the configured
// threshold, new visitors are queued fairly (first-come,
// first-served) instead of being dropped or challenged harder.
// Queued visitors get a generic waiting page that refreshes
// itself; as load allows, the front of the queue is admitted.
//
// State is per domain and in memory only. Queue membership is
// tracked with two signed cookies, both bound to the client IP
// with an HMAC-SHA256 key that is random per process:
//
//   - The queue cookie carries the join timestamp. A visitor's
//     position is the number of queued entries that joined
//     earlier, so positions are stable and fair.
//   - The admitted cookie carries an expiry (10 minutes). Once
//     admitted, a visitor passes without re-queueing until it
//     expires.
//
// The queue is capped (5,000 entries); beyond that, new visitors
// get a plain 503 with Retry-After instead of joining a queue
// that would never drain. Entries older than 15 minutes are
// pruned. When traffic falls back under the threshold, everyone
// passes immediately — the queue only ever gates excess traffic.
// The waiting room never activates for normal traffic, and with
// no threshold configured it does not exist (nil).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultWaitingRoomAdmit = 20
	maxWaitingRoomQueue     = 5000
	waitingRoomEntryTTL     = 15 * time.Minute
	waitingRoomAdmitTTL     = 10 * time.Minute
)

// waitingRoomKey signs queue/admit cookies. Random per process:
// cookies from a previous process (or a forged one) never verify.
var waitingRoomKey = func() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand failing is effectively impossible; fall
		// back to a time-derived key rather than no key.
		return []byte(strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	return key
}()

// WaitingRoom is one domain's queue state.
type WaitingRoom struct {
	mu        sync.Mutex
	queue     map[string]time.Time // token -> join time
	threshold int
	admit     int
}

// NewWaitingRoom builds a waiting room from the domain config, or
// nil when the waiting room is disabled (not enabled, or no
// positive threshold).
func NewWaitingRoom(enabled bool, threshold, admit int) *WaitingRoom {
	if !enabled || threshold <= 0 {
		return nil
	}
	if admit <= 0 {
		admit = defaultWaitingRoomAdmit
	}
	return &WaitingRoom{
		queue:     map[string]time.Time{},
		threshold: threshold,
		admit:     admit,
	}
}

// WaitingDecision is the outcome of evaluating one request.
type WaitingDecision struct {
	Pass           bool
	Position       int // 1-based queue position when not passing
	Full           bool
	QueueCookie    *http.Cookie
	AdmittedCookie *http.Cookie
}

// Evaluate decides whether a request passes, queues, or is turned
// away because the queue is full. It is safe on a nil *WaitingRoom
// (feature disabled): every request passes.
func (w *WaitingRoom) Evaluate(r *http.Request, ip string, bypassedRPS int) WaitingDecision {
	if w == nil || bypassedRPS < w.threshold {
		return WaitingDecision{Pass: true}
	}

	now := time.Now()

	if isValidAdmitCookie(r, ip, now) {
		return WaitingDecision{Pass: true}
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Prune stale entries so the queue cannot fill with ghosts.
	for token, joined := range w.queue {
		if now.Sub(joined) > waitingRoomEntryTTL {
			delete(w.queue, token)
		}
	}

	// A visitor already in the queue keeps their place.
	if token, joined, ok := validQueueCookie(r, ip, now); ok {
		if _, known := w.queue[token]; !known {
			// Pruned between requests (or a restart kept the
			// cookie): rejoin at the back with the original
			// join time, so the visitor is not punished.
			w.queue[token] = joined
		}
		position := 1
		for _, other := range w.queue {
			if other.Before(joined) {
				position++
			}
		}
		if position <= w.admit {
			delete(w.queue, token)
			return WaitingDecision{Pass: true, AdmittedCookie: admitCookie(ip, now, r.TLS != nil)}
		}
		return WaitingDecision{Position: position}
	}

	if len(w.queue) >= maxWaitingRoomQueue {
		return WaitingDecision{Full: true}
	}
	token := queueToken(ip, now)
	w.queue[token] = now
	return WaitingDecision{Position: len(w.queue), QueueCookie: queueCookie(token, r.TLS != nil)}
}

func signWaitingPayload(parts ...string) string {
	mac := hmac.New(sha256.New, waitingRoomKey)
	for _, p := range parts {
		mac.Write([]byte(p))
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func queueToken(ip string, now time.Time) string {
	payload := strconv.FormatInt(now.UnixNano(), 10)
	sig := signWaitingPayload("queue", ip, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + sig))
}

func queueCookie(token string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     "__bProxy_q",
		Value:    token,
		Path:     "/",
		MaxAge:   int(waitingRoomEntryTTL.Seconds()),
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func admitCookie(ip string, now time.Time, secure bool) *http.Cookie {
	expiry := now.Add(waitingRoomAdmitTTL)
	payload := strconv.FormatInt(expiry.Unix(), 10)
	sig := signWaitingPayload("admit", ip, payload)
	token := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + sig))
	return &http.Cookie{
		Name:     "__bProxy_qa",
		Value:    token,
		Path:     "/",
		MaxAge:   int(waitingRoomAdmitTTL.Seconds()),
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// validQueueCookie parses and verifies the queue cookie. It
// returns the raw token (the queue map key) and the join time.
func validQueueCookie(r *http.Request, ip string, now time.Time) (string, time.Time, bool) {
	cookie, err := r.Cookie("__bProxy_q")
	if err != nil || cookie.Value == "" {
		return "", time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", time.Time{}, false
	}
	payload, sig, ok := strings.Cut(string(raw), ".")
	if !ok {
		return "", time.Time{}, false
	}
	want := signWaitingPayload("queue", ip, payload)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", time.Time{}, false
	}
	nanos, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	joined := time.Unix(0, nanos)
	if joined.After(now) || now.Sub(joined) > waitingRoomEntryTTL {
		return "", time.Time{}, false
	}
	return cookie.Value, joined, true
}

func isValidAdmitCookie(r *http.Request, ip string, now time.Time) bool {
	cookie, err := r.Cookie("__bProxy_qa")
	if err != nil || cookie.Value == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return false
	}
	payload, sig, ok := strings.Cut(string(raw), ".")
	if !ok {
		return false
	}
	want := signWaitingPayload("admit", ip, payload)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	expiry, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return false
	}
	return now.Unix() < expiry && expiry <= now.Add(waitingRoomAdmitTTL+time.Minute).Unix()
}
