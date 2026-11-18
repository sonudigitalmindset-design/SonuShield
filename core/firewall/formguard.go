package firewall

// Form spam guard (Batch 7).
//
// An opt-in, per-path guard for POST endpoints. The operator
// lists guarded path prefixes (formGuard.paths) and adds one
// hidden honeypot field to their forms; the proxy then checks
// three signals:
//
//   - Honeypot: the named field (default "website") must be
//     empty. Bots that fill every field trip it; humans never
//     see it.
//   - Submission timing: GETs to guarded paths receive a
//     signed timestamp cookie (__bProxy_fg). A POST that
//     arrives impossibly fast after the form was served
//     (under formGuard.minSeconds, default 3) is spam. A
//     missing, expired, or invalid cookie NEVER condemns a
//     request on its own — cookieless clients, cleared
//     cookies, and direct POSTs simply skip the timing check.
//   - Per-form rate limit: more than formGuard.maxPerMinute
//     POSTs (default 30) from one IP to one guarded path in a
//     60-second window is spam.
//
// Mode "log" (the default, and the fallback for any unknown
// mode) only logs; mode "block" answers with a generic 403.
// Only URL-encoded bodies are inspected for the honeypot and
// timing signals; multipart bodies get the rate limit only.
// Bodies are always restored after inspection so proxying is
// unaffected. The bounds are deliberately generous so
// legitimate forms — including fast typists and password
// managers — are not disturbed.
//
// The timestamp cookie is signed with a process-random key:
// it proves only that this proxy served the form recently,
// and it is worthless after a restart (which simply disables
// the timing check until the next GET).

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
)

const (
	formGuardCookieName          = "__bProxy_fg"
	formGuardMaxBody             = 1 << 20 // 1 MB
	formGuardCookieTTL           = 24 * time.Hour
	formGuardDefaultMinSeconds   = 3
	formGuardDefaultMaxPerMinute = 30
)

var formGuardKey []byte

func init() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err == nil {
		formGuardKey = key
	}
	// On randomness failure the key stays nil and no cookie
	// is ever issued: the timing check simply never fires.
}

// formGuardSign returns the cookie value for a timestamp, or
// "" when no signing key is available.
func formGuardSign(ts int64) string {
	if formGuardKey == nil {
		return ""
	}
	raw := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, formGuardKey)
	mac.Write([]byte(raw))
	return raw + "." + hex.EncodeToString(mac.Sum(nil))
}

// formGuardAge verifies a cookie value and returns the age of
// the timestamp it carries. ok is false for any malformed,
// tampered, stale, or future-dated value.
func formGuardAge(value string) (age time.Duration, ok bool) {
	if formGuardKey == nil || value == "" {
		return 0, false
	}
	raw, sig, found := strings.Cut(value, ".")
	if !found || sig == "" {
		return 0, false
	}
	mac := hmac.New(sha256.New, formGuardKey)
	mac.Write([]byte(raw))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return 0, false
	}
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	issued := time.Unix(ts, 0)
	now := time.Now()
	if issued.After(now.Add(time.Minute)) || now.Sub(issued) > formGuardCookieTTL {
		return 0, false
	}
	return now.Sub(issued), true
}

// MaybeSetFormGuardCookie sets the signed timestamp cookie on
// a GET response when the path is guarded. It is a no-op for
// unguarded paths and when no signing key is available.
func MaybeSetFormGuardCookie(writer http.ResponseWriter, paths []string, requestPath string) {
	if !pathUnderPrefixes(requestPath, paths) {
		return
	}
	value := formGuardSign(time.Now().Unix())
	if value == "" {
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     formGuardCookieName,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// CheckFormGuard evaluates a POST to a guarded path. It
// returns spam=true with a reason ("honeypot", "timing", or
// "ratelimit") when a signal fires. Unguarded paths, non-POST
// methods, and oversized bodies return spam=false. The body
// is restored (with GetBody) whenever it is read.
func CheckFormGuard(request *http.Request, settings domains.FormGuardConfig, ip string) (spam bool, reason string) {
	if request.Method != http.MethodPost || !pathUnderPrefixes(request.URL.Path, settings.Paths) {
		return false, ""
	}
	if formGuardRateExceeded(ip, request.URL.Path, settings.MaxPerMinute) {
		return true, "ratelimit"
	}
	mediaType, _, _ := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" {
		return false, ""
	}
	body := readAndRestoreFormBody(request)
	if body == "" {
		return false, ""
	}
	values, err := url.ParseQuery(body)
	if err != nil {
		return false, ""
	}
	field := settings.HoneypotField
	if field == "" {
		field = "website"
	}
	if values.Get(field) != "" {
		return true, "honeypot"
	}
	minSeconds := settings.MinSeconds
	if minSeconds <= 0 {
		minSeconds = formGuardDefaultMinSeconds
	}
	if cookie, err := request.Cookie(formGuardCookieName); err == nil {
		if age, ok := formGuardAge(cookie.Value); ok && age < time.Duration(minSeconds)*time.Second {
			return true, "timing"
		}
	}
	return false, ""
}

// readAndRestoreFormBody reads a small POST body and restores
// it (with GetBody for replay-safe retries). It returns "" for
// bodies that are absent, oversized, or unreadable.
func readAndRestoreFormBody(request *http.Request) string {
	if request.Body == nil {
		return ""
	}
	if request.ContentLength <= 0 || request.ContentLength > formGuardMaxBody {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, formGuardMaxBody+1))
	if err != nil || len(body) > formGuardMaxBody {
		return ""
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return string(body)
}

type formWindow struct {
	start time.Time
	count int
}

var formGuardHits = struct {
	sync.Mutex
	counts map[string]*formWindow
}{counts: map[string]*formWindow{}}

// formGuardRateExceeded counts one POST from ip to path in a
// 60-second window and reports whether the limit is exceeded.
func formGuardRateExceeded(ip, path string, maxPerMinute int) bool {
	if maxPerMinute <= 0 {
		maxPerMinute = formGuardDefaultMaxPerMinute
	}
	key := ip + "\x00" + path
	now := time.Now()
	formGuardHits.Lock()
	defer formGuardHits.Unlock()
	window, ok := formGuardHits.counts[key]
	if !ok || now.Sub(window.start) >= time.Minute {
		formGuardHits.counts[key] = &formWindow{start: now, count: 1}
		if len(formGuardHits.counts) > 10000 {
			for k, entry := range formGuardHits.counts {
				if now.Sub(entry.start) >= 2*time.Minute {
					delete(formGuardHits.counts, k)
				}
			}
		}
		return false
	}
	window.count++
	return window.count > maxPerMinute
}
