package api

// Public API v1 (Batch 6): the tenant/reseller-facing read API,
// deliberately distinct from the internal control API
// (/_bProxy/api/v2/*):
//
//   - REST paths under /_bProxy/public/v1/, versioned in the
//     URL so a future v2 can coexist.
//   - API-key auth (Bearer token or X-API-Key header) with one
//     tenant per key, config-file-only keys. A key reads only
//     its own tenant: there is no tenant parameter to tamper
//     with, and domains outside the tenant 404 exactly like
//     nonexistent ones.
//   - Per-key fixed-window rate limits with standard
//     X-RateLimit-* headers and Retry-After on 429.
//   - A stable JSON envelope: {"ok":true,"data":...} on
//     success, {"ok":false,"error":{"code","message"}} on
//     failure, with matching HTTP status codes.
//   - Read-only. v1 exposes usage and domain status only;
//     nothing here changes proxy state, so reads are not
//     audit-logged (the control API audits state changes).
//
// Endpoints:
//
//	GET /_bProxy/public/v1/ping    — auth check; returns the key's tenant and name
//	GET /_bProxy/public/v1/usage   — tenant usage aggregate; ?domain= filters to one of the tenant's domains
//	GET /_bProxy/public/v1/domains — the tenant's domains with stage and counters
//
// Challenge interaction: a request carrying a valid public key
// is exempt from the challenge flow (see
// AuthenticatedControlRequest), exactly like a
// secret-authenticated control request. A missing or wrong key
// keeps the normal fall-through behavior: at Stage 0 the
// handler answers 401 JSON; under attack the request may be
// challenged first, same as the control API.
//
// Keys are never logged and never appear in responses or
// errors. The rate limiter keys windows by the SHA-256 of the
// key, never the key itself.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/utils"
)

const publicAPIPrefix = "/_bProxy/public/"

// publicRateWindow is the fixed rate-limit window. A var so
// tests can shorten it.
var publicRateWindow = time.Minute

type publicError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type publicEnvelope struct {
	OK    bool         `json:"ok"`
	Data  interface{}  `json:"data,omitempty"`
	Error *publicError `json:"error,omitempty"`
}

type publicUsage struct {
	Tenant     string   `json:"tenant"`
	Requests   int64    `json:"requests"`
	Blocked    int64    `json:"blocked"`
	BytesIn    int64    `json:"bytes_in"`
	BytesOut   int64    `json:"bytes_out"`
	BytesTotal int64    `json:"bytes_total"`
	Domains    []string `json:"domains"`
}

type publicDomain struct {
	Name        string `json:"name"`
	Stage       int    `json:"stage"`
	StageName   string `json:"stage_name"`
	StageLocked bool   `json:"stage_locked"`
	UnderAttack bool   `json:"under_attack"`
	Requests    int64  `json:"requests"`
	Blocked     int64  `json:"blocked"`
	BytesTotal  int64  `json:"bytes_total"`
}

// resolvePublicKey authenticates a request against the
// configured public API keys. The key travels as
// "Authorization: Bearer <key>" (preferred) or "X-API-Key:
// <key>". Every configured key is compared in constant time;
// short keys never match.
func resolvePublicKey(r *http.Request) (domains.PublicAPIKey, bool) {
	provided := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		provided = strings.TrimPrefix(auth, "Bearer ")
	} else {
		provided = r.Header.Get("X-API-Key")
	}
	if provided == "" || domains.Config == nil {
		return domains.PublicAPIKey{}, false
	}
	var matched domains.PublicAPIKey
	found := false
	for _, key := range domains.Config.Proxy.PublicAPIKeys {
		if len(key.Key) < domains.MinPublicAPIKeyLength {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(key.Key)) == 1 {
			matched = key
			found = true
		}
	}
	return matched, found
}

type publicRateWindowState struct {
	count int
	reset time.Time
}

var publicRateLimiter = struct {
	mu      sync.Mutex
	windows map[[32]byte]*publicRateWindowState
}{windows: map[[32]byte]*publicRateWindowState{}}

// publicRateAllowed applies the caller's fixed-window budget.
// It returns whether the request may proceed, the remaining
// budget in the current window, and the window reset time.
func publicRateAllowed(key domains.PublicAPIKey) (bool, int, time.Time) {
	limit := key.EffectiveRateLimit()
	sum := sha256.Sum256([]byte(key.Key))
	now := time.Now()
	publicRateLimiter.mu.Lock()
	defer publicRateLimiter.mu.Unlock()
	win, ok := publicRateLimiter.windows[sum]
	if !ok || !now.Before(win.reset) {
		win = &publicRateWindowState{count: 1, reset: now.Add(publicRateWindow)}
		publicRateLimiter.windows[sum] = win
		return true, limit - 1, win.reset
	}
	if win.count >= limit {
		return false, 0, win.reset
	}
	win.count++
	return true, limit - win.count, win.reset
}

func writePublicJSON(w http.ResponseWriter, status int, payload interface{}) {
	body, err := json.Marshal(publicEnvelope{OK: true, Data: payload})
	if err != nil {
		writePublicError(w, http.StatusInternalServerError, "internal_error", "failed to encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writePublicError(w http.ResponseWriter, status int, code, message string) {
	body, _ := json.Marshal(publicEnvelope{OK: false, Error: &publicError{Code: code, Message: message}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ProcessPublic serves the public API. It returns false only
// when the path is outside the public prefix (the caller falls
// through); every path under the prefix is answered here, so a
// mistyped version or endpoint gets a JSON 404, never a
// proxied backend response.
func ProcessPublic(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, publicAPIPrefix) {
		return false
	}
	key, ok := resolvePublicKey(r)
	if !ok {
		writePublicError(w, http.StatusUnauthorized, "unauthorized", "a valid API key is required")
		return true
	}
	allowed, remaining, reset := publicRateAllowed(key)
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(key.EffectiveRateLimit()))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
	if !allowed {
		retry := int(time.Until(reset).Seconds()) + 1
		if retry < 1 {
			retry = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writePublicError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded; retry after the window resets")
		return true
	}
	if r.Method != http.MethodGet {
		writePublicError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is supported")
		return true
	}
	switch strings.TrimPrefix(r.URL.Path, publicAPIPrefix) {
	case "v1/ping":
		writePublicJSON(w, http.StatusOK, map[string]interface{}{
			"tenant":   key.EffectiveTenant(),
			"key_name": key.Name,
		})
	case "v1/usage":
		publicUsageHandler(w, r, key)
	case "v1/domains":
		publicDomainsHandler(w, key)
	default:
		writePublicError(w, http.StatusNotFound, "not_found", "unknown public API endpoint")
	}
	return true
}

// tenantDomainCounters aggregates one tenant's counters over
// the given domain names, with the same blocked approximation
// as the control API's usage response.
func tenantDomainCounters(names []string) (requests, blocked, bytesIn, bytesOut int64) {
	firewall.Mutex.RLock()
	defer firewall.Mutex.RUnlock()
	for _, name := range names {
		data := domains.DomainsData[name]
		requests += int64(data.TotalRequests)
		blocked += int64(data.TotalRequests) - int64(data.BypassedRequests)
		bytesIn += data.BytesIn
		bytesOut += data.BytesOut
	}
	if blocked < 0 {
		blocked = 0
	}
	return requests, blocked, bytesIn, bytesOut
}

func publicUsageHandler(w http.ResponseWriter, r *http.Request, key domains.PublicAPIKey) {
	tenant := key.EffectiveTenant()
	names := domains.TenantDomains()[tenant]
	sort.Strings(names)
	if selected := r.URL.Query().Get("domain"); selected != "" {
		found := false
		for _, name := range names {
			if name == selected {
				found = true
				break
			}
		}
		if !found {
			// Another tenant's domain 404s exactly like a
			// nonexistent one: no cross-tenant leakage.
			writePublicError(w, http.StatusNotFound, "not_found", "unknown domain")
			return
		}
		names = []string{selected}
	}
	requests, blocked, bytesIn, bytesOut := tenantDomainCounters(names)
	if names == nil {
		names = []string{}
	}
	writePublicJSON(w, http.StatusOK, publicUsage{
		Tenant:     tenant,
		Requests:   requests,
		Blocked:    blocked,
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
		BytesTotal: bytesIn + bytesOut,
		Domains:    names,
	})
}

func publicDomainsHandler(w http.ResponseWriter, key domains.PublicAPIKey) {
	names := domains.TenantDomains()[key.EffectiveTenant()]
	sort.Strings(names)
	firewall.Mutex.RLock()
	defer firewall.Mutex.RUnlock()
	list := []publicDomain{}
	for _, name := range names {
		data := domains.DomainsData[name]
		blocked := int64(data.TotalRequests) - int64(data.BypassedRequests)
		if blocked < 0 {
			blocked = 0
		}
		list = append(list, publicDomain{
			Name:        name,
			Stage:       data.Stage,
			StageName:   utils.StageToString(data.Stage),
			StageLocked: data.StageManuallySet,
			UnderAttack: data.RawAttack || data.BypassAttack,
			Requests:    int64(data.TotalRequests),
			Blocked:     blocked,
			BytesTotal:  data.BytesIn + data.BytesOut,
		})
	}
	writePublicJSON(w, http.StatusOK, map[string]interface{}{
		"tenant":  key.EffectiveTenant(),
		"domains": list,
	})
}
