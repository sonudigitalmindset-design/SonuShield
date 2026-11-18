package server

// Invisible markers (Batch 7).
//
// Two decoys that exist ONLY on challenge/verification pages
// the proxy itself serves — never in origin content:
//
//   - A hidden link, inserted just before </body> on every
//     built-in challenge page (classic PoW, captcha, provider,
//     memory-hard PoW) when invisibleMarkers is enabled for
//     the domain. The link points to /_bProxy/marker with a
//     short-lived random nonce scoped to the domain. A client
//     that follows it is recorded as automated: its IP is
//     blocked for the domain for one hour. The endpoint always
//     answers 404, valid nonce or not, so following the link
//     reveals nothing.
//   - A honeypot form field ("website") on the two real
//     verification forms (provider challenge, memory-hard
//     PoW). The field is hidden with CSS, removed from tab
//     order, and marked autocomplete=off; a submission with
//     the field filled fails verification generically. The
//     field is only honoured when the challenge was served
//     with markers enabled, so disabled domains behave
//     exactly as before.
//
// Custom page templates receive the same treatment as
// built-in pages: the proxy already appends fixed solver
// scripts to template renders, and the marker link is part of
// the page chrome, not the template's visible content. Origin
// content is never touched — markers exist only on pages the
// proxy itself serves.
//
// Marker hits fire a rate-limited operator notice (one per
// domain+IP per hour) over the existing alert channels.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/logging"
	"sonushield/core/utils"
)

const (
	markerNonceTTL   = 10 * time.Minute
	markerNonceMax   = 50000
	markerAlertEvery = time.Hour
)

// markerHoneypotField is the hidden input added to the
// verification forms. Its name is deliberately generic: a bot
// that fills every field trips it, a human never sees it.
const markerHoneypotField = `<input type="text" name="website" value="" style="display:none" tabindex="-1" autocomplete="off" aria-hidden="true">`

type markerNonceEntry struct {
	domain  string
	expires time.Time
}

var (
	markerNoncesMu  sync.Mutex
	markerNonces    = map[string]markerNonceEntry{}
	markerAlertMu   sync.Mutex
	markerAlertLast = map[string]time.Time{}
)

// issueMarkerNonce mints a random nonce scoped to one domain.
// It returns "" when the registry is full or randomness fails.
func issueMarkerNonce(domain string) string {
	if domain == "" {
		return ""
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	nonce := hex.EncodeToString(raw)
	markerNoncesMu.Lock()
	defer markerNoncesMu.Unlock()
	if len(markerNonces) >= markerNonceMax {
		return ""
	}
	markerNonces[nonce] = markerNonceEntry{
		domain:  domain,
		expires: time.Now().Add(markerNonceTTL),
	}
	return nonce
}

// validateMarkerNonce reports whether nonce was issued for
// domain and has not expired. Expired nonces are dropped.
func validateMarkerNonce(nonce, domain string) bool {
	markerNoncesMu.Lock()
	defer markerNoncesMu.Unlock()
	entry, ok := markerNonces[nonce]
	if !ok || entry.domain != domain {
		return false
	}
	if time.Now().After(entry.expires) {
		delete(markerNonces, nonce)
		return false
	}
	return true
}

// withInvisibleMarkers inserts the hidden marker link into a
// built-in challenge page's HTML, just before </body> when
// present, otherwise at the end. Pages are returned unchanged
// when the feature is disabled or no nonce could be issued.
func withInvisibleMarkers(page string, settings domains.DomainSettings, domainName string) string {
	if !settings.InvisibleMarkers {
		return page
	}
	nonce := issueMarkerNonce(domainName)
	if nonce == "" {
		return page
	}
	link := `<a href="/_bProxy/marker?n=` + nonce + `" style="display:none" tabindex="-1" aria-hidden="true"></a>`
	if idx := strings.LastIndex(page, "</body>"); idx >= 0 {
		return page[:idx] + link + page[idx:]
	}
	return page + link
}

// markerShouldAlert rate-limits marker notices to one per
// domain+IP per hour.
func markerShouldAlert(domain, ip string) bool {
	if domain == "" || ip == "" {
		return false
	}
	now := time.Now()
	key := domain + "\x00" + ip
	markerAlertMu.Lock()
	defer markerAlertMu.Unlock()
	if last, ok := markerAlertLast[key]; ok && now.Sub(last) < markerAlertEvery {
		return false
	}
	markerAlertLast[key] = now
	if len(markerAlertLast) > 50000 {
		for k, at := range markerAlertLast {
			if now.Sub(at) >= markerAlertEvery {
				delete(markerAlertLast, k)
			}
		}
	}
	return true
}

// HandleMarkerHit answers GET /_bProxy/marker. It returns true
// when the request targeted the marker path. A valid nonce
// records the IP as automated, logs the hit, and fires a
// rate-limited notice; the response is always a generic 404,
// whether or not the nonce was valid.
func HandleMarkerHit(writer http.ResponseWriter, request *http.Request, domainName, ip string, settings domains.DomainSettings) bool {
	if request.URL.Path != "/_bProxy/marker" {
		return false
	}
	if request.Method == http.MethodGet && settings.InvisibleMarkers &&
		validateMarkerNonce(request.URL.Query().Get("n"), domainName) {
		firewall.MarkMarkerHit(domainName, ip)
		logging.Log(logging.Entry{Event: "marker", Domain: domainName, IP: ip, Action: "marker_hit", Method: request.Method, Path: "/_bProxy/marker", UserAgent: request.UserAgent()})
		if markerShouldAlert(domainName, ip) {
			settingsCopy := settings
			go utils.SendNotice(settingsCopy, "Invisible marker tripped on "+domainName, "IP "+ip+" followed a hidden marker link on a challenge page. The IP is blocked for this domain for one hour.")
		}
	}
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusNotFound)
	_, _ = writer.Write([]byte("404 Not Found"))
	return true
}
