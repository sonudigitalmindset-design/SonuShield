package server

// Behavior beacon endpoint (Batch 7).
//
// POST /_bProxy/behavior accepts the coarse interaction facts
// reported by the script appended to the proxy's own challenge
// pages (see firewall/behavior.go for what is collected and
// why). The beacon carries a short-lived random token issued
// when the challenge page was served, scoped to the domain, so
// arbitrary internet noise cannot pollute the verdict store.
// The token is NOT bound to the client IP: a verdict only ever
// applies to the beacon sender's own IP, and a "human" verdict
// confers no advantage, so IP binding would add complexity
// without changing the threat model. The token registry is
// bounded and tokens expire after 10 minutes.
//
// The beacon is accepted only when the domain has behaviorCheck
// enabled; otherwise the endpoint answers 404 like any unknown
// reserved path. Failures (bad token, malformed body, wrong
// method) answer with the same generic 404 and reveal nothing.

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/firewall"
)

const (
	behaviorTokenTTL  = 10 * time.Minute
	behaviorTokenMax  = 50000
	behaviorBodyMax   = 4 << 10 // 4 KB
	behaviorTokenSize = 16
)

type behaviorTokenEntry struct {
	domain  string
	expires time.Time
}

var (
	behaviorTokensMu sync.Mutex
	behaviorTokens   = map[string]behaviorTokenEntry{}
)

// issueBehaviorToken mints a random token scoped to one domain.
// It returns "" when the registry is full (fail-open: the page
// is served without a beacon script) or randomness fails.
func issueBehaviorToken(domain string) string {
	if domain == "" {
		return ""
	}
	raw := make([]byte, behaviorTokenSize)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	token := hex.EncodeToString(raw)
	behaviorTokensMu.Lock()
	defer behaviorTokensMu.Unlock()
	if len(behaviorTokens) >= behaviorTokenMax {
		return ""
	}
	behaviorTokens[token] = behaviorTokenEntry{
		domain:  domain,
		expires: time.Now().Add(behaviorTokenTTL),
	}
	return token
}

// validateBehaviorToken reports whether token was issued for
// domain and has not expired. Expired tokens are dropped.
func validateBehaviorToken(token, domain string) bool {
	behaviorTokensMu.Lock()
	defer behaviorTokensMu.Unlock()
	entry, ok := behaviorTokens[token]
	if !ok || entry.domain != domain {
		return false
	}
	if time.Now().After(entry.expires) {
		delete(behaviorTokens, token)
		return false
	}
	return true
}

// behaviorBeaconScript returns the <script> block appended to a
// challenge page, or "" when the feature is disabled for the
// domain or no token could be issued. The script records only
// three booleans/buckets (mouse moved, page scrolled, elapsed
// bucket) and reports them with sendBeacon when the page is
// left. No coordinates, no keystrokes, no identifiers.
func behaviorBeaconScript(settings domains.DomainSettings, domainName string) string {
	if !settings.BehaviorCheck {
		return ""
	}
	token := issueBehaviorToken(domainName)
	if token == "" {
		return ""
	}
	return `<script>(function(){var t0=Date.now(),m=false,s=false;addEventListener('mousemove',function(){m=true},{once:true,passive:true});addEventListener('scroll',function(){s=true},{once:true,passive:true});addEventListener('pagehide',function(){var e=Date.now()-t0,b='fast';if(e>5000){b='slow'}else if(e>1500){b='medium'}try{navigator.sendBeacon('/_bProxy/behavior','t=` + token + `&m='+(m?1:0)+'&s='+(s?1:0)+'&e='+b)}catch(_){}});})();</script>`
}

// withBehaviorScript inserts the beacon script into a challenge
// page's HTML, just before </body> when present, otherwise at
// the end. Pages are returned unchanged when the feature is
// disabled.
func withBehaviorScript(page string, settings domains.DomainSettings, domainName string) string {
	script := behaviorBeaconScript(settings, domainName)
	if script == "" {
		return page
	}
	if idx := strings.LastIndex(page, "</body>"); idx >= 0 {
		return page[:idx] + script + page[idx:]
	}
	return page + script
}

// HandleBehaviorBeacon answers POST /_bProxy/behavior. It
// returns true when the request targeted the beacon path, even
// on failure (the response is always written). All other paths
// return false so the caller continues.
func HandleBehaviorBeacon(writer http.ResponseWriter, request *http.Request, domainName, ip string, settings domains.DomainSettings) bool {
	if request.URL.Path != "/_bProxy/behavior" {
		return false
	}
	if request.Method != http.MethodPost || !settings.BehaviorCheck {
		// Generic 404: the endpoint does not exist for
		// callers who should not know about it.
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte("404 Not Found"))
		return true
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, behaviorBodyMax+1))
	if err != nil || len(body) > behaviorBodyMax {
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte("404 Not Found"))
		return true
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || !validateBehaviorToken(values.Get("t"), domainName) {
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte("404 Not Found"))
		return true
	}
	firewall.RecordBehavior(domainName, ip, values.Get("m") == "1", values.Get("s") == "1", values.Get("e"))
	writer.WriteHeader(http.StatusNoContent)
	return true
}
