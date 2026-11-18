package server

// Optional memory-hard proof-of-work for Stage 2, replacing the
// classic hash puzzle when the operator enables memoryHardPow for
// a domain. The puzzle is Argon2id: the browser searches for a
// counter whose Argon2id output has N leading zero bits, and the
// server verifies with a single Argon2id computation. A
// memory-hard puzzle raises the cost of large-scale solving
// farms (memory, not just CPU) while staying cheap to verify.
//
// Off by default; the classic puzzle stays the default. The
// provider challenge (Turnstile/hCaptcha), when configured,
// takes precedence over this one. Parameters are config-file
// only (see docs/configuration.md); the API reports them
// read-only via GET_DOMAIN_FEATURES.
//
// Defaults and bounds (0 means "unset" and selects the default):
//   - memoryHardPowBits:   default 4, clamped to 1..8. Each bit
//     doubles the expected solve time.
//   - memoryHardPowMemoryKB: default 512, clamped to 256..8192.
//     The browser allocates this much memory per attempt.
//   - memoryHardPowTime:   default 1, clamped to 1..3 passes.
//
// Measured solve cost (V8 on a laptop-class CPU, single attempt):
// ~16 ms at 256 KiB, ~31 ms at 512 KiB, ~67 ms at 1024 KiB.
// At the defaults (4 bits, 512 KiB, 1 pass) the expected solve
// is ~0.5 s on a laptop and roughly 1-2 s on a phone. Operators
// must not combine high values: 8 bits at 8192 KiB with 3 passes
// would take minutes on a phone. The clamps bound the worst
// case; the docs carry the warning.
//
// The browser solver is pure JavaScript (argon2pow.js, embedded
// below): no WASM blob, no CDN, no WebCrypto. It implements
// Blake2b and Argon2id from RFC 7693 / RFC 9106 and is verified
// against golang.org/x/crypto/argon2 output; any change to the
// solver must re-run that comparison before shipping.
//
// Flow (mirrors the provider challenge in challenge.go, no new
// cookie names, no new management paths):
//
//  1. Middleware serves the memory-hard page for a Stage 2
//     request and stores a single-use random nonce bound to the
//     client's IP, TLS fingerprint and User-Agent, together with
//     the random salt, the parameters, and the encrypted
//     challenge token the client must end up holding.
//  2. The page solves the puzzle in JavaScript and POSTs nonce +
//     solution to /_bProxy/pow-verify (a reserved path like
//     /_bProxy/verified, handled before the cookie check because
//     the client has no cookie yet).
//  3. The server recomputes one Argon2id and checks the leading
//     zero bits. On success it sets the same __bProxy_v cookie
//     the proof-of-work flow sets and redirects to the original
//     URL. On failure it answers with a short generic plain-text
//     error (fail-closed); nothing is rendered.
//
// Verification costs one Argon2id per submission, and a
// submission requires a fresh single-use nonce (one challenge
// page fetch, itself behind the rate limits), so flooding the
// endpoint is bounded by the cost of fetching challenge pages.
// The pending map is capped with the same opportunistic purge
// as the provider challenges.

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/logging"
)

//go:embed argon2pow.js
var argon2powJS string

// Memory-hard PoW defaults and clamps. Zero in the config means
// "unset" and selects the default.
const (
	memoryPowDefaultBits   = 4
	memoryPowMinBits       = 1
	memoryPowMaxBits       = 8
	memoryPowDefaultMemory = 512 // KiB
	memoryPowMinMemory     = 256 // KiB
	memoryPowMaxMemory     = 8192 // KiB
	memoryPowDefaultTime   = 1
	memoryPowMinTime       = 1
	memoryPowMaxTime       = 3
)

type pendingMemoryPow struct {
	encryptedIP string
	redirectURL string
	salt        []byte
	bits        uint32
	memoryKB    uint32
	timeCost    uint32
	ip          string
	tlsFp       string
	userAgent   string
	markers     bool
	expires     time.Time
}

// pendingMemoryPowChallenges holds not-yet-verified memory-hard
// challenges, keyed by nonce. Entries are single-use and expire
// after 10 minutes (challengeNonceTTL, shared with the provider
// challenges).
var pendingMemoryPowChallenges = sync.Map{}

// memoryPowParams resolves the effective parameters for a domain,
// applying defaults for unset values and clamping the rest. The
// clamps run in the int domain: converting a negative value to
// uint32 first would wrap it to a huge number and clamp to the
// maximum instead of the minimum.
func memoryPowParams(settings domains.DomainSettings) (bits, memoryKB, timeCost uint32) {
	bits = memoryPowDefaultBits
	if settings.MemoryHardPowBits != 0 {
		v := settings.MemoryHardPowBits
		if v < memoryPowMinBits {
			v = memoryPowMinBits
		}
		if v > memoryPowMaxBits {
			v = memoryPowMaxBits
		}
		bits = uint32(v)
	}
	memoryKB = memoryPowDefaultMemory
	if settings.MemoryHardPowMemory != 0 {
		v := settings.MemoryHardPowMemory
		if v < memoryPowMinMemory {
			v = memoryPowMinMemory
		}
		if v > memoryPowMaxMemory {
			v = memoryPowMaxMemory
		}
		memoryKB = uint32(v)
	}
	timeCost = memoryPowDefaultTime
	if settings.MemoryHardPowTime != 0 {
		v := settings.MemoryHardPowTime
		if v < memoryPowMinTime {
			v = memoryPowMinTime
		}
		if v > memoryPowMaxTime {
			v = memoryPowMaxTime
		}
		timeCost = uint32(v)
	}
	return bits, memoryKB, timeCost
}

func storePendingMemoryPow(entry pendingMemoryPow) string {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return ""
	}
	nonce := hex.EncodeToString(nonceBytes)
	entry.expires = time.Now().Add(challengeNonceTTL)
	pendingMemoryPowChallenges.Store(nonce, entry)

	// Opportunistic purge so a flood of challenge pages cannot grow
	// the map without bound. Lazy expiry on lookup handles the rest.
	count := 0
	pendingMemoryPowChallenges.Range(func(_, _ any) bool {
		count++
		return count <= 4096
	})
	if count > 4096 {
		now := time.Now()
		pendingMemoryPowChallenges.Range(func(key, value any) bool {
			if entry, ok := value.(pendingMemoryPow); ok && now.After(entry.expires) {
				pendingMemoryPowChallenges.Delete(key)
			}
			return true
		})
	}
	return nonce
}

func takePendingMemoryPow(nonce, ip, tlsFp, userAgent string) (pendingMemoryPow, bool) {
	value, ok := pendingMemoryPowChallenges.LoadAndDelete(nonce)
	if !ok {
		return pendingMemoryPow{}, false
	}
	entry, ok := value.(pendingMemoryPow)
	if !ok || time.Now().After(entry.expires) {
		return pendingMemoryPow{}, false
	}
	// The nonce is bound to the client it was issued to.
	if entry.ip != ip || entry.tlsFp != tlsFp || entry.userAgent != userAgent {
		return pendingMemoryPow{}, false
	}
	return entry, true
}

// memoryPowSolutionValid recomputes one Argon2id over the
// password "saltHex:solution" (the exact construction the
// JavaScript solver uses) and reports whether the output has the
// required leading zero bits.
func memoryPowSolutionValid(salt []byte, solution string, bits, memoryKB, timeCost uint32) bool {
	password := hex.EncodeToString(salt) + ":" + solution
	key := argon2.IDKey([]byte(password), salt, timeCost, memoryKB, 1, 32)
	full := bits / 8
	for i := uint32(0); i < full; i++ {
		if key[i] != 0 {
			return false
		}
	}
	if rem := bits % 8; rem != 0 {
		if key[full]>>(8-rem) != 0 {
			return false
		}
	}
	return true
}

// ServeMemoryPowChallenge renders the memory-hard Stage 2 page.
// It stores a single-use nonce and returns silently (rendering
// nothing) only when nonce or salt generation fails, in which
// case the caller falls back to the classic proof-of-work page.
func ServeMemoryPowChallenge(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings, domainName, encryptedIP, ip, tlsFp, userAgent string) bool {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return false
	}
	bits, memoryKB, timeCost := memoryPowParams(settings)
	nonce := storePendingMemoryPow(pendingMemoryPow{
		encryptedIP: encryptedIP,
		redirectURL: safeRedirectTarget(request.URL.RequestURI()),
		salt:        salt,
		bits:        bits,
		memoryKB:    memoryKB,
		timeCost:    timeCost,
		ip:          ip,
		tlsFp:       tlsFp,
		userAgent:   userAgent,
		markers:     settings.InvisibleMarkers,
	})
	if nonce == "" {
		return false
	}

	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	//Built-in page text is English/Hindi by Accept-Language.
	fmt.Fprint(writer, withBehaviorScript(withInvisibleMarkers(memoryPowPage(stringsFor(request), resolveBranding(settings), nonce, hex.EncodeToString(salt), bits, memoryKB, timeCost, settings.InvisibleMarkers), settings, domainName), settings, domainName))
	return true
}

// HandleMemoryPowVerify answers POST /_bProxy/pow-verify. It always
// writes a response (redirect on success, short generic plain-text
// error otherwise) and reports whether it handled the request.
// Non-POST requests get a plain 404; no page is ever rendered here.
func HandleMemoryPowVerify(writer http.ResponseWriter, request *http.Request, domainName, ip, tlsFp string) bool {
	if request.URL.Path != "/_bProxy/pow-verify" {
		return false
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, "404 Not Found")
		return true
	}
	if err := request.ParseForm(); err != nil {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "Bad request.")
		return true
	}

	entry, ok := takePendingMemoryPow(request.Form.Get("nonce"), ip, tlsFp, request.UserAgent())
	if !ok {
		// Unknown, expired, replayed, or client-mismatched nonce.
		// Answer generically without revealing which.
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, "404 Not Found")
		return true
	}

	// Honeypot form field (Batch 7): honoured only when the
	// challenge was served with markers enabled. A filled
	// field fails verification generically and marks the IP
	// as automated for the domain.
	if entry.markers && request.Form.Get("website") != "" {
		firewall.MarkMarkerHit(domainName, ip)
		logging.Log(logging.Entry{Event: "marker", Domain: domainName, IP: ip, Action: "marker_honeypot", Method: request.Method, Path: "/_bProxy/pow-verify", UserAgent: request.UserAgent()})
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, "404 Not Found")
		return true
	}

	// The solution is a decimal counter. Reject anything else
	// before spending an Argon2id computation on it.
	solution := request.Form.Get("solution")
	valid := len(solution) > 0 && len(solution) <= 20
	for i := 0; valid && i < len(solution); i++ {
		if solution[i] < '0' || solution[i] > '9' {
			valid = false
		}
	}
	if !valid || !memoryPowSolutionValid(entry.salt, solution, entry.bits, entry.memoryKB, entry.timeCost) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusForbidden)
		fmt.Fprint(writer, "Verification failed. Please go back and try again.")
		return true
	}

	// Same cookie the proof-of-work flow sets, then back to the original URL.
	// Deliberately NOT HttpOnly: the proof-of-work page sets
	// this same cookie from JavaScript, and a script cannot
	// overwrite an HttpOnly cookie. See challenge.go and
	// docs/security-audit.md (M-4).
	writer.Header().Set("Set-Cookie", "__bProxy_v="+entry.encryptedIP+"; SameSite=Lax; path=/; Secure")
	http.Redirect(writer, request, entry.redirectURL, http.StatusFound)
	return true
}

// memoryPowPage renders the built-in memory-hard Stage 2 page: the
// same loader and message as the classic proof-of-work page, a
// form the solver submits, and the embedded Argon2id solver with
// the salt and parameters substituted. The solver script is fixed
// server-side content; the page carries no branding.
func memoryPowPage(s pageStrings, brand domains.Branding, nonce, saltHex string, bits, memoryKB, timeCost uint32, markers bool) string {
	script := strings.ReplaceAll(argon2powJS, "__ARGON_SALT_HEX__", saltHex)
	script = strings.ReplaceAll(script, "__ARGON_BITS__", strconv.FormatUint(uint64(bits), 10))
	script = strings.ReplaceAll(script, "__ARGON_MEMORY_KB__", strconv.FormatUint(uint64(memoryKB), 10))
	script = strings.ReplaceAll(script, "__ARGON_TIME__", strconv.FormatUint(uint64(timeCost), 10))
	// Honeypot form field (Batch 7): present only when the
	// domain enabled invisible markers.
	honeypot := ""
	if markers {
		honeypot = markerHoneypotField
	}
	return `<!doctype html><html lang="` +
		s.lang +
		`"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` +
		s.powTitle +
		`</title><style>body,html{height:100%;width:100%;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center;background-color:#f0f0f0;font-family:Arial,sans-serif}.loader{display:flex;justify-content:space-around;align-items:center;width:100px;height:100px;animation:pageIn .5s cubic-bezier(.22,1,.36,1)}.loader div{width:20px;height:20px;background-color:#333;border-radius:50%;animation:dotPulse 1.6s cubic-bezier(.45,0,.55,1) infinite}.loader div:nth-child(2){animation-delay:.2s}.loader div:nth-child(3){animation-delay:.4s}@keyframes dotPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(.82)}}@keyframes pageIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}.message{text-align:center;margin-top:20px;color:#333;animation:pageIn .5s .1s cubic-bezier(.22,1,.36,1) both}.subtext{text-align:center;color:#666;font-size:.9em;margin-top:5px}#mpow-status{animation:pageIn .5s .2s cubic-bezier(.22,1,.36,1) both}@media (prefers-reduced-motion:reduce){.loader,.loader div,.message,#mpow-status{animation:none}}</style>` +
		brandAccentOverride(brand, ".loader div{background-color:{accent}}") +
		`</head><body>` +
		brandBanner(brand) +
		`<div class="loader"><div></div><div></div><div></div></div><div class="message"><p>` +
		s.powMessage +
		`</p><div class="subtext">` +
		s.powSubtext +
		`</div></div><div class="subtext" id="mpow-status"></div><form id="mpow-form" method="post" action="/_bProxy/pow-verify"><input type="hidden" name="nonce" value="` +
		html.EscapeString(nonce) +
		`"><input type="hidden" name="solution" id="mpow-solution">` +
		honeypot +
		`</form><script>` +
		script +
		`</script><noscript><p>` +
		s.verifyNoJS +
		`</p></noscript></body></html>`
}
