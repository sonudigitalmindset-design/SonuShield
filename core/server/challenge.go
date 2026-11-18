package server

// Optional Turnstile / hCaptcha challenge for Stage 2, replacing the
// proof-of-work page when the operator configures a provider with their
// own keys. Plumbing only: the feature is disabled unless
// challengeProvider, challengeSiteKey and challengeSecretKey are all set
// for a domain. No keys are bundled or invented; see docs/configuration.md
// for where the operator gets keys.
//
// The widget runs in the provider's invisible mode and executes
// automatically, so a legitimate visitor sees at most a brief generic
// "verifying" page and is then redirected. The provider may still show an
// interactive challenge when it judges one is needed; that decision is
// the provider's, not SonuShield's. The challenge page carries no product
// branding and the verification endpoint renders no page at all.
//
// Flow (mirrors the existing Stage 2 cookie mechanism, no new cookie
// names, no new management paths):
//
//  1. Middleware serves the provider page for a Stage 2 request and
//     stores a single-use random nonce bound to the client's IP, TLS
//     fingerprint and User-Agent, together with the encrypted challenge
//     token the client must end up holding.
//  2. The widget calls back with a token; the page POSTs nonce + token to
//     /_bProxy/challenge-verify (a reserved path like /_bProxy/verified,
//     handled before the cookie check because the client has no cookie
//     yet).
//  3. The server verifies the token with the provider. On success it sets
//     the same __bProxy_v cookie the proof-of-work flow sets and
//     redirects to the original URL. On failure it answers with a short
//     generic plain-text error (fail-closed); nothing is rendered.
//
// Provider verification endpoints (official siteverify APIs):
//   - Turnstile: https://challenges.cloudflare.com/turnstile/v0/siteverify
//   - hCaptcha:  https://hcaptcha.com/siteverify

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"sonushield/core/domains"
)

type pendingChallenge struct {
	encryptedIP string
	redirectURL string
	provider    string
	secretKey   string
	ip          string
	tlsFp       string
	userAgent   string
	expires     time.Time
}

// pendingChallenges holds not-yet-verified challenges, keyed by nonce.
// Entries are single-use and expire after 10 minutes.
var pendingChallenges = sync.Map{}

const challengeNonceTTL = 10 * time.Minute

// ChallengeProviderConfigured reports whether a domain has a usable
// challenge provider: a supported provider name plus both keys.
func ChallengeProviderConfigured(settings domains.DomainSettings) bool {
	if settings.ChallengeProvider != "turnstile" && settings.ChallengeProvider != "hcaptcha" {
		return false
	}
	return settings.ChallengeSiteKey != "" && settings.ChallengeSecretKey != ""
}

func storePendingChallenge(entry pendingChallenge) string {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return ""
	}
	nonce := hex.EncodeToString(nonceBytes)
	entry.expires = time.Now().Add(challengeNonceTTL)
	pendingChallenges.Store(nonce, entry)

	// Opportunistic purge so a flood of challenge pages cannot grow the
	// map without bound. Lazy expiry on lookup handles the rest.
	count := 0
	pendingChallenges.Range(func(_, _ any) bool {
		count++
		return count <= 4096
	})
	if count > 4096 {
		now := time.Now()
		pendingChallenges.Range(func(key, value any) bool {
			if entry, ok := value.(pendingChallenge); ok && now.After(entry.expires) {
				pendingChallenges.Delete(key)
			}
			return true
		})
	}
	return nonce
}

func takePendingChallenge(nonce, ip, tlsFp, userAgent string) (pendingChallenge, bool) {
	value, ok := pendingChallenges.LoadAndDelete(nonce)
	if !ok {
		return pendingChallenge{}, false
	}
	entry, ok := value.(pendingChallenge)
	if !ok || time.Now().After(entry.expires) {
		return pendingChallenge{}, false
	}
	// The nonce is bound to the client it was issued to.
	if entry.ip != ip || entry.tlsFp != tlsFp || entry.userAgent != userAgent {
		return pendingChallenge{}, false
	}
	return entry, true
}

// verifyProviderToken verifies a widget token with the provider's
// siteverify API. It returns (true, nil) when the provider confirms the
// token, (false, nil) when the provider rejects it, and (false, err) when
// the provider could not be reached or did not answer.
func verifyProviderToken(provider, secret, token, remoteIP string) (bool, error) {
	var endpoint string
	switch provider {
	case "turnstile":
		endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	case "hcaptcha":
		endpoint = "https://hcaptcha.com/siteverify"
	default:
		return false, fmt.Errorf("unsupported challenge provider %q", provider)
	}

	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(endpoint, form)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("provider returned status %d", resp.StatusCode)
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Success, nil
}

// ServeProviderChallenge renders the invisible provider widget page for a
// Stage 2 request. It stores a single-use nonce and returns silently
// (rendering nothing) only when nonce generation fails, in which case the
// caller falls back to the proof-of-work page.
func ServeProviderChallenge(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings, encryptedIP, ip, tlsFp, userAgent string) bool {
	nonce := storePendingChallenge(pendingChallenge{
		encryptedIP: encryptedIP,
		redirectURL: request.URL.RequestURI(),
		provider:    settings.ChallengeProvider,
		secretKey:   settings.ChallengeSecretKey,
		ip:          ip,
		tlsFp:       tlsFp,
		userAgent:   userAgent,
	})
	if nonce == "" {
		return false
	}

	siteKey := strconv.Quote(settings.ChallengeSiteKey)

	var widgetScript string
	if settings.ChallengeProvider == "turnstile" {
		widgetScript = `<script>function onloadChallenge(){var w=turnstile.render("#widget",{sitekey:` + siteKey + `,size:"invisible",callback:onSolved,"error-callback":onError});turnstile.execute(w);}</script><script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadChallenge" async defer></script>`
	} else {
		widgetScript = `<script>function onloadChallenge(){var w=hcaptcha.render("widget",{sitekey:` + siteKey + `,size:"invisible",callback:onSolved,"error-callback":onError});hcaptcha.execute(w);}</script><script src="https://js.hcaptcha.com/1/api.js?onload=onloadChallenge&render=explicit" async defer></script>`
	}

	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	//Built-in page text is English/Hindi by Accept-Language.
	fmt.Fprint(writer, providerPage(stringsFor(request), resolveBranding(settings), nonce, widgetScript))
	return true
}

// HandleChallengeVerify answers POST /_bProxy/challenge-verify. It always
// writes a response (redirect on success, short generic plain-text error
// otherwise) and reports whether it handled the request. Non-POST requests
// get a plain 404; no page is ever rendered here.
func HandleChallengeVerify(writer http.ResponseWriter, request *http.Request, ip, tlsFp string) bool {
	if request.URL.Path != "/_bProxy/challenge-verify" {
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

	entry, ok := takePendingChallenge(request.Form.Get("nonce"), ip, tlsFp, request.UserAgent())
	if !ok {
		// Unknown, expired, replayed, or client-mismatched nonce. Answer
		// generically without revealing which.
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, "404 Not Found")
		return true
	}

	verified, err := verifyProviderToken(entry.provider, entry.secretKey, request.Form.Get("token"), ip)
	if err != nil {
		fmt.Println("[ ! ] [ Challenge verification unavailable (" + entry.provider + "): " + err.Error() + " ]")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(writer, "Verification service unavailable. Please try again later.")
		return true
	}
	if !verified {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusForbidden)
		fmt.Fprint(writer, "Verification failed. Please go back and try again.")
		return true
	}

	// Same cookie the proof-of-work flow sets, then back to the original URL.
	writer.Header().Set("Set-Cookie", "__bProxy_v="+entry.encryptedIP+"; SameSite=Lax; path=/; Secure")
	http.Redirect(writer, request, entry.redirectURL, http.StatusFound)
	return true
}
