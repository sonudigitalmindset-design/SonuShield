package server

// Challenge rotation (Batch 6): rotate the served Stage 2
// challenge type across attack waves (or, per operator policy,
// per request) so attackers cannot settle on one solver.
//
// Configuration (per domain, config-file-only):
//   - challengeRotation: ordered list of challenge type names.
//     Empty or unset disables rotation and the fixed chain below
//     is used exactly as before.
//   - challengeRotationMode: "wave" (default) or "request".
//
// Type names (matched case-insensitively, surrounding spaces
// ignored): "pow" (classic hash puzzle), "memoryPow" (Argon2id
// puzzle, item 3), "turnstile", "hcaptcha", "captcha" (the Stage 3
// slider captcha, served here for a Stage 2 suspicion level).
// Unknown names are dropped, duplicates collapse to the first
// occurrence, and unavailable types are skipped: a provider type
// is available only when the domain is configured for that
// provider with its keys. Each domain has one provider
// configuration, so a single domain rotates between at most one
// provider type and the keyless types; rotating between
// Turnstile and hCaptcha on one domain is not supported. When no
// listed type is available, rotation is inert and the fixed chain
// runs. The classic puzzle is always available, so an enabled
// rotation always serves something.
//
// Modes:
//   - "wave": the type is stable within an attack wave and
//     advances to the next listed type when a new wave begins.
//     Wave start is the monitor loop's attack_start event, which
//     fires exactly once per wave episode (see
//     advanceChallengeRotation). A visitor mid-challenge keeps
//     seeing the same type for the whole wave.
//   - "request": the type advances on every served challenge
//     (round-robin). Each challenge is self-contained, so a
//     retry legitimately shows a different type.
//
// Rotation replaces the fixed chain only when enabled: provider
// first, then memory-hard, then classic PoW is the behavior with
// no rotation list, unchanged. Rotation state is a per-domain
// atomic counter: it survives reloads (it is wave state, not
// config) and resets on restart. The counter is shared by both
// modes but advanced by only one mechanism at a time: the monitor
// hook no-ops in request mode, and the dispatcher advances only
// in request mode.
//
// The captcha type reuses serveCaptchaChallenge (captcha.go) and
// the existing /_bProxy/verified endpoint; the provider and
// memory-hard types reuse their existing verify endpoints. No
// new cookie names, no new paths, no new visible pages.

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"sonushield/core/domains"
	"sonushield/core/firewall"
)

// Rotation challenge type names, lowercase; config values are
// lowercased before comparison.
const (
	rotationTypePow       = "pow"
	rotationTypeMemoryPow = "memorypow"
	rotationTypeTurnstile = "turnstile"
	rotationTypeHCaptcha  = "hcaptcha"
	rotationTypeCaptcha   = "captcha"
)

// normalizeRotationMode resolves the rotation mode: "request"
// selects per-request rotation, anything else (including empty
// and unknown values) selects wave rotation.
func normalizeRotationMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "request") {
		return "request"
	}
	return "wave"
}

// effectiveRotationTypes returns the operator's rotation list with
// unknown names dropped, duplicates removed (first occurrence
// wins), and unavailable types skipped. It returns nil when
// rotation is disabled or no listed type is available.
func effectiveRotationTypes(settings domains.DomainSettings) []string {
	if len(settings.ChallengeRotation) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range settings.ChallengeRotation {
		name := strings.ToLower(strings.TrimSpace(raw))
		if seen[name] {
			continue
		}
		seen[name] = true
		switch name {
		case rotationTypePow, rotationTypeMemoryPow, rotationTypeCaptcha:
			out = append(out, name)
		case rotationTypeTurnstile, rotationTypeHCaptcha:
			if ChallengeProviderConfigured(settings) && settings.ChallengeProvider == name {
				out = append(out, name)
			}
		default:
			// Unknown name: dropped.
		}
	}
	return out
}

// rotationCursors holds one atomic counter per domain, keyed by
// domain name.
var rotationCursors sync.Map // domain name -> *atomic.Uint32

func rotationCursor(domainName string) *atomic.Uint32 {
	if value, ok := rotationCursors.Load(domainName); ok {
		return value.(*atomic.Uint32)
	}
	cursor := &atomic.Uint32{}
	actual, _ := rotationCursors.LoadOrStore(domainName, cursor)
	return actual.(*atomic.Uint32)
}

// advanceChallengeRotation moves a domain to the next challenge
// type in its rotation list. Called by the monitor loop at
// attack-wave start, exactly once per wave episode. It is a no-op
// when rotation is disabled, when no listed type is available, or
// when the domain uses request mode (whose dispatcher advances
// the counter itself).
func advanceChallengeRotation(domainName string, settings domains.DomainSettings) {
	if normalizeRotationMode(settings.ChallengeRotationMode) != "wave" {
		return
	}
	if len(effectiveRotationTypes(settings)) == 0 {
		return
	}
	rotationCursor(domainName).Add(1)
}

// rotationNextType reports the challenge type the next rotation
// decision will serve: in wave mode the current wave's type, in
// request mode the next type in the cycle. It returns "" when
// rotation is disabled. Read-only; used for API visibility.
func rotationNextType(settings domains.DomainSettings) string {
	types := effectiveRotationTypes(settings)
	if len(types) == 0 {
		return ""
	}
	return types[int(rotationCursor(settings.Name).Load())%len(types)]
}

// serveClassicPowChallenge serves the classic Stage 2 hash puzzle:
// adaptive difficulty when configured, otherwise the fixed
// configured difficulty, with the built-in page or the validated
// custom PoW template. Shared by the fixed challenge chain and by
// rotation (the "pow" type and the ultimate fallback). It always
// writes a response.
func serveClassicPowChallenge(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings, domainData domains.DomainData, domainName, encryptedIP, hashedEncryptedIP string, buffer *bytes.Buffer) {
	//Adaptive PoW: scale the difficulty with current load so a
	//legitimate visitor is barely delayed under normal conditions
	//and bots face a harder puzzle during an attack. Disabled by
	//default (fixed configured difficulty). The clamps below also
	//guard against misconfigured difficulties.
	difficulty := domainData.Stage2Difficulty
	if settings.AdaptivePow {
		difficulty = firewall.EffectivePoWDifficulty(domainData.Stage2Difficulty, settings.PoWDifficultyMin, settings.PoWDifficultyMax, domainData.RequestsBypassedPerSecond, settings.BypassStage1, settings.BypassStage2)
	}
	if difficulty < 1 {
		difficulty = 1
	}
	if difficulty >= len(encryptedIP) {
		difficulty = len(encryptedIP) - 1
	}
	publicSalt := encryptedIP[:len(encryptedIP)-difficulty]
	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
	//Built-in page text is English/Hindi by Accept-Language; a
	//validated custom template replaces the visible part.
	pageStr := stringsFor(request)
	if tpl := settings.PageTemplates; tpl != nil && tpl.PoW != "" {
		SendResponse(withBehaviorScript(withInvisibleMarkers(renderPowTemplate(tpl.PoW, pageStr, publicSalt, hashedEncryptedIP, difficulty), settings, domainName), settings, domainName), buffer, writer)
	} else {
		SendResponse(withBehaviorScript(withInvisibleMarkers(powPage(pageStr, resolveBranding(settings), publicSalt, hashedEncryptedIP, difficulty), settings, domainName), settings, domainName), buffer, writer)
	}
}

// serveRotatedChallenge serves the Stage 2 challenge selected by
// the domain's rotation policy. It returns false when rotation is
// disabled or no listed type is available, in which case the
// caller falls through to the fixed challenge chain. When
// rotation is enabled it always serves something and returns
// true: a type whose serving fails (nonce generation) falls back
// to the classic PoW page inside the dispatcher.
func serveRotatedChallenge(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings, domainData domains.DomainData, domainName, encryptedIP, hashedEncryptedIP, ip, tlsFp, userAgent string, buffer *bytes.Buffer) bool {
	types := effectiveRotationTypes(settings)
	if len(types) == 0 {
		return false
	}
	cursor := rotationCursor(domainName)
	var index uint32
	if normalizeRotationMode(settings.ChallengeRotationMode) == "request" {
		index = cursor.Add(1) - 1
	} else {
		index = cursor.Load()
	}
	switch types[int(index)%len(types)] {
	case rotationTypeMemoryPow:
		if ServeMemoryPowChallenge(writer, request, settings, domainName, encryptedIP, ip, tlsFp, userAgent) {
			return true
		}
	case rotationTypeTurnstile, rotationTypeHCaptcha:
		if ServeProviderChallenge(writer, request, settings, domainName, encryptedIP, ip, tlsFp, userAgent) {
			return true
		}
	case rotationTypeCaptcha:
		serveCaptchaChallenge(writer, request, settings, domainName, encryptedIP, ip, buffer)
		return true
	}
	// "pow", or any type whose serving failed: classic puzzle.
	serveClassicPowChallenge(writer, request, settings, domainData, domainName, encryptedIP, hashedEncryptedIP, buffer)
	return true
}
