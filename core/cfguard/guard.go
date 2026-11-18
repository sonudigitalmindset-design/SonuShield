// Package cfguard implements Cloudflare automatic Under
// Attack Mode (Batch 3): while SonuShield detects an attack
// on a domain, the domain's Cloudflare security level is
// raised to "under_attack" through the Cloudflare API, and
// it is restored to the operator's chosen level when the
// attack ends.
//
// The feature is strictly opt-in and per domain: it needs
// cloudflareAutoUAM=true plus the domain's existing
// cloudflareApiToken/cloudflareZoneId in config.json
// (config-file-only credentials, never logged, never
// returned by any API action). Without all three it does
// nothing.
//
// The monitor calls Report once per second with the
// domain's current attack state. Report never blocks: it
// only inspects in-memory state and, on a transition,
// starts one goroutine for the API call. At most one API
// call is in flight per domain, duplicate transitions are
// coalesced, and a failed call is retried no more than once
// a minute. Every failure fails open: SonuShield's own
// stages keep working exactly as before, with or without
// Cloudflare.
//
// State is memory-only: a restart forgets whether the level
// was raised, and the next attack raises it again (the API
// call is idempotent). The applied level is visible through
// AppliedLevel for the dashboard features response.
//
// This package never reads the configuration itself: the
// caller passes Settings, so the logic is unit-testable
// against a mock API server. No real Cloudflare account is
// involved in any test; live behavior against the real API
// is untested and documented as such.
package cfguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// UnderAttack is the Cloudflare security level applied
// while an attack is ongoing.
const UnderAttack = "under_attack"

// DefaultRestoreLevel is the level restored when the attack
// ends, unless the operator configured another.
const DefaultRestoreLevel = "medium"

// validLevels is the set of security_level values the
// Cloudflare API accepts.
var validLevels = map[string]bool{
	"off":            true,
	"essentially_off": true,
	"low":            true,
	"medium":         true,
	"high":           true,
	"under_attack":   true,
}

// ValidLevel reports whether level is an accepted
// Cloudflare security_level value.
func ValidLevel(level string) bool {
	return validLevels[level]
}

// RestoreLevel returns the level to restore: the
// configured one, or DefaultRestoreLevel when empty or
// invalid. An invalid configured level must never reach
// the API; config validation rejects it first, and this
// is the backstop.
func RestoreLevel(configured string) string {
	if ValidLevel(configured) {
		return configured
	}
	return DefaultRestoreLevel
}

// Settings carries one domain's auto-UAM configuration.
// Token is used only for the Authorization header.
type Settings struct {
	Enabled      bool
	Token        string
	ZoneID       string
	APIBase      string
	RestoreLevel string
}

// ready reports whether the settings can drive the API.
func (s Settings) ready() bool {
	return s.Enabled && s.Token != "" && s.ZoneID != ""
}

// apiBase returns the API base URL, defaulting to the
// public Cloudflare API.
func (s Settings) apiBase() string {
	base := strings.TrimRight(s.APIBase, "/")
	if base == "" {
		return "https://api.cloudflare.com"
	}
	return base
}

// retryInterval bounds how often a failed transition is
// retried. A variable (not a constant) so tests can
// shorten it.
var retryInterval = time.Minute

// nowFunc is the clock, overridable in tests.
var nowFunc = time.Now

// httpClient bounds every Cloudflare API call.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// maxResponse caps a Cloudflare API response body.
const maxResponse = 1 << 20 // 1 MB

// guard is the per-domain state machine.
type guard struct {
	mu           sync.Mutex
	raised       bool      // under_attack was successfully applied by us
	appliedLevel string    // last level successfully applied, "" if none
	inFlight     bool      // an API call is running
	lastFail     time.Time // last failed attempt; retries wait out retryInterval
}

var (
	guardsMu sync.Mutex
	guards   = map[string]*guard{}
)

// forDomain returns the state machine for a domain,
// creating it on first use.
func forDomain(domainName string) *guard {
	guardsMu.Lock()
	defer guardsMu.Unlock()
	g, ok := guards[domainName]
	if !ok {
		g = &guard{}
		guards[domainName] = g
	}
	return g
}

// Reset clears all per-domain state. Tests only: the proxy
// never forgets state mid-run.
func Reset() {
	guardsMu.Lock()
	defer guardsMu.Unlock()
	guards = map[string]*guard{}
}

// Report records one monitor tick's attack state for a
// domain and starts an API call when a transition needs
// one. It never blocks on the network and never fails: a
// domain without usable settings is a silent no-op. Only
// failed attempts are throttled: a restore right after a
// successful raise proceeds immediately, while a failed
// call is retried no more than once a minute.
func Report(domainName string, attacking bool, settings Settings) {
	if domainName == "" || !settings.ready() {
		return
	}
	g := forDomain(domainName)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight || nowFunc().Sub(g.lastFail) < retryInterval {
		return
	}
	if attacking {
		if g.raised {
			return
		}
		g.inFlight = true
		go g.apply(domainName, settings, UnderAttack)
		return
	}
	if !g.raised {
		return
	}
	g.inFlight = true
	go g.apply(domainName, settings, RestoreLevel(settings.RestoreLevel))
}

// apply performs one security-level change and records the
// outcome. Failures leave the raised/applied state
// unchanged (except clearing inFlight and noting the
// failure time), so the next eligible tick retries.
func (g *guard) apply(domainName string, settings Settings, level string) {
	err := setSecurityLevel(settings, level)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inFlight = false
	if err != nil {
		g.lastFail = nowFunc()
		// Generic line only: no token, no zone ID, no
		// response body. Attempts are throttled to once a
		// minute, so this cannot flood the log.
		fmt.Printf("[ ! ] [ Cloudflare security level update failed for domain %s ]\n", domainName)
		return
	}
	g.lastFail = time.Time{}
	g.appliedLevel = level
	g.raised = level == UnderAttack
}

// AppliedLevel returns the last security level this process
// successfully applied for a domain, or "" when none has
// been applied (yet). It never reflects changes made
// outside this process.
func AppliedLevel(domainName string) string {
	g := forDomain(domainName)
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.appliedLevel
}

// cfEnvelope is the Cloudflare API response envelope.
type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// setSecurityLevel PATCHes one zone's security_level
// setting. The token travels only in the Authorization
// header. Errors are generic: response details are never
// propagated (they could echo request data).
func setSecurityLevel(settings Settings, level string) error {
	body, err := json.Marshal(map[string]string{"value": level})
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/client/v4/zones/%s/settings/security_level", settings.apiBase(), settings.ZoneID)
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+settings.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the Cloudflare API")
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if readErr != nil {
		return fmt.Errorf("could not read the Cloudflare API response")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Cloudflare API returned HTTP %d", resp.StatusCode)
	}
	if len(data) > maxResponse {
		return fmt.Errorf("Cloudflare API response exceeds the 1 MB cap")
	}
	var envelope cfEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("Cloudflare API response is not valid")
	}
	if !envelope.Success {
		return fmt.Errorf("Cloudflare API reported failure")
	}
	return nil
}
