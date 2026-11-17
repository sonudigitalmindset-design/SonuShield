package firewall

// Cross-domain reputation sharing (Batch 5).
//
// When a domain opts in (shareReputation), the blocks it issues
// are remembered proxy-wide for a short time, and requests from
// the same IP or TLS fingerprint arriving at other opted-in
// domains start with elevated suspicion. Each domain opts into
// the pool in both directions: a domain that has not opted in
// neither contributes blocks nor consumes them.
//
// The store only ever ADDS suspicion (a configurable bump,
// default 1); it never blocks a request by itself, and a lookup
// problem behaves like "not seen" (fail-open). Entries expire
// after 10 minutes and the maps are size-bounded, so a sustained
// attack cannot grow memory without bound. Recording is skipped
// entirely when no domain has opted in.
//
// Recorded signals are the blocks the middleware issues after
// evaluation: suspect-level blocks and WAF-lite blocks. Rate-limit
// and fingerprint-list blocks are not recorded: the rate-limit
// tallies and fingerprint lists are already proxy-wide, so those
// signals reach every domain without this store.

import (
	"sync"
	"sync/atomic"
	"time"
)

// sharedRepTTL is how long a recorded block influences other
// domains. A variable (not a constant) only so tests can shorten
// it; production code never changes it.
var sharedRepTTL = 10 * time.Minute

const sharedRepMaxEntries = 100000

type sharedRepEntry struct {
	lastSeen time.Time
	hits     int
	source   string
}

var (
	sharedRepEnabled atomic.Bool
	sharedRepMu      sync.Mutex
	sharedRepIPs     = map[string]*sharedRepEntry{}
	sharedRepFPs     = map[string]*sharedRepEntry{}
	sharedRepSweep   sync.Once
)

// SetSharedReputationEnabled turns cross-domain recording and
// lookup on or off proxy-wide. It is called from config loading
// and reload with "true" when at least one domain opted in, and
// starts the expiry sweeper on first enable.
func SetSharedReputationEnabled(enabled bool) {
	was := sharedRepEnabled.Swap(enabled)
	if enabled && !was {
		sharedRepSweep.Do(func() { go sharedRepSweepLoop() })
	}
}

// SharedReputationEnabled reports whether any domain opted in.
func SharedReputationEnabled() bool {
	return sharedRepEnabled.Load()
}

// SharedReputationBump returns the suspicion bump for a
// shared-reputation hit: the configured value, defaulting to 1.
func SharedReputationBump(configured int) int {
	if configured <= 0 {
		return 1
	}
	return configured
}

// RecordSharedReputation remembers that domain blocked a request
// from ip with the given TLS fingerprint. It is a no-op when the
// feature is disabled proxy-wide. The fingerprint key is skipped
// when empty (Cloudflare mode has no TLS fingerprint).
func RecordSharedReputation(ip, fingerprint, domain string) {
	if !sharedRepEnabled.Load() {
		return
	}
	now := time.Now()
	sharedRepMu.Lock()
	defer sharedRepMu.Unlock()
	recordSharedLocked(sharedRepIPs, ip, domain, now)
	if fingerprint != "" {
		recordSharedLocked(sharedRepFPs, fingerprint, domain, now)
	}
}

func recordSharedLocked(store map[string]*sharedRepEntry, key, domain string, now time.Time) {
	if key == "" {
		return
	}
	if entry, ok := store[key]; ok {
		entry.lastSeen = now
		entry.hits++
		return
	}
	if len(store) >= sharedRepMaxEntries {
		// Bounded: drop the new record rather than growing
		// without limit. Fail-open: the pool just misses one
		// signal.
		return
	}
	store[key] = &sharedRepEntry{lastSeen: now, hits: 1, source: domain}
}

// LookupSharedReputation reports whether the IP or the TLS
// fingerprint was recently blocked on another opted-in domain.
// Expired entries count as absent and are dropped lazily.
func LookupSharedReputation(ip, fingerprint string) bool {
	if !sharedRepEnabled.Load() {
		return false
	}
	now := time.Now()
	sharedRepMu.Lock()
	defer sharedRepMu.Unlock()
	if lookupSharedLocked(sharedRepIPs, ip, now) {
		return true
	}
	if fingerprint != "" && lookupSharedLocked(sharedRepFPs, fingerprint, now) {
		return true
	}
	return false
}

func lookupSharedLocked(store map[string]*sharedRepEntry, key string, now time.Time) bool {
	if key == "" {
		return false
	}
	entry, ok := store[key]
	if !ok {
		return false
	}
	if now.Sub(entry.lastSeen) > sharedRepTTL {
		delete(store, key)
		return false
	}
	return true
}

// sharedRepSweepLoop drops expired entries once a minute so the
// maps stay bounded even for keys that are never looked up again.
func sharedRepSweepLoop() {
	for {
		time.Sleep(time.Minute)
		cutoff := time.Now().Add(-sharedRepTTL)
		sharedRepMu.Lock()
		for key, entry := range sharedRepIPs {
			if entry.lastSeen.Before(cutoff) {
				delete(sharedRepIPs, key)
			}
		}
		for key, entry := range sharedRepFPs {
			if entry.lastSeen.Before(cutoff) {
				delete(sharedRepFPs, key)
			}
		}
		sharedRepMu.Unlock()
	}
}
