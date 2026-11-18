package firewall

// Invisible-marker hits (Batch 7).
//
// When a client follows an invisible marker link on a challenge
// page, or fills a honeypot field on a verification form, its
// IP is recorded here for the domain. A recorded IP is treated
// as automated: subsequent requests are blocked while the
// record lasts. Records expire after one hour, the map is
// bounded, and stale entries are swept every minute — the same
// pattern as the timing and behavior stores.

import (
	"sync"
	"time"
)

const (
	markerHitTTL     = time.Hour
	markerHitMaxKeys = 50000
)

var (
	markerHitMu    sync.Mutex
	markerHits     = map[string]time.Time{}
	markerHitSweep sync.Once
)

func markerHitKey(domain, ip string) string {
	return domain + "\x00" + ip
}

// MarkMarkerHit records that a client tripped an invisible
// marker for a domain.
func MarkMarkerHit(domain, ip string) {
	if domain == "" || ip == "" {
		return
	}
	markerHitSweep.Do(func() { go markerHitSweepLoop() })
	markerHitMu.Lock()
	defer markerHitMu.Unlock()
	key := markerHitKey(domain, ip)
	if _, ok := markerHits[key]; !ok && len(markerHits) >= markerHitMaxKeys {
		// Bounded: untracked keys are simply not
		// recorded. Fail-open.
		return
	}
	markerHits[key] = time.Now()
}

// MarkerHit reports whether the IP tripped a marker for the
// domain within the last hour.
func MarkerHit(domain, ip string) bool {
	markerHitMu.Lock()
	defer markerHitMu.Unlock()
	at, ok := markerHits[markerHitKey(domain, ip)]
	return ok && time.Since(at) <= markerHitTTL
}

// markerHitSweepLoop drops expired records so the map stays
// bounded for keys that never return.
func markerHitSweepLoop() {
	for {
		time.Sleep(time.Minute)
		cutoff := time.Now().Add(-markerHitTTL)
		markerHitMu.Lock()
		for key, at := range markerHits {
			if at.Before(cutoff) {
				delete(markerHits, key)
			}
		}
		markerHitMu.Unlock()
	}
}
