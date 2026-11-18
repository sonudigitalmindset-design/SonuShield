package firewall

import (
	"sync"
	"time"

	"sonushield/core/shared"
)

// CacheIps TTL sweep (sale-readiness, L-4 fix).
//
// CacheIps entries used to live until memory pressure forced
// a full wipe, so the map — and the H-1 exposure surface —
// grew with unique visitors. Entries are keyed with the
// current hour, so anything older than an hour is useless
// anyway: the sweep below drops entries older than the TTL
// on the existing two-minute cleanup tick, independent of
// memory pressure. Store time is tracked in a parallel map
// so the CacheIps value type (and every Load site) is
// unchanged. All stores go through CacheStore; direct
// CacheIps.Store calls must not be reintroduced.

// cacheIpsStoredAt records when each CacheIps key was stored.
var cacheIpsStoredAt sync.Map // map[string]time.Time

// CacheIpsTTL is the maximum age of a CacheIps entry: one
// hour, matching the cookie hour granularity in the keys.
const CacheIpsTTL = time.Hour

// CacheStore stores a CacheIps entry and records its store
// time for TTL sweeping. When the Redis shared cache is
// enabled the entry is also written to Redis (hashed key,
// same TTL) so other nodes can reuse it; Redis failures are
// swallowed inside the shared store.
func CacheStore(key, value string) {
	CacheIps.Store(key, value)
	cacheIpsStoredAt.Store(key, time.Now())
	shared.CacheSet(key, value, CacheIpsTTL)
}

// CacheLoad reads a CacheIps entry: the local map first,
// then the Redis shared cache on a local miss (populating
// the local map on a shared hit, so the next lookup is
// local). The return shape matches sync.Map.Load so call
// sites are unchanged. With no shared cache configured this
// is exactly CacheIps.Load.
func CacheLoad(key string) (any, bool) {
	if value, ok := CacheIps.Load(key); ok {
		return value, true
	}
	if value, ok := shared.CacheGet(key); ok {
		CacheIps.Store(key, value)
		cacheIpsStoredAt.Store(key, time.Now())
		return value, true
	}
	return nil, false
}

// SweepCacheIps deletes CacheIps entries older than maxAge
// and reports how many were dropped.
func SweepCacheIps(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	swept := 0
	cacheIpsStoredAt.Range(func(key, value any) bool {
		if stored, ok := value.(time.Time); ok && stored.Before(cutoff) {
			CacheIps.Delete(key)
			cacheIpsStoredAt.Delete(key)
			swept++
		}
		return true
	})
	return swept
}

// ClearCacheIps drops every CacheIps entry and its store
// time. Used by the memory-pressure wipe in the monitor.
func ClearCacheIps() {
	CacheIps.Range(func(key, value any) bool {
		CacheIps.Delete(key)
		return true
	})
	cacheIpsStoredAt.Range(func(key, value any) bool {
		cacheIpsStoredAt.Delete(key)
		return true
	})
}
