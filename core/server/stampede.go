package server

// Stampede guard (Batch 6): collapse simultaneous identical
// cache misses into a single origin fetch.
//
// When the edge cache is enabled and a domain opts in with
// stampedeGuard, the first request for an uncached cacheable URL
// becomes the leader and fetches from the origin; concurrent
// requests for the same cache key wait for the leader, then serve
// from the cache entry the leader's fetch populated. One slow
// origin response no longer fans out into N identical backend
// requests.
//
// Mechanics: the guard keys on the edge cache's own key
// (domains.CacheKey), so guard and cache can never disagree
// about what "identical" means. The leader is released when its
// middleware call returns, which is after the reverse proxy has
// run and the cache hook has stored the response, so followers
// waking up find the entry. A follower waits at most
// stampedeWaitTimeout, then fetches unguarded rather than waiting
// again: a slow or failed leader degrades to unguarded behavior,
// never to a wedge. If the leader's response was not cacheable
// (or errored), followers find nothing in the cache and fetch
// themselves, exactly as they would without the guard.
//
// The guard only applies to cacheable requests (plain GET,
// no Authorization, not an upgrade) and only when the edge cache
// exists: without a cache there is nothing for followers to
// share. It is off by default. A disconnected client stops
// waiting immediately via the request context.

import (
	"net/http"
	"sync"
	"time"

	"sonushield/core/domains"
)

// stampedeWaitTimeout bounds how long a follower waits for the
// leader's fetch before fetching unguarded itself. A variable (not
// a constant) so tests can shorten the wait.
var stampedeWaitTimeout = 30 * time.Second

// stampedeCall is one in-flight guarded fetch, keyed by cache key.
// Followers wait on done; the leader closes it on release.
type stampedeCall struct {
	done chan struct{}
}

// stampedeCalls holds the in-flight guarded fetches.
var stampedeCalls sync.Map // cache key -> *stampedeCall

// stampedeAcquire claims the leader slot for key. It reports
// whether this caller is the leader and, for followers, the
// channel that closes when the leader releases.
func stampedeAcquire(key string) (leader bool, wait <-chan struct{}) {
	call := &stampedeCall{done: make(chan struct{})}
	actual, loaded := stampedeCalls.LoadOrStore(key, call)
	if loaded {
		return false, actual.(*stampedeCall).done
	}
	return true, nil
}

// stampedeRelease drops the leader slot for key and wakes all
// followers. It is called via defer by the leader, so it runs
// even if the proxy path panics.
func stampedeRelease(key string) {
	if value, ok := stampedeCalls.LoadAndDelete(key); ok {
		close(value.(*stampedeCall).done)
	}
}

// stampedeEnter runs the guard for a backend-bound request. It
// returns (served, release):
//
//   - served=true: the response was served from the cache after
//     waiting (or the client disconnected while waiting); the
//     caller returns without proxying.
//   - served=false, release!=nil: this request is the leader; the
//     caller must defer release() so followers wake when the
//     fetch completes.
//   - served=false, release==nil: the guard does not apply; the
//     caller proxies normally.
func stampedeEnter(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings, domainName string) (served bool, release func()) {
	if !settings.StampedeGuard || settings.Cache == nil ||
		request.Method != http.MethodGet || request.Header.Get("Authorization") != "" ||
		isUpgradeRequest(request) {
		return false, nil
	}
	key := domains.CacheKey(request)
	// Another request may have populated the cache since the
	// middleware's lookup (waiting room, API gate); re-check
	// before acquiring.
	if serveCachedResponse(writer, request, settings, domainName, key) {
		return true, nil
	}
	leader, wait := stampedeAcquire(key)
	if leader {
		return false, func() { stampedeRelease(key) }
	}
	timer := time.NewTimer(stampedeWaitTimeout)
	defer timer.Stop()
	select {
	case <-wait:
	case <-timer.C:
	case <-request.Context().Done():
		return true, nil
	}
	if serveCachedResponse(writer, request, settings, domainName, key) {
		return true, nil
	}
	// The leader's response was not cached, or the wait timed
	// out: fetch unguarded. Do not re-acquire, so a stale entry
	// can never wedge followers into repeated waits.
	return false, nil
}
