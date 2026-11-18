package domains

// In-memory edge cache (Batch 4).
//
// One cache per domain, disabled by default (edgeCache). When
// enabled, safe GET responses are served from memory instead of
// hitting the backend. The cache is deliberately conservative —
// it only stores what the backend explicitly allows to be cached:
//
//   - GET requests only, without an Authorization header.
//   - Response status 200, 203, 301, or 308.
//   - The response must carry an explicit freshness lifetime:
//     Cache-Control s-maxage/max-age > 0, or a future Expires
//     header. No heuristic freshness is ever applied.
//   - Cache-Control: no-store, no-cache, or private forbids
//     caching, as does any Set-Cookie header.
//   - Responses with a Vary header are never cached: the cache
//     keys on method + URL only, so a response that varies by
//     request headers could be served to the wrong client.
//   - Responses with a Content-Encoding are never cached, for
//     the same reason: the key does not capture what encodings
//     the client accepts.
//
// The effective lifetime is the smaller of the backend's lifetime
// and the configured edgeCacheTTL (default 60 seconds). Entries
// are capped at 1 MB each and the whole cache at edgeCacheMaxMB
// (default 64 MB); when full, expired entries go first, then the
// oldest. A reload discards the cache.
//
// Stale entries are kept for up to staleGrace past expiry so the
// load-balancer fallback (Batch 4) can serve them, clearly
// marked, when every backend is down. LookupStale is the only
// reader that sees expired entries; normal lookups never serve
// stale content. Entries older than lifetime + staleGrace are
// dropped on sight.
//
// All methods are safe on a nil *EdgeCache (feature disabled):
// lookups miss, stores and purges are no-ops.

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultEdgeCacheTTLSeconds = 60
	defaultEdgeCacheMaxMB      = 64
	maxEdgeCacheMaxMB          = 1024
	maxEdgeEntryBytes          = 1 << 20 // 1 MB
	// staleGrace bounds how long an expired entry is retained
	// for the all-backends-down fallback.
	staleGrace = time.Hour
)

type cacheEntry struct {
	status   int
	header   http.Header
	body     []byte
	storedAt time.Time
	lifetime time.Duration
	// tags are the Cache-Tag values recorded at store time
	// (Batch 8), used by PurgeTag. At most 10, each capped.
	tags []string
}

type EdgeCache struct {
	mu       sync.Mutex
	entries  map[string]*cacheEntry
	bytes    int64
	maxBytes int64
	ttlCap   time.Duration
	// Analytics counters (Batch 8): counters only, guarded by
	// the same mutex as the entries. A reload resets them.
	hits        int64
	misses      int64
	bytesServed int64
	stores      int64
	evictions   int64
	purges      int64
	staleServes int64
}

// NewEdgeCache builds a cache from the domain config, or nil when
// edge caching is disabled.
func NewEdgeCache(enabled bool, ttlSeconds, maxMB int) *EdgeCache {
	if !enabled {
		return nil
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultEdgeCacheTTLSeconds * time.Second
	}
	maxBytes := int64(maxMB) << 20
	if maxMB <= 0 {
		maxBytes = defaultEdgeCacheMaxMB << 20
	}
	if maxBytes > maxEdgeCacheMaxMB<<20 {
		maxBytes = maxEdgeCacheMaxMB << 20
	}
	return &EdgeCache{
		entries:  map[string]*cacheEntry{},
		maxBytes: maxBytes,
		ttlCap:   ttl,
	}
}

// CacheKey is the lookup key for a request: method + full request
// URI. One cache exists per domain, so the host is not part of the
// key.
func CacheKey(r *http.Request) string {
	return r.Method + " " + r.URL.RequestURI()
}

// Lookup returns a fresh cached response for key, if one exists.
// Expired entries are reported as misses but retained (up to the
// stale grace) so the all-backends-down fallback can still serve
// them; only entries past the grace are removed here.
func (c *EdgeCache) Lookup(key string) (status int, header http.Header, body []byte, age time.Duration, ok bool) {
	if c == nil {
		return 0, nil, nil, 0, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, exists := c.entries[key]
	if !exists {
		c.misses++
		return 0, nil, nil, 0, false
	}
	if now.After(entry.storedAt.Add(entry.lifetime)) {
		if now.After(entry.storedAt.Add(entry.lifetime + staleGrace)) {
			delete(c.entries, key)
			c.bytes -= int64(len(entry.body))
		}
		c.misses++
		return 0, nil, nil, 0, false
	}
	c.hits++
	c.bytesServed += int64(len(entry.body))
	return entry.status, entry.header, entry.body, now.Sub(entry.storedAt), true
}

// LookupStale returns a cached response even when expired, for the
// all-backends-down fallback, as long as it is within the stale
// grace. Entries past the grace are dropped and reported as
// misses.
func (c *EdgeCache) LookupStale(key string) (status int, header http.Header, body []byte, ok bool) {
	if c == nil {
		return 0, nil, nil, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, exists := c.entries[key]
	if !exists {
		return 0, nil, nil, false
	}
	if now.After(entry.storedAt.Add(entry.lifetime + staleGrace)) {
		delete(c.entries, key)
		c.bytes -= int64(len(entry.body))
		return 0, nil, nil, false
	}
	// Stale serves count separately from fresh hits: the
	// normal Lookup already counted this key as a miss.
	c.staleServes++
	c.bytesServed += int64(len(entry.body))
	return entry.status, entry.header, entry.body, true
}

// Store saves a response under key. Oversized entries and entries
// that cannot fit even after eviction are refused silently.
func (c *EdgeCache) Store(key string, status int, header http.Header, body []byte, lifetime time.Duration) {
	if c == nil || len(body) > maxEdgeEntryBytes || lifetime <= 0 {
		return
	}
	if lifetime > c.ttlCap {
		lifetime = c.ttlCap
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, exists := c.entries[key]; exists {
		c.bytes -= int64(len(old.body))
		delete(c.entries, key)
	}
	size := int64(len(body))
	if size > c.maxBytes {
		return
	}
	for c.bytes+size > c.maxBytes {
		if !c.evictOneLocked() {
			return
		}
	}
	cloned := make(http.Header, len(header))
	for k, v := range header {
		cloned[k] = append([]string(nil), v...)
	}
	c.entries[key] = &cacheEntry{status: status, header: cloned, body: body, storedAt: time.Now(), lifetime: lifetime, tags: parseCacheTags(header)}
	c.bytes += size
	c.stores++
}

// parseCacheTags splits a Cache-Tag header value into tags:
// comma-separated, trimmed, at most 10 tags of at most 64
// characters each. Empty values yield no tags.
func parseCacheTags(header http.Header) []string {
	raw := header.Get("Cache-Tag")
	if raw == "" {
		return nil
	}
	var tags []string
	for _, tag := range strings.Split(raw, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if len(tag) > 64 {
			tag = tag[:64]
		}
		tags = append(tags, tag)
		if len(tags) >= 10 {
			break
		}
	}
	return tags
}

// evictOneLocked removes one entry: an expired entry first, else
// the oldest. The caller must hold c.mu. It reports whether
// anything was removed.
func (c *EdgeCache) evictOneLocked() bool {
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.storedAt.Add(entry.lifetime)) {
			delete(c.entries, key)
			c.bytes -= int64(len(entry.body))
			c.evictions++
			return true
		}
	}
	var oldestKey string
	var oldestTime time.Time
	for key, entry := range c.entries {
		if oldestKey == "" || entry.storedAt.Before(oldestTime) {
			oldestKey, oldestTime = key, entry.storedAt
		}
	}
	if oldestKey == "" {
		return false
	}
	c.bytes -= int64(len(c.entries[oldestKey].body))
	delete(c.entries, oldestKey)
	c.evictions++
	return true
}

// Purge removes every entry and reports how many were removed.
func (c *EdgeCache) Purge() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = map[string]*cacheEntry{}
	c.bytes = 0
	c.purges += int64(n)
	return n
}

// PurgePath removes entries for one URL path: the exact key
// "GET <path>" and any key for the same path with a query string.
// It reports how many entries were removed.
func (c *EdgeCache) PurgePath(path string) int {
	if c == nil {
		return 0
	}
	exact := "GET " + path
	prefix := exact + "?"
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for key, entry := range c.entries {
		if key == exact || strings.HasPrefix(key, prefix) {
			delete(c.entries, key)
			c.bytes -= int64(len(entry.body))
			n++
		}
	}
	c.purges += int64(n)
	return n
}

// PurgePrefix removes entries whose URL path starts with the
// given prefix (keys are "GET <path>[?query]"). It reports
// how many entries were removed.
func (c *EdgeCache) PurgePrefix(prefix string) int {
	if c == nil || prefix == "" {
		return 0
	}
	match := "GET " + prefix
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for key, entry := range c.entries {
		if strings.HasPrefix(key, match) {
			delete(c.entries, key)
			c.bytes -= int64(len(entry.body))
			n++
		}
	}
	c.purges += int64(n)
	return n
}

// PurgeTag removes entries recorded with the given Cache-Tag
// value. It reports how many entries were removed.
func (c *EdgeCache) PurgeTag(tag string) int {
	if c == nil || tag == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for key, entry := range c.entries {
		for _, entryTag := range entry.tags {
			if entryTag == tag {
				delete(c.entries, key)
				c.bytes -= int64(len(entry.body))
				n++
				break
			}
		}
	}
	c.purges += int64(n)
	return n
}

// CacheAnalytics is the counter snapshot for one domain's
// edge cache (Batch 8). Counters only: no keys, paths, or
// bodies are exposed.
type CacheAnalytics struct {
	Hits        int64
	Misses      int64
	BytesServed int64
	Stores      int64
	Evictions   int64
	Purges      int64
	StaleServes int64
	Entries     int
	Bytes       int64
}

// Analytics returns the counter snapshot. A nil cache
// reports zeros.
func (c *EdgeCache) Analytics() CacheAnalytics {
	if c == nil {
		return CacheAnalytics{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheAnalytics{
		Hits: c.hits, Misses: c.misses, BytesServed: c.bytesServed,
		Stores: c.stores, Evictions: c.evictions, Purges: c.purges,
		StaleServes: c.staleServes, Entries: len(c.entries), Bytes: c.bytes,
	}
}

// Stats reports the entry count and total stored bytes.
func (c *EdgeCache) Stats() (entries int, bytes int64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.bytes
}

// ResponseFreshness decides whether a backend response may be
// cached and, if so, for how long. It implements the conservative
// rules documented at the top of this file. The returned lifetime
// is the backend's lifetime, before the configured TTL cap.
func ResponseFreshness(resp *http.Response) (time.Duration, bool) {
	switch resp.StatusCode {
	case 200, 203, 301, 308:
	default:
		return 0, false
	}
	header := resp.Header
	if header.Get("Set-Cookie") != "" {
		return 0, false
	}
	if header.Get("Vary") != "" {
		return 0, false
	}
	// A compressed body is only correct for clients that accept
	// that encoding, and the cache key does not capture it, so
	// encoded responses are never stored.
	if enc := header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return 0, false
	}
	directives := parseCacheControl(header.Get("Cache-Control"))
	if directives["no-store"] || directives["no-cache"] || directives["private"] {
		return 0, false
	}
	if sMaxAge, ok := cacheControlSeconds(header.Get("Cache-Control"), "s-maxage"); ok && sMaxAge > 0 {
		return time.Duration(sMaxAge) * time.Second, true
	}
	if maxAge, ok := cacheControlSeconds(header.Get("Cache-Control"), "max-age"); ok && maxAge > 0 {
		return time.Duration(maxAge) * time.Second, true
	}
	if expires := header.Get("Expires"); expires != "" {
		if t, err := http.ParseTime(expires); err == nil {
			if remaining := time.Until(t); remaining > 0 {
				return remaining, true
			}
		}
	}
	return 0, false
}

func parseCacheControl(value string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		name := strings.ToLower(strings.TrimSpace(strings.SplitN(part, "=", 2)[0]))
		if name != "" {
			out[name] = true
		}
	}
	return out
}

func cacheControlSeconds(value, directive string) (int64, bool) {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || !strings.EqualFold(kv[0], directive) {
			continue
		}
		n, err := strconv.ParseInt(strings.Trim(kv[1], `"`), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
