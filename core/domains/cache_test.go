package domains

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEdgeCacheDisabledIsNilSafe(t *testing.T) {
	var c *EdgeCache
	if _, _, _, _, ok := c.Lookup("k"); ok {
		t.Fatal("nil cache lookup hit")
	}
	c.Store("k", 200, nil, []byte("x"), time.Minute)
	if c.Purge() != 0 || c.PurgePath("/x") != 0 || c.PurgePrefix("/x") != 0 || c.PurgeTag("t") != 0 {
		t.Fatal("nil cache purge returned nonzero")
	}
}

func TestEdgeCacheStoreLookup(t *testing.T) {
	c := NewEdgeCache(true, 60, 64)
	if _, _, _, _, ok := c.Lookup("missing"); ok {
		t.Fatal("lookup hit on empty cache")
	}
	hdr := http.Header{"Content-Type": {"text/html"}, "Cache-Tag": {"news, front"}}
	c.Store("/page", 200, hdr, []byte("hello"), time.Minute)
	status, gotHdr, body, _, ok := c.Lookup("/page")
	if !ok || status != 200 || string(body) != "hello" || gotHdr.Get("Content-Type") != "text/html" {
		t.Fatalf("lookup = (%d, %q, %v), want (200, hello, true)", status, body, ok)
	}
	entries, _ := c.Stats()
	if entries != 1 {
		t.Fatalf("entries = %d, want 1", entries)
	}
}

func TestEdgeCacheExpiryAndStale(t *testing.T) {
	c := NewEdgeCache(true, 60, 64)
	// A nanosecond lifetime: expired by the time we look it up.
	c.Store("/old", 200, nil, []byte("stale"), time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	if _, _, _, _, ok := c.Lookup("/old"); ok {
		t.Fatal("normal lookup served an expired entry")
	}
	// LookupStale sees it (all-backends-down fallback).
	if _, _, body, ok := c.LookupStale("/old"); !ok || string(body) != "stale" {
		t.Fatal("LookupStale missed a recently expired entry")
	}
	// Older than lifetime + staleGrace: dropped on sight.
	// (Same-package test: backdate the stored time directly.)
	c.Store("/ancient", 200, nil, []byte("gone"), time.Minute)
	c.entries["/ancient"].storedAt = time.Now().Add(-2 * staleGrace)
	if _, _, _, ok := c.LookupStale("/ancient"); ok {
		t.Fatal("LookupStale served an entry older than the stale grace period")
	}
}

func TestEdgeCachePurge(t *testing.T) {
	c := NewEdgeCache(true, 60, 64)
	// Keys are "GET <path>[?query]" (see CacheKey/PurgePath).
	c.Store("GET /a/1", 200, http.Header{"Cache-Tag": {"news"}}, []byte("1"), time.Minute)
	c.Store("GET /a/2", 200, http.Header{"Cache-Tag": {"news"}}, []byte("2"), time.Minute)
	c.Store("GET /b/1", 200, http.Header{"Cache-Tag": {"blog"}}, []byte("3"), time.Minute)
	if n := c.PurgePath("/a/1"); n != 1 {
		t.Fatalf("PurgePath removed %d, want 1", n)
	}
	if n := c.PurgeTag("news"); n != 1 {
		t.Fatalf("PurgeTag removed %d, want 1", n)
	}
	if n := c.PurgePrefix("/b/"); n != 1 {
		t.Fatalf("PurgePrefix removed %d, want 1", n)
	}
	if n := c.Purge(); n != 0 {
		t.Fatalf("Purge on empty cache removed %d", n)
	}
}

func TestCacheKey(t *testing.T) {
	a := httptest.NewRequest(http.MethodGet, "https://example.com/page?x=1", nil)
	b := httptest.NewRequest(http.MethodGet, "https://example.com/page?x=1", nil)
	if CacheKey(a) != CacheKey(b) {
		t.Fatal("identical requests produced different cache keys")
	}
	c := httptest.NewRequest(http.MethodGet, "https://example.com/page?x=2", nil)
	if CacheKey(a) == CacheKey(c) {
		t.Fatal("different query strings produced the same cache key")
	}
}

func TestResponseFreshness(t *testing.T) {
	mk := func(hdr http.Header) *http.Response {
		return &http.Response{StatusCode: 200, Header: hdr}
	}
	// Explicit max-age is cacheable.
	if d, ok := ResponseFreshness(mk(http.Header{"Cache-Control": {"max-age=30"}})); !ok || d != 30*time.Second {
		t.Fatalf("max-age freshness = (%v, %v), want (30s, true)", d, ok)
	}
	// s-maxage wins over max-age.
	if d, ok := ResponseFreshness(mk(http.Header{"Cache-Control": {"max-age=30, s-maxage=10"}})); !ok || d != 10*time.Second {
		t.Fatalf("s-maxage freshness = (%v, %v), want (10s, true)", d, ok)
	}
	// Forbidding directives are never cacheable.
	for _, cc := range []string{"no-store", "no-cache", "private", "max-age=0"} {
		if _, ok := ResponseFreshness(mk(http.Header{"Cache-Control": {cc}})); ok {
			t.Fatalf("Cache-Control %q was treated as cacheable", cc)
		}
	}
	// Set-Cookie, Vary, and Content-Encoding forbid caching.
	if _, ok := ResponseFreshness(mk(http.Header{"Cache-Control": {"max-age=30"}, "Set-Cookie": {"a=1"}})); ok {
		t.Fatal("Set-Cookie response was treated as cacheable")
	}
	if _, ok := ResponseFreshness(mk(http.Header{"Cache-Control": {"max-age=30"}, "Vary": {"Accept-Encoding"}})); ok {
		t.Fatal("Vary response was treated as cacheable")
	}
	if _, ok := ResponseFreshness(mk(http.Header{"Cache-Control": {"max-age=30"}, "Content-Encoding": {"gzip"}})); ok {
		t.Fatal("Content-Encoding response was treated as cacheable")
	}
	// Non-cacheable statuses.
	resp := mk(http.Header{"Cache-Control": {"max-age=30"}})
	resp.StatusCode = 404
	if _, ok := ResponseFreshness(resp); ok {
		t.Fatal("404 was treated as cacheable")
	}
	// No freshness headers at all: no heuristic freshness.
	if _, ok := ResponseFreshness(mk(http.Header{})); ok {
		t.Fatal("response without freshness headers was treated as cacheable")
	}
}
