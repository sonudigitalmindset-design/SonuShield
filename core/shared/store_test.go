package shared

import (
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// testStore starts a miniredis server and a Store against
// it. The caller closes both.
func testStore(t *testing.T, opts Options) (*miniredis.Miniredis, *Store) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	opts.Addr = mr.Addr()
	opts.FlushInterval = time.Hour // tests flush explicitly
	store, err := New(opts)
	if err != nil {
		mr.Close()
		t.Fatalf("New: %v", err)
	}
	return mr, store
}

func TestCountsAcrossNodes(t *testing.T) {
	mr, storeA := testStore(t, Options{WindowSeconds: 120})
	defer mr.Close()
	defer storeA.Close()
	storeB, err := New(Options{Addr: mr.Addr(), WindowSeconds: 120, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("New B: %v", err)
	}
	defer storeB.Close()

	now := time.Now()
	// Node A records and flushes; node B must see the counts
	// without having recorded anything itself.
	for i := 0; i < 5; i++ {
		storeA.Record(KindRequests, "203.0.113.7")
	}
	for i := 0; i < 2; i++ {
		storeA.Record(KindChallenges, "203.0.113.7")
	}
	storeA.Flush()
	req, ck, ok := storeB.Counts("203.0.113.7", int(now.Unix()), 120)
	if !ok {
		t.Fatal("Counts returned ok=false against a live server")
	}
	if req != 5 || ck != 2 {
		t.Fatalf("cross-node counts = (%d, %d), want (5, 2)", req, ck)
	}
	// An unrecorded IP counts zero.
	req, ck, ok = storeB.Counts("198.51.100.9", int(now.Unix()), 120)
	if !ok || req != 0 || ck != 0 {
		t.Fatalf("unknown IP counts = (%d, %d, %v), want (0, 0, true)", req, ck, ok)
	}
}

func TestCountsIncludeUnflushed(t *testing.T) {
	_, store := testStore(t, Options{WindowSeconds: 120})
	defer store.Close()
	now := time.Now()
	store.Record(KindRequests, "203.0.113.7")
	store.Record(KindRequests, "203.0.113.7")
	// No flush: the node's own pending counts must still show.
	req, _, ok := store.Counts("203.0.113.7", int(now.Unix()), 120)
	if !ok || req != 2 {
		t.Fatalf("unflushed counts = (%d, %v), want (2, true)", req, ok)
	}
	// After a flush the total must not double-count.
	store.Flush()
	req, _, ok = store.Counts("203.0.113.7", int(now.Unix()), 120)
	if !ok || req != 2 {
		t.Fatalf("flushed counts = (%d, %v), want (2, true)", req, ok)
	}
}

func TestCountsWindowExpiry(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	mr, store := testStore(t, Options{WindowSeconds: 120, Now: func() time.Time { return clock }})
	defer mr.Close()
	defer store.Close()
	store.Record(KindRequests, "203.0.113.7")
	store.Flush()
	// Inside the window: counted.
	if req, _, ok := store.Counts("203.0.113.7", int(clock.Unix())+30, 120); !ok || req != 1 {
		t.Fatalf("in-window counts = (%d, %v), want (1, true)", req, ok)
	}
	// Past the window: the key is out of the summed range.
	if req, _, ok := store.Counts("203.0.113.7", int(clock.Unix())+300, 120); !ok || req != 0 {
		t.Fatalf("expired counts = (%d, %v), want (0, true)", req, ok)
	}
}

func TestCountsFailOpen(t *testing.T) {
	mr, store := testStore(t, Options{WindowSeconds: 120})
	store.Close()
	mr.Close() // Redis gone: Counts must fail open, not hang or panic.
	req, ck, ok := store.Counts("203.0.113.7", int(time.Now().Unix()), 120)
	if ok || req != 0 || ck != 0 {
		t.Fatalf("dead-Redis counts = (%d, %d, %v), want (0, 0, false)", req, ck, ok)
	}
	// Record/Flush/Cache calls against a dead server must not panic.
	store.Record(KindRequests, "203.0.113.7")
	store.Flush()
	if _, found := store.CacheGet("k"); found {
		t.Fatal("CacheGet against dead Redis reported a hit")
	}
}

func TestNewRefusesUnreachable(t *testing.T) {
	// Port 1 on localhost: nothing listens; New must fail fast
	// and must not leak the password in its error.
	_, err := New(Options{Addr: "127.0.0.1:1", Password: "s3cr3t-test-password", Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("New against an unreachable address succeeded")
	}
	if strings.Contains(err.Error(), "s3cr3t-test-password") {
		t.Fatalf("error leaks the password: %v", err)
	}
}

func TestCacheRoundTripAndHashing(t *testing.T) {
	mr, store := testStore(t, Options{WindowSeconds: 120, SharedCache: true})
	defer mr.Close()
	defer store.Close()
	rawKey := "203.0.113.7" + "fingerprint" + "Mozilla/5.0" + "14" + "2"
	store.CacheSet(rawKey, "encrypted-blob", time.Hour)
	val, found := store.CacheGet(rawKey)
	if !found || val != "encrypted-blob" {
		t.Fatalf("CacheGet = (%q, %v), want (\"encrypted-blob\", true)", val, found)
	}
	// The raw key (IP + fingerprint + UA) must not appear in
	// Redis: keys are SHA-256 hashes.
	for _, key := range mr.Keys() {
		if strings.Contains(key, "203.0.113.7") || strings.Contains(key, "Mozilla") {
			t.Fatalf("raw cache key material in Redis key %q", key)
		}
	}
	// A different key misses.
	if _, found := store.CacheGet("other-key"); found {
		t.Fatal("CacheGet reported a hit for an unstored key")
	}
	// Expiry is honored.
	mr.FastForward(2 * time.Hour)
	if _, found := store.CacheGet(rawKey); found {
		t.Fatal("CacheGet reported a hit after TTL expiry")
	}
}

func TestCacheDisabledByDefault(t *testing.T) {
	mr, store := testStore(t, Options{WindowSeconds: 120})
	defer mr.Close()
	defer store.Close()
	store.CacheSet("k", "v", time.Hour)
	if _, found := store.CacheGet("k"); found {
		t.Fatal("CacheGet hit with SharedCache disabled")
	}
	if n := len(mr.Keys()); n != 0 {
		t.Fatalf("disabled cache wrote %d keys to Redis", n)
	}
}

func TestGlobalHandleNoopWhenUnconfigured(t *testing.T) {
	// With no store configured, the package-level functions
	// must be safe no-ops / fail-open.
	Shutdown()
	RecordRequest("203.0.113.7")
	RecordChallenge("203.0.113.7")
	if _, _, ok := Counts("203.0.113.7", int(time.Now().Unix()), 120); ok {
		t.Fatal("Counts ok=true with no store configured")
	}
	if _, found := CacheGet("k"); found {
		t.Fatal("CacheGet hit with no store configured")
	}
	CacheSet("k", "v", time.Hour)
	if Enabled() {
		t.Fatal("Enabled with no store configured")
	}
}
