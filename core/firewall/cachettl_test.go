package firewall

import (
	"testing"
	"time"
)

func TestSweepCacheIps(t *testing.T) {
	CacheStore("test-sweep-fresh", "v1")
	CacheStore("test-sweep-old", "v2")
	// Backdate the old entry past the TTL.
	cacheIpsStoredAt.Store("test-sweep-old", time.Now().Add(-2*CacheIpsTTL))
	defer func() {
		CacheIps.Delete("test-sweep-fresh")
		CacheIps.Delete("test-sweep-old")
		cacheIpsStoredAt.Delete("test-sweep-fresh")
		cacheIpsStoredAt.Delete("test-sweep-old")
	}()
	if n := SweepCacheIps(CacheIpsTTL); n != 1 {
		t.Fatalf("SweepCacheIps dropped %d entries, want 1", n)
	}
	if _, ok := CacheIps.Load("test-sweep-old"); ok {
		t.Fatal("stale entry survived the sweep")
	}
	if _, ok := CacheIps.Load("test-sweep-fresh"); !ok {
		t.Fatal("fresh entry was swept")
	}
	if _, ok := cacheIpsStoredAt.Load("test-sweep-old"); ok {
		t.Fatal("stale entry's store time survived the sweep")
	}
}

func TestClearCacheIps(t *testing.T) {
	CacheStore("test-clear-1", "v1")
	CacheStore("test-clear-2", "v2")
	ClearCacheIps()
	if _, ok := CacheIps.Load("test-clear-1"); ok {
		t.Fatal("entry survived ClearCacheIps")
	}
	if _, ok := cacheIpsStoredAt.Load("test-clear-2"); ok {
		t.Fatal("store time survived ClearCacheIps")
	}
}
