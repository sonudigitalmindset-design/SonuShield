package controlplane

import (
	"testing"
	"time"
)

func TestLoginLimiterBlocksAfterFailures(t *testing.T) {
	l := newLoginLimiter()
	ip := "203.0.113.7"
	if l.blocked(ip) {
		t.Fatal("fresh IP is blocked")
	}
	for i := 0; i < loginMaxFailures-1; i++ {
		l.recordFailure(ip)
		if l.blocked(ip) {
			t.Fatalf("blocked after %d failures, want %d", i+1, loginMaxFailures)
		}
	}
	l.recordFailure(ip)
	if !l.blocked(ip) {
		t.Fatal("not blocked after max failures")
	}
	// Other IPs are unaffected.
	if l.blocked("203.0.113.8") {
		t.Fatal("unrelated IP blocked")
	}
}

func TestLoginLimiterWindowExpiry(t *testing.T) {
	l := newLoginLimiter()
	ip := "203.0.113.7"
	// Failures older than the window do not count.
	l.failures[ip] = []time.Time{time.Now().Add(-loginBlockWindow - time.Minute)}
	for i := 0; i < loginMaxFailures; i++ {
		l.failures[ip] = append(l.failures[ip], time.Now().Add(-loginBlockWindow-time.Minute))
	}
	if l.blocked(ip) {
		t.Fatal("stale failures blocked the IP")
	}
}
