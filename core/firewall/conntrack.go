package firewall

// Per-IP concurrent-connection cap (Batch 5, slowloris guard).
//
// Slowloris holds many connections open while sending headers or
// bodies very slowly. The existing timeout.read_header setting
// already bounds how long a single connection may idle while
// sending headers; this cap bounds how many connections one IP
// may hold at once, so one slow client cannot exhaust the
// server's connection capacity. It is disabled (0) by default
// and configured with proxy.maxConnsPerIP.
//
// Counting is driven by the server's ConnState hook: a
// connection is counted when it is new and released when it
// closes or is hijacked (WebSocket upgrades leave server
// tracking at hijack time, so they are released there). Only
// connections admitted while the cap is enabled are counted, so
// toggling the cap on reload cannot leak counts. When the cap is
// disabled, no tracking happens at all.

import (
	"net"
	"sync"
	"sync/atomic"
)

var (
	connCap     atomic.Int32
	connTrackMu sync.Mutex
	connCounts  = map[string]int{}
	connTracked = map[string]bool{}
)

// SetMaxConnsPerIP installs the per-IP connection cap. A
// non-positive value disables the cap (and clears tracking, so
// a reload that disables the feature leaves no stale counts).
func SetMaxConnsPerIP(limit int) {
	if limit <= 0 {
		limit = 0
	}
	connCap.Store(int32(limit))
	if limit == 0 {
		connTrackMu.Lock()
		connCounts = map[string]int{}
		connTracked = map[string]bool{}
		connTrackMu.Unlock()
	}
}

// MaxConnsPerIP returns the configured cap, or 0 when disabled.
func MaxConnsPerIP() int {
	return int(connCap.Load())
}

// connTrackIP extracts the IP from a remote address. SplitHostPort
// handles IPv6 correctly; a malformed address falls back to the
// whole string as its own key so it can never poison another
// client's count.
func connTrackIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// ConnOpened records a new connection. It reports false when the
// connection must be closed immediately: the cap is configured
// and this IP already holds that many connections. The caller
// (the ConnState hook) closes the connection; a rejected
// connection is never counted.
func ConnOpened(remoteAddr string, conn net.Conn) bool {
	_ = conn
	limit := int(connCap.Load())
	if limit <= 0 {
		return true
	}
	ip := connTrackIP(remoteAddr)
	connTrackMu.Lock()
	defer connTrackMu.Unlock()
	if connCounts[ip] >= limit {
		return false
	}
	connCounts[ip]++
	connTracked[remoteAddr] = true
	return true
}

// ConnClosed releases a connection counted by ConnOpened. It is
// safe to call for connections that were never counted.
func ConnClosed(remoteAddr string) {
	connTrackMu.Lock()
	defer connTrackMu.Unlock()
	if !connTracked[remoteAddr] {
		return
	}
	delete(connTracked, remoteAddr)
	ip := connTrackIP(remoteAddr)
	if connCounts[ip] > 0 {
		connCounts[ip]--
	}
	if connCounts[ip] == 0 {
		delete(connCounts, ip)
	}
}
