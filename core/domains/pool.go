package domains

// Backend pool: load balancing, failover, and health checks
// (Batch 4).
//
// A domain may list several backends ("backends" in config.json).
// When the list is empty, the pool holds the single legacy
// "backend" and behaves exactly like the old single-host proxy:
// same target, same error page, no extra probing.
//
// Policies ("lbPolicy"): "round-robin" (default) or
// "least-connections". Unknown values fall back to round-robin
// with a warning at startup.
//
// Failover works two ways:
//   - Transport failures mark a backend down after 2 consecutive
//     failures, for a 30-second cooldown, whether or not active
//     health checks are enabled. The next request then picks
//     another backend; a request already in flight is retried on
//     another backend when its body can be replayed (GET/HEAD, or
//     any request with a GetBody). Non-replayable bodies are never
//     retried, so a POST is never duplicated.
//   - Active health checks ("healthCheckEnabled") probe each
//     backend's health path on an interval. A backend that fails
//     probing is excluded until it passes again.
//
// When every backend is down, the proxy serves a stale cached
// response if the edge cache has one (see the RoundTripper
// fallback), and the old backend error page otherwise.
//
// Health checks run in a single background goroutine started once
// by StartHealthChecks, which iterates the live domain map, so a
// reload (which replaces pools) needs no goroutine bookkeeping.

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	backendFailThreshold = 2
	backendCooldown      = 30 * time.Second
	healthCheckTick      = 5 * time.Second
	healthProbeTimeout   = 3 * time.Second
	minHealthInterval    = 5 * time.Second
)

// Backend is one upstream server in a pool.
type Backend struct {
	Addr string

	mu        sync.Mutex
	healthy   bool
	fails     int
	downUntil time.Time
	conns     atomic.Int32
}

// BackendPool is one domain's set of backends.
type BackendPool struct {
	Scheme      string
	Policy      string
	HostHeader  string
	backends    []*Backend
	rr          atomic.Uint64
	healthOn    bool
	healthPath  string
	healthEvery time.Duration

	checkMu   sync.Mutex
	lastCheck time.Time
}

// NewBackendPool builds a pool from the domain config. backends may
// be empty, in which case fallback (the legacy single backend) is
// the only entry. Empty or whitespace-only entries are dropped;
// when nothing remains, the pool is still built with the fallback
// address so the proxy fails exactly as the old code would.
func NewBackendPool(domainName, scheme string, backends []string, fallback, policy string, healthEnabled bool, healthPath string, healthIntervalSec int) *BackendPool {
	addrs := []string{}
	for _, addr := range backends {
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			addrs = append(addrs, trimmed)
		}
	}
	if len(addrs) == 0 && strings.TrimSpace(fallback) != "" {
		addrs = []string{strings.TrimSpace(fallback)}
	}
	pool := &BackendPool{
		Scheme:     scheme,
		Policy:     strings.ToLower(strings.TrimSpace(policy)),
		HostHeader: domainName,
		healthOn:   healthEnabled,
		healthPath: healthPath,
	}
	if pool.Policy != "least-connections" {
		pool.Policy = "round-robin"
	}
	if pool.healthPath == "" {
		pool.healthPath = "/"
	}
	pool.healthEvery = time.Duration(healthIntervalSec) * time.Second
	if pool.healthEvery < minHealthInterval {
		pool.healthEvery = minHealthInterval
	}
	for _, addr := range addrs {
		pool.backends = append(pool.backends, &Backend{Addr: addr, healthy: true})
	}
	return pool
}

// Size reports the number of backends in the pool.
func (p *BackendPool) Size() int {
	if p == nil {
		return 0
	}
	return len(p.backends)
}

// HealthEnabled reports whether active health checks run for this pool.
func (p *BackendPool) HealthEnabled() bool {
	return p != nil && p.healthOn
}

func (p *BackendPool) eligible(b *Backend, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.healthOn && !b.healthy {
		return false
	}
	return now.After(b.downUntil) || now.Equal(b.downUntil)
}

// Pick selects the next backend for a request, or nil when no
// backend is currently eligible (all down or cooling down).
func (p *BackendPool) Pick() *Backend {
	if p == nil || len(p.backends) == 0 {
		return nil
	}
	now := time.Now()
	if p.Policy == "least-connections" {
		var best *Backend
		var bestConns int32
		for _, b := range p.backends {
			if !p.eligible(b, now) {
				continue
			}
			if conns := b.conns.Load(); best == nil || conns < bestConns {
				best, bestConns = b, conns
			}
		}
		return best
	}
	start := p.rr.Add(1)
	for i := 0; i < len(p.backends); i++ {
		b := p.backends[int((start+uint64(i))%uint64(len(p.backends)))]
		if p.eligible(b, now) {
			return b
		}
	}
	return nil
}

// MarkFailed records a transport failure. After the threshold of
// consecutive failures the backend cools down; with health checks
// enabled it is also marked unhealthy until a probe passes.
func (p *BackendPool) MarkFailed(b *Backend) {
	if p == nil || b == nil {
		return
	}
	b.mu.Lock()
	b.fails++
	if b.fails >= backendFailThreshold {
		b.downUntil = time.Now().Add(backendCooldown)
		if p.healthOn {
			b.healthy = false
		}
	}
	b.mu.Unlock()
}

// MarkOK records a successful round trip: failures reset and any
// cooldown is cleared.
func (p *BackendPool) MarkOK(b *Backend) {
	if p == nil || b == nil {
		return
	}
	b.mu.Lock()
	b.fails = 0
	b.downUntil = time.Time{}
	if p.healthOn {
		b.healthy = true
	}
	b.mu.Unlock()
}

// AllDown reports whether no backend is currently eligible.
func (p *BackendPool) AllDown() bool {
	if p == nil {
		return true
	}
	now := time.Now()
	for _, b := range p.backends {
		if p.eligible(b, now) {
			return false
		}
	}
	return true
}

// TrackStart/TrackEnd bracket one proxied request for the
// least-connections policy. They are no-ops on a nil pool.
func (p *BackendPool) TrackStart(b *Backend) {
	if p != nil && b != nil {
		b.conns.Add(1)
	}
}

// TrackEnd ends the request bracketed by TrackStart.
func (p *BackendPool) TrackEnd(b *Backend) {
	if p != nil && b != nil {
		b.conns.Add(-1)
	}
}

// dueForCheck reports whether the pool is due for a health probe,
// and marks it checked. Not due when health checks are disabled.
func (p *BackendPool) dueForCheck(now time.Time) bool {
	if !p.HealthEnabled() {
		return false
	}
	p.checkMu.Lock()
	defer p.checkMu.Unlock()
	if now.Sub(p.lastCheck) < p.healthEvery {
		return false
	}
	p.lastCheck = now
	return true
}

var healthClient = &http.Client{
	Timeout: healthProbeTimeout,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Probe checks every backend once and updates health state. A
// 2xx/3xx response marks the backend up; anything else (error,
// timeout, 4xx/5xx) marks it down until the next successful probe.
func (p *BackendPool) Probe() {
	if !p.HealthEnabled() {
		return
	}
	for _, b := range p.backends {
		url := p.Scheme + "://" + b.Addr + p.healthPath
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Host = p.HostHeader
		resp, err := healthClient.Do(req)
		up := err == nil && resp.StatusCode >= 200 && resp.StatusCode < 400
		if resp != nil {
			resp.Body.Close()
		}
		b.mu.Lock()
		if up {
			b.healthy = true
			b.fails = 0
			b.downUntil = time.Time{}
		} else {
			b.healthy = false
		}
		b.mu.Unlock()
	}
}

var healthCheckOnce sync.Once

// StartHealthChecks launches the single background health-check
// loop. It is safe to call repeatedly; only the first call starts
// the loop. The loop reads the live domain map each tick, so
// reloads are picked up without any bookkeeping.
func StartHealthChecks() {
	healthCheckOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(healthCheckTick)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				DomainsMap.Range(func(_, value any) bool {
					settings, _ := value.(DomainSettings)
					if settings.Pool != nil && settings.Pool.dueForCheck(now) {
						func() {
							defer func() {
								_ = recover()
							}()
							settings.Pool.Probe()
						}()
					}
					return true
				})
			}
		}()
	})
}

// WarnUnknownLBPolicy prints a startup warning for an unrecognised
// lbPolicy value. The pool itself falls back to round-robin.
func WarnUnknownLBPolicy(domainName, policy string) {
	trimmed := strings.ToLower(strings.TrimSpace(policy))
	if trimmed != "" && trimmed != "round-robin" && trimmed != "least-connections" {
		fmt.Println("[ ! ] [ Unknown lbPolicy \"" + policy + "\" for " + domainName + "; using round-robin ]")
	}
}
