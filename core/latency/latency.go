package latency

// Latency sample store (Batch 7).
//
// This package holds only the per-domain sample rings and the
// percentile math, so both the server package (which records
// samples in the RoundTripper) and the API package (which
// serves GET_LATENCY) can use it without an import cycle. The
// measurement-point documentation lives with the recording
// code in core/server/latency.go.

import (
	"sort"
	"sync"
	"time"
)

type sample struct {
	ttfb   time.Duration
	total  time.Duration
	proxy  time.Duration
	status int
	err    bool
	at     time.Time
}

// Stats is a computed summary over the retained window.
type Stats struct {
	Samples     int64
	Errors      int64
	Status5xx   int64
	TTFBP50     time.Duration
	TTFBP95     time.Duration
	TTFBP99     time.Duration
	TotalP50    time.Duration
	TotalP95    time.Duration
	TotalP99    time.Duration
	ProxyMean   time.Duration
	SuccessRate float64 // 0-100, over the retained window
	WindowStart time.Time
	WindowEnd   time.Time
}

// RingSize is the number of samples retained per domain.
const RingSize = 512

var (
	mu    sync.Mutex
	rings = map[string][]sample{}
)

// Record stores one origin sample for a domain.
func Record(domain string, ttfb, total, proxy time.Duration, status int, transportErr bool) {
	if domain == "" {
		return
	}
	if proxy < 0 {
		proxy = 0
	}
	if total < ttfb {
		total = ttfb
	}
	mu.Lock()
	defer mu.Unlock()
	ring := append(rings[domain], sample{
		ttfb: ttfb, total: total, proxy: proxy,
		status: status, err: transportErr, at: time.Now(),
	})
	if len(ring) > RingSize {
		ring = ring[len(ring)-RingSize:]
	}
	rings[domain] = ring
}

// StatsFor computes the summary over the retained window for
// a domain. Empty windows yield zero stats.
func StatsFor(domain string) Stats {
	mu.Lock()
	ring := append([]sample(nil), rings[domain]...)
	mu.Unlock()

	stats := Stats{}
	if len(ring) == 0 {
		return stats
	}
	stats.Samples = int64(len(ring))
	stats.WindowStart = ring[0].at
	stats.WindowEnd = ring[len(ring)-1].at

	ttfbs := make([]time.Duration, 0, len(ring))
	totals := make([]time.Duration, 0, len(ring))
	var proxySum time.Duration
	var successes int64
	for _, s := range ring {
		ttfbs = append(ttfbs, s.ttfb)
		totals = append(totals, s.total)
		proxySum += s.proxy
		if s.err {
			stats.Errors++
		} else if s.status >= 500 {
			stats.Status5xx++
		} else {
			successes++
		}
	}
	sort.Slice(ttfbs, func(i, j int) bool { return ttfbs[i] < ttfbs[j] })
	sort.Slice(totals, func(i, j int) bool { return totals[i] < totals[j] })
	stats.TTFBP50 = percentile(ttfbs, 0.50)
	stats.TTFBP95 = percentile(ttfbs, 0.95)
	stats.TTFBP99 = percentile(ttfbs, 0.99)
	stats.TotalP50 = percentile(totals, 0.50)
	stats.TotalP95 = percentile(totals, 0.95)
	stats.TotalP99 = percentile(totals, 0.99)
	stats.ProxyMean = proxySum / time.Duration(len(ring))
	stats.SuccessRate = float64(successes) * 100 / float64(len(ring))
	return stats
}

// percentile returns the nearest-rank percentile of a sorted
// slice. Empty slices yield zero.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(p*float64(len(sorted)) + 0.5)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
