package rum

// Real-user monitoring aggregation (Batch 8).
//
// Beacons arrive at POST /_bProxy/rum (see server/rum.go)
// from the snippet served at /_bProxy/rum.js, which the
// operator embeds on origin pages. Only navigation-timing
// buckets are collected: dns, connect, tls, ttfb, dom, and
// load, each clamped to 0–60000 ms and rounded to 10 ms
// buckets. No client IP is stored, no user-agent is stored,
// and the optional path is stripped of its query string and
// capped at 256 characters. In privacy mode (Batch 7) the
// per-path breakdown is dropped entirely and only
// domain-level aggregates are kept.
//
// Storage is in-memory and bounded: per-domain histograms
// (one counter per observed 10 ms bucket per metric) and a
// per-path table capped at 100 paths per domain. A reload
// discards it. Nothing here is ever injected into origin
// content: the snippet only runs where the operator embeds
// it.

import (
	"sort"
	"sync"
)

const (
	maxBeaconMs   = 60000
	bucketMs      = 10
	maxPaths      = 100
	metricCount   = 6
)

// metric indexes into the histogram arrays.
const (
	metricDNS = iota
	metricConnect
	metricTLS
	metricTTFB
	metricDOM
	metricLoad
)

// Metric names in wire order.
var metricNames = [metricCount]string{"dns", "connect", "tls", "ttfb", "dom", "load"}

// Beacon is one validated client timing report. Values are
// already clamped and bucketed; -1 means "not reported".
type Beacon struct {
	Values [metricCount]int64
	Path   string
}

// clampBucket clamps a millisecond value to the accepted
// range and rounds it down to the bucket grid. Negative
// input means "not reported" and stays -1.
func clampBucket(ms int64) int64 {
	if ms < 0 {
		return -1
	}
	if ms > maxBeaconMs {
		ms = maxBeaconMs
	}
	return ms / bucketMs * bucketMs
}

// NewBeacon builds a Beacon from raw millisecond values
// (map from metric name to ms) and a query-stripped path.
func NewBeacon(raw map[string]int64, path string) Beacon {
	var beacon Beacon
	for i := range beacon.Values {
		beacon.Values[i] = -1
	}
	for i, name := range metricNames {
		if value, ok := raw[name]; ok {
			beacon.Values[i] = clampBucket(value)
		}
	}
	beacon.Path = path
	return beacon
}

type pathStats struct {
	count int64
	ttfb  int64
	load  int64
}

type domainStats struct {
	count      int64
	histograms [metricCount]map[int64]int64
	sums       [metricCount]int64
	seen       [metricCount]int64
	paths      map[string]*pathStats
}

var (
	mu      sync.Mutex
	domains = map[string]*domainStats{}
)

// Record adds one beacon to a domain's aggregates.
// privacyMode drops the per-path breakdown.
func Record(domain string, beacon Beacon, privacyMode bool) {
	if domain == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	stats, ok := domains[domain]
	if !ok {
		stats = &domainStats{paths: map[string]*pathStats{}}
		for i := range stats.histograms {
			stats.histograms[i] = map[int64]int64{}
		}
		domains[domain] = stats
	}
	stats.count++
	for i, value := range beacon.Values {
		if value < 0 {
			continue
		}
		stats.histograms[i][value]++
		stats.sums[i] += value
		stats.seen[i]++
	}
	if privacyMode || beacon.Path == "" {
		return
	}
	pathEntry, ok := stats.paths[beacon.Path]
	if !ok {
		if len(stats.paths) >= maxPaths {
			return
		}
		pathEntry = &pathStats{}
		stats.paths[beacon.Path] = pathEntry
	}
	pathEntry.count++
	if beacon.Values[metricTTFB] >= 0 {
		pathEntry.ttfb += beacon.Values[metricTTFB]
	}
	if beacon.Values[metricLoad] >= 0 {
		pathEntry.load += beacon.Values[metricLoad]
	}
}

// MetricStats is the aggregate for one timing metric.
type MetricStats struct {
	Samples int64
	Average int64
	P50     int64
	P95     int64
}

// PathStats is the aggregate for one path.
type PathStats struct {
	Path      string
	Count     int64
	AvgTTFB   int64
	AvgLoad   int64
}

// Stats is the full aggregate view for a domain.
type Stats struct {
	Count   int64
	Metrics map[string]MetricStats
	Paths   []PathStats
}

// Snapshot returns the aggregates for a domain. Paths are
// the top 10 by beacon count.
func Snapshot(domain string) Stats {
	mu.Lock()
	defer mu.Unlock()
	stats, ok := domains[domain]
	if !ok {
		return Stats{Metrics: map[string]MetricStats{}}
	}
	out := Stats{Count: stats.count, Metrics: map[string]MetricStats{}}
	for i, name := range metricNames {
		metric := MetricStats{Samples: stats.seen[i]}
		if stats.seen[i] > 0 {
			metric.Average = stats.sums[i] / stats.seen[i]
			metric.P50 = percentile(stats.histograms[i], stats.seen[i], 50)
			metric.P95 = percentile(stats.histograms[i], stats.seen[i], 95)
		}
		out.Metrics[name] = metric
	}
	for path, entry := range stats.paths {
		pathStats := PathStats{Path: path, Count: entry.count}
		if entry.count > 0 {
			pathStats.AvgTTFB = entry.ttfb / entry.count
			pathStats.AvgLoad = entry.load / entry.count
		}
		out.Paths = append(out.Paths, pathStats)
	}
	sort.Slice(out.Paths, func(i, j int) bool { return out.Paths[i].Count > out.Paths[j].Count })
	if len(out.Paths) > 10 {
		out.Paths = out.Paths[:10]
	}
	return out
}

func percentile(histogram map[int64]int64, total int64, pct int) int64 {
	if total <= 0 {
		return 0
	}
	threshold := (total*int64(pct) + 99) / 100
	if threshold < 1 {
		threshold = 1
	}
	buckets := make([]int64, 0, len(histogram))
	for bucket := range histogram {
		buckets = append(buckets, bucket)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i] < buckets[j] })
	var seen int64
	for _, bucket := range buckets {
		seen += histogram[bucket]
		if seen >= threshold {
			return bucket
		}
	}
	return buckets[len(buckets)-1]
}
