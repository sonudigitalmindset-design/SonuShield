package firewall

// Timing and velocity detection (Batch 5).
//
// ObserveTiming records one request timestamp per IP and reports
// whether the IP's recent timing looks inhuman. Two shapes are
// detected, both deliberately conservative so legitimate traffic
// is not flagged:
//
//   - "regular": at least 12 recent requests with very even
//     spacing (coefficient of variation under 0.08) at a mean
//     interval under 500ms. Human browsing and page loads are
//     bursty and irregular; slow, exact polling (1s or slower,
//     e.g. a dashboard auto-refresh) is below the rate bar and
//     is never flagged.
//   - "burst": 50 or more requests inside one second from one
//     IP. Asset-heavy page loads stay under this bar; floods
//     do not.
//
// The signal is LOG-ONLY by default: a flagged IP gets a
// "timing" structured-log entry (at most one per IP per minute,
// and only when JSON logging is configured) and a +20 risk-score
// contribution, but no request is challenged or blocked because
// of timing alone. Enforcement is opt-in per domain
// (timingEnforce): flagged requests get a suspicion bump
// (timingSusLv, default 1). The classification is also a
// firewall rule field (ip.timing: "", "regular", or "burst").
//
// State is bounded: one small record per recently seen IP, swept
// every minute, with a hard cap on tracked IPs. Tracking itself
// is always on — it is one timestamp store per request — because
// the signal must exist before an operator can decide to enforce
// it; it changes no request outcome on its own.

import (
	"math"
	"sync"
	"time"
)

const (
	timingRingSize   = 16
	timingMinSamples = 12
	timingMaxCV      = 0.08
	timingMaxMean    = 500 * time.Millisecond
	timingBurstCount = 50
	timingBurstSpan  = time.Second
	timingMaxIPs     = 50000
	timingIdleTTL    = time.Minute
	timingLogEvery   = time.Minute
)

// TimingVerdict is the result of observing one request.
type TimingVerdict struct {
	// Kind is "", "regular", or "burst".
	Kind string
	// Anomaly is true when Kind is not "".
	Anomaly bool
	// LogThis is true when this observation should produce a
	// "timing" log entry (rate-limited to one per IP per minute).
	LogThis bool
}

type timingState struct {
	ring       [timingRingSize]time.Time
	count      int
	head       int
	burstStart time.Time
	burstCount int
	lastLog    time.Time
	lastSeen   time.Time
}

var (
	timingMu    sync.Mutex
	timingIPs   = map[string]*timingState{}
	timingSweep sync.Once
)

// ObserveTiming records a request from ip and classifies its
// recent timing. It never blocks and never fails: on any internal
// problem it reports no anomaly.
func ObserveTiming(ip string) TimingVerdict {
	if ip == "" {
		return TimingVerdict{}
	}
	timingSweep.Do(func() { go timingSweepLoop() })
	now := time.Now()

	timingMu.Lock()
	defer timingMu.Unlock()

	state, ok := timingIPs[ip]
	if !ok {
		if len(timingIPs) >= timingMaxIPs {
			// Bounded: untracked IPs are simply not
			// classified. Fail-open.
			return TimingVerdict{}
		}
		state = &timingState{}
		timingIPs[ip] = state
	}
	state.lastSeen = now

	// Burst window: fixed 1-second window, reset when stale.
	if state.burstCount == 0 || now.Sub(state.burstStart) > timingBurstSpan {
		state.burstStart = now
		state.burstCount = 0
	}
	state.burstCount++

	// Regularity ring.
	state.ring[state.head] = now
	state.head = (state.head + 1) % timingRingSize
	if state.count < timingRingSize {
		state.count++
	}

	verdict := TimingVerdict{}
	if state.burstCount >= timingBurstCount {
		verdict.Kind = "burst"
	} else if isRegular(state) {
		verdict.Kind = "regular"
	}
	if verdict.Kind == "" {
		return verdict
	}
	verdict.Anomaly = true
	if now.Sub(state.lastLog) >= timingLogEvery {
		state.lastLog = now
		verdict.LogThis = true
	}
	return verdict
}

// isRegular reports whether the stored timestamps are spaced
// almost perfectly evenly at a fast rate. The caller holds
// timingMu.
func isRegular(state *timingState) bool {
	if state.count < timingMinSamples {
		return false
	}
	// Read the ring oldest-first.
	stamps := make([]time.Time, 0, state.count)
	for i := 0; i < state.count; i++ {
		idx := (state.head - state.count + i + timingRingSize*2) % timingRingSize
		stamps = append(stamps, state.ring[idx])
	}
	var sum float64
	intervals := make([]float64, 0, len(stamps)-1)
	for i := 1; i < len(stamps); i++ {
		d := stamps[i].Sub(stamps[i-1]).Seconds()
		if d < 0 {
			return false
		}
		intervals = append(intervals, d)
		sum += d
	}
	mean := sum / float64(len(intervals))
	if mean <= 0 || mean > timingMaxMean.Seconds() {
		return false
	}
	var variance float64
	for _, d := range intervals {
		diff := d - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	cv := math.Sqrt(variance) / mean
	return cv < timingMaxCV
}

// timingSweepLoop drops IPs idle for over a minute so the map
// stays bounded for keys that never return.
func timingSweepLoop() {
	for {
		time.Sleep(time.Minute)
		cutoff := time.Now().Add(-timingIdleTTL)
		timingMu.Lock()
		for ip, state := range timingIPs {
			if state.lastSeen.Before(cutoff) {
				delete(timingIPs, ip)
			}
		}
		timingMu.Unlock()
	}
}
