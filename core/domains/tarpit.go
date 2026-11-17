package domains

import "time"

// TarpitLimiter delays responses to confirmed-bad requests.
//
// When a request's suspicion level reaches the configured
// threshold, the proxy sleeps for the configured delay before
// answering with the block message. Slowing the response down
// wastes the attacker's time and connection slots while costing
// the proxy almost nothing — but only up to a point: the number
// of simultaneously tarpitted requests is capped by a semaphore,
// so a flood of tarpitted connections can never exhaust the
// proxy's workers. When the cap is reached, further blocks are
// answered immediately instead of waiting.
//
// The limiter is nil when the tarpit is disabled (no delay or no
// threshold configured), and Apply on a nil limiter is a no-op,
// so callers never need a nil check. The tarpit only ever applies
// to requests that are already going to be blocked; legitimate
// visitors never see a delay.
type TarpitLimiter struct {
	delay     time.Duration
	threshold int
	sem       chan struct{}
}

const (
	defaultTarpitMaxConns = 64
	maxTarpitMaxConns     = 1024
	maxTarpitDelay        = 30 * time.Second
)

// NewTarpitLimiter builds a limiter from the domain config. It
// returns nil when the tarpit is disabled.
func NewTarpitLimiter(delayMs, threshold, maxConns int) *TarpitLimiter {
	if delayMs <= 0 || threshold <= 0 {
		return nil
	}
	delay := time.Duration(delayMs) * time.Millisecond
	if delay > maxTarpitDelay {
		delay = maxTarpitDelay
	}
	if maxConns <= 0 {
		maxConns = defaultTarpitMaxConns
	}
	if maxConns > maxTarpitMaxConns {
		maxConns = maxTarpitMaxConns
	}
	return &TarpitLimiter{
		delay:     delay,
		threshold: threshold,
		sem:       make(chan struct{}, maxConns),
	}
}

// Apply sleeps for the configured delay when susLv reaches the
// threshold and a tarpit slot is free. It returns immediately
// when the limiter is nil, the level is below the threshold, or
// all slots are in use.
func (l *TarpitLimiter) Apply(susLv int) {
	if l == nil || susLv < l.threshold {
		return
	}
	select {
	case l.sem <- struct{}{}:
		defer func() { <-l.sem }()
		time.Sleep(l.delay)
	default:
	}
}
