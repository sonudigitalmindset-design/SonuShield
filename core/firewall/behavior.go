package firewall

// Mouse/scroll behavior signal (Batch 7).
//
// The proxy's own challenge pages can report three coarse,
// privacy-respecting facts about the visitor's interaction with
// the page: whether the mouse moved at all, whether the page
// scrolled at all, and which elapsed-time bucket the visit fell
// into (fast/medium/slow). Nothing else is collected: no
// coordinates, no movement paths, no keystrokes, no timing
// traces, no cross-site tracking, and no identifier beyond the
// existing challenge flow. The script runs ONLY on challenge
// pages the proxy itself serves, and only when the operator
// enables behaviorCheck for the domain.
//
// Classification is deliberately conservative:
//
//   - "human": the mouse moved or the page scrolled. A
//     human verdict confers no advantage; it only means "not
//     a bot signal".
//   - "bot": no mouse movement, no scrolling, AND the fast
//     elapsed bucket (under 1.5s). A headless solver that
//     loads the page, solves, and leaves in under 1.5 seconds
//     without any pointer interaction.
//   - no verdict: no beacon received, or no interaction but a
//     slow/medium visit. Keyboard-only users, screen-reader
//     users, and slow solvers are never flagged: absence of
//     pointer input alone is not evidence of automation.
//
// The signal is weak by design — it is client-reported, and a
// determined bot can fake it — so it is LOG-ONLY by default: a
// "behavior" log entry and a +15 risk-score contribution, and
// the ip.behavior rule field. Enforcement is opt-in per domain
// (behaviorEnforce): flagged requests get a suspicion bump
// (behaviorSusLv, default 1).
//
// State is bounded: one small record per domain+IP, 10-minute
// TTL, swept every minute, with a hard cap on tracked keys.

import (
	"sync"
	"time"
)

const (
	behaviorTTL     = 10 * time.Minute
	behaviorMaxKeys = 50000
	behaviorIdleTTL = time.Minute
)

// BehaviorRecord is one beacon's coarse facts.
type BehaviorRecord struct {
	Mouse   bool
	Scroll  bool
	Elapsed string // "fast", "medium", or "slow"
	At      time.Time
	logged  bool
}

var (
	behaviorMu    sync.Mutex
	behaviorRecs  = map[string]*BehaviorRecord{}
	behaviorSweep sync.Once
)

func behaviorKey(domain, ip string) string {
	return domain + "\x00" + ip
}

// RecordBehavior stores one beacon's facts for a domain+IP.
// An unrecognised elapsed bucket is treated as "slow"
// (inconclusive): malformed input must never create a bot
// verdict.
func RecordBehavior(domain, ip string, mouse, scroll bool, elapsed string) {
	if domain == "" || ip == "" {
		return
	}
	switch elapsed {
	case "fast", "medium", "slow":
	default:
		elapsed = "slow"
	}
	behaviorSweep.Do(func() { go behaviorSweepLoop() })
	behaviorMu.Lock()
	defer behaviorMu.Unlock()
	key := behaviorKey(domain, ip)
	if _, ok := behaviorRecs[key]; !ok && len(behaviorRecs) >= behaviorMaxKeys {
		// Bounded: untracked keys are simply not
		// classified. Fail-open.
		return
	}
	behaviorRecs[key] = &BehaviorRecord{
		Mouse:   mouse,
		Scroll:  scroll,
		Elapsed: elapsed,
		At:      time.Now(),
	}
}

// BehaviorVerdict classifies the stored beacon for a domain+IP.
// It returns the verdict ("", "human", or "bot") and whether
// this observation should produce a log entry: a bot verdict
// logs once per record.
func BehaviorVerdict(domain, ip string) (verdict string, logThis bool) {
	behaviorMu.Lock()
	defer behaviorMu.Unlock()
	rec, ok := behaviorRecs[behaviorKey(domain, ip)]
	if !ok || time.Since(rec.At) > behaviorTTL {
		return "", false
	}
	if rec.Mouse || rec.Scroll {
		return "human", false
	}
	if rec.Elapsed != "fast" {
		return "", false
	}
	if !rec.logged {
		rec.logged = true
		return "bot", true
	}
	return "bot", false
}

// behaviorSweepLoop drops records idle past their TTL so the
// map stays bounded for keys that never return.
func behaviorSweepLoop() {
	for {
		time.Sleep(time.Minute)
		cutoff := time.Now().Add(-behaviorTTL)
		behaviorMu.Lock()
		for key, rec := range behaviorRecs {
			if rec.At.Before(cutoff) {
				delete(behaviorRecs, key)
			}
		}
		behaviorMu.Unlock()
	}
}
