package firewall

// Credential stuffing detection (Batch 8).
//
// The detector counts failed-login responses per watched path:
// a POST to a configured login path whose origin response has
// a failure status (default 401/403), or an origin signal
// reporting a failed login (see the origin-signal endpoint).
// Bodies and usernames are never inspected — only counts.
//
// Two patterns are flagged, both deliberately conservative:
//   - Per-IP: one IP accumulates PerIPThreshold failures on one
//     path within the window (default 10 in 300 seconds). A
//     human mistyping a password a few times never reaches it.
//   - Distributed: DistributedThreshold distinct IPs each
//     record at least one failure on one path within the window
//     (default 20 in 300 seconds). This is the shape of a
//     stuffing run spread across a botnet; a busy login page
//     with a few failures per IP does not reach it unless many
//     distinct clients fail at once, which is itself worth a
//     log line.
//
// The signal is LOG-ONLY by default: a flagged pattern gets one
// log entry when the threshold is first crossed in a window.
// In "block" mode a flagged request gets a suspicion bump of 2
// (toward the captcha challenge), never an outright block: the
// detector is a heuristic, and a bump preserves a path for a
// legitimate user caught in a distributed pattern.
//
// State is bounded: each (domain, path) key keeps at most
// maxStuffingEvents events, and at most maxStuffingKeys keys
// exist; the oldest key is dropped when the cap is hit. A
// reload discards all state.

import (
	"sonushield/core/domains"
	"sync"
	"time"
)

const (
	maxStuffingEvents = 10000
	maxStuffingKeys   = 1024
)

type stuffingEvent struct {
	at time.Time
	ip string
}

type stuffingKey struct {
	domain string
	path   string
}

type stuffingState struct {
	events          []stuffingEvent
	lastPerIPLog    map[string]time.Time
	lastDistLog     time.Time
	lastPrune       time.Time
}

var (
	stuffingMu     sync.Mutex
	stuffingStates = map[stuffingKey]*stuffingState{}
)

// RecordStuffingFailure records one failed login for a
// (domain, path, IP) triple. path is the matched configured
// prefix, not the raw request path, so distinct query strings
// cannot multiply keys.
func RecordStuffingFailure(domain, path, ip string) {
	if domain == "" || path == "" || ip == "" {
		return
	}
	now := time.Now()
	key := stuffingKey{domain: domain, path: path}
	stuffingMu.Lock()
	defer stuffingMu.Unlock()
	state, ok := stuffingStates[key]
	if !ok {
		if len(stuffingStates) >= maxStuffingKeys {
			// Drop the oldest-touched key.
			var oldest stuffingKey
			var oldestAt time.Time
			for k, s := range stuffingStates {
				if oldestAt.IsZero() || s.lastPrune.Before(oldestAt) {
					oldest, oldestAt = k, s.lastPrune
				}
			}
			delete(stuffingStates, oldest)
		}
		state = &stuffingState{lastPerIPLog: map[string]time.Time{}}
		stuffingStates[key] = state
	}
	state.events = append(state.events, stuffingEvent{at: now, ip: ip})
	if len(state.events) > maxStuffingEvents {
		state.events = state.events[len(state.events)-maxStuffingEvents:]
	}
	state.lastPrune = now
}

// pruneLocked drops events older than the window. The caller
// must hold stuffingMu.
func (s *stuffingState) pruneLocked(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	kept := 0
	for _, event := range s.events {
		if event.at.After(cutoff) {
			s.events[kept] = event
			kept++
		}
	}
	s.events = s.events[:kept]
	for ip, loggedAt := range s.lastPerIPLog {
		if now.Sub(loggedAt) > window {
			delete(s.lastPerIPLog, ip)
		}
	}
}

// StuffingVerdict is the outcome of checking one request.
type StuffingVerdict struct {
	Flagged bool
	Kind    string // "per_ip" or "distributed", "" when not flagged
	LogThis bool   // log once per threshold crossing per window
}

// CheckStuffing evaluates one request against the recorded
// failures for its path. Only POST requests to watched paths
// are ever checked; the caller enforces that. A nil/empty
// config reports unflagged.
func CheckStuffing(domain, path, ip string, cfg domains.StuffingConfig) StuffingVerdict {
	enabled, _, perIP, distributed, windowSeconds, _ := cfg.StuffingEffective()
	if !enabled || ip == "" {
		return StuffingVerdict{}
	}
	matched := ""
	for _, prefix := range cfg.Paths {
		if prefix != "" && len(prefix) > len(matched) && hasPrefix(path, prefix) {
			matched = prefix
		}
	}
	if matched == "" {
		return StuffingVerdict{}
	}
	window := time.Duration(windowSeconds) * time.Second
	now := time.Now()
	stuffingMu.Lock()
	defer stuffingMu.Unlock()
	state, ok := stuffingStates[stuffingKey{domain: domain, path: matched}]
	if !ok {
		return StuffingVerdict{}
	}
	state.pruneLocked(now, window)
	ipCount := 0
	distinct := map[string]bool{}
	for _, event := range state.events {
		distinct[event.ip] = true
		if event.ip == ip {
			ipCount++
		}
	}
	if ipCount >= perIP {
		logThis := false
		if last, logged := state.lastPerIPLog[ip]; !logged || now.Sub(last) > window {
			state.lastPerIPLog[ip] = now
			logThis = true
		}
		return StuffingVerdict{Flagged: true, Kind: "per_ip", LogThis: logThis}
	}
	if len(distinct) >= distributed {
		logThis := false
		if now.Sub(state.lastDistLog) > window {
			state.lastDistLog = now
			logThis = true
		}
		return StuffingVerdict{Flagged: true, Kind: "distributed", LogThis: logThis}
	}
	return StuffingVerdict{}
}

// StuffingPathStatus is one watched path's current counts.
type StuffingPathStatus struct {
	Path       string
	Failures   int
	DistinctIP int
	Flagged    bool
	Kind       string
}

// StuffingStatus reports the current window counts for a
// domain's watched paths. Counts are computed against the
// configured window; paths with no recorded failures are
// reported with zero counts so the dashboard can show the
// whole watched set.
func StuffingStatus(domain string, cfg domains.StuffingConfig) []StuffingPathStatus {
	enabled, _, perIP, distributed, windowSeconds, _ := cfg.StuffingEffective()
	if !enabled {
		return nil
	}
	window := time.Duration(windowSeconds) * time.Second
	now := time.Now()
	stuffingMu.Lock()
	defer stuffingMu.Unlock()
	out := make([]StuffingPathStatus, 0, len(cfg.Paths))
	for _, prefix := range cfg.Paths {
		status := StuffingPathStatus{Path: prefix}
		state, ok := stuffingStates[stuffingKey{domain: domain, path: prefix}]
		if ok {
			state.pruneLocked(now, window)
			distinct := map[string]bool{}
			perIPCounts := map[string]int{}
			for _, event := range state.events {
				distinct[event.ip] = true
				perIPCounts[event.ip]++
			}
			status.Failures = len(state.events)
			status.DistinctIP = len(distinct)
			for _, count := range perIPCounts {
				if count >= perIP {
					status.Flagged = true
					status.Kind = "per_ip"
					break
				}
			}
			if !status.Flagged && len(distinct) >= distributed {
				status.Flagged = true
				status.Kind = "distributed"
			}
		}
		out = append(out, status)
	}
	return out
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
