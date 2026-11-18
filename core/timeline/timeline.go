package timeline

// Attack timeline store (Batch 7).
//
// This package holds only the per-domain timeline rings and
// finished-attack history, so the server package (which
// records events from the attack monitor) and the API package
// (which serves GET_POSTMORTEM) can share it without an
// import cycle. No new data is collected: events are recorded
// at the state-change points the monitor already computes
// (attack start/end, stage changes), and peaks come from the
// counters the monitor already maintains.
//
// An "attack" is the period between the monitor's attack_start
// and attack_end decisions. Events recorded while no attack
// is active start an implicit attack, so a stage change is
// never lost; ending with no active attack is a no-op.
// History keeps the 10 most recent finished attacks per
// domain; each attack keeps at most 200 events.

import (
	"sync"
	"time"
)

// Event is one timeline entry.
type Event struct {
	Time       time.Time
	Kind       string // "attack_start", "attack_end", "stage_change"
	Detail     string
	Stage      int
	RPS        int
	RPSAllowed int
}

// Attack is one attack's timeline plus its summary.
type Attack struct {
	Start          time.Time
	End            time.Time
	PeakRPS        int
	PeakRPSAllowed int
	MaxStage       int
	Events         []Event
	Finished       bool
}

const (
	maxEventsPerAttack  = 200
	maxHistoryPerDomain = 10
)

type domainTimeline struct {
	current *Attack
	history []Attack
}

var (
	mu        sync.Mutex
	timelines = map[string]*domainTimeline{}
)

func forDomainLocked(domain string) *domainTimeline {
	tl, ok := timelines[domain]
	if !ok {
		tl = &domainTimeline{}
		timelines[domain] = tl
	}
	return tl
}

// StartAttack begins a new current attack for the domain,
// recording the start event. If an attack is already active,
// the event is appended to it instead of starting a second
// one: the monitor's start decisions are the source of truth,
// and a duplicate start must not split the timeline.
func StartAttack(domain string, event Event) {
	if domain == "" {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	mu.Lock()
	defer mu.Unlock()
	tl := forDomainLocked(domain)
	if tl.current == nil {
		tl.current = &Attack{
			Start:    event.Time,
			MaxStage: event.Stage,
		}
	}
	appendEventLocked(tl.current, event)
}

// RecordEvent appends an event to the current attack,
// starting an implicit attack when none is active.
func RecordEvent(domain string, event Event) {
	if domain == "" {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	mu.Lock()
	defer mu.Unlock()
	tl := forDomainLocked(domain)
	if tl.current == nil {
		tl.current = &Attack{
			Start:    event.Time,
			MaxStage: event.Stage,
		}
	}
	appendEventLocked(tl.current, event)
}

// EndAttack finishes the current attack, recording the end
// event and the monitor's peaks, and moves it to history.
// With no active attack it is a no-op.
func EndAttack(domain string, event Event, peakRPS, peakRPSAllowed int) {
	if domain == "" {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	mu.Lock()
	defer mu.Unlock()
	tl := forDomainLocked(domain)
	if tl.current == nil {
		return
	}
	appendEventLocked(tl.current, event)
	tl.current.End = event.Time
	tl.current.PeakRPS = peakRPS
	tl.current.PeakRPSAllowed = peakRPSAllowed
	tl.current.Finished = true
	tl.history = append(tl.history, *tl.current)
	if len(tl.history) > maxHistoryPerDomain {
		tl.history = tl.history[len(tl.history)-maxHistoryPerDomain:]
	}
	tl.current = nil
}

// appendEventLocked appends an event, updating the max stage
// and trimming the ring. The caller holds mu.
func appendEventLocked(attack *Attack, event Event) {
	if event.Stage > attack.MaxStage {
		attack.MaxStage = event.Stage
	}
	attack.Events = append(attack.Events, event)
	if len(attack.Events) > maxEventsPerAttack {
		attack.Events = attack.Events[len(attack.Events)-maxEventsPerAttack:]
	}
}

// Current returns a copy of the active attack, if any.
func Current(domain string) (Attack, bool) {
	mu.Lock()
	defer mu.Unlock()
	tl, ok := timelines[domain]
	if !ok || tl.current == nil {
		return Attack{}, false
	}
	return copyAttack(*tl.current), true
}

// Last returns a copy of the most recent finished attack, if
// any.
func Last(domain string) (Attack, bool) {
	mu.Lock()
	defer mu.Unlock()
	tl, ok := timelines[domain]
	if !ok || len(tl.history) == 0 {
		return Attack{}, false
	}
	return copyAttack(tl.history[len(tl.history)-1]), true
}

// History returns copies of all finished attacks, oldest
// first.
func History(domain string) []Attack {
	mu.Lock()
	defer mu.Unlock()
	tl, ok := timelines[domain]
	if !ok {
		return nil
	}
	out := make([]Attack, 0, len(tl.history))
	for _, attack := range tl.history {
		out = append(out, copyAttack(attack))
	}
	return out
}

// copyAttack deep-copies the events slice.
func copyAttack(attack Attack) Attack {
	attack.Events = append([]Event(nil), attack.Events...)
	return attack
}
