// Package maintenance holds the on-demand maintenance-mode
// override state (Batch 7). It is neutral: the server
// package checks it on every request, the API package sets
// it, and neither may import the other.
//
// The override is in-memory only and survives config
// reloads: an operator who enables maintenance for an
// emergency deploy does not lose it to an unrelated reload.
// It does not survive a process restart. Scheduled windows
// (from the domain configuration) are evaluated separately
// by the server package; either source can put a domain
// into maintenance.
package maintenance

import (
	"sync"
	"time"
)

// State is one domain's override state.
type State struct {
	Enabled bool      `json:"enabled"`
	Message string    `json:"message"`
	Until   time.Time `json:"until,omitempty"` // Zero = until disabled.
}

var (
	mu     sync.RWMutex
	states = map[string]State{}
)

// Set records the override for domain. An empty message
// clears the stored message (the page falls back to its
// default text). A zero until means "until disabled".
func Set(domain string, enabled bool, message string, until time.Time) {
	mu.Lock()
	defer mu.Unlock()
	states[domain] = State{Enabled: enabled, Message: message, Until: until}
}

// Get returns the stored override for domain, if any.
func Get(domain string) (State, bool) {
	mu.RLock()
	defer mu.RUnlock()
	state, ok := states[domain]
	return state, ok
}

// Active reports whether the override is in effect for
// domain at now, and the message to show. An expired
// override is inactive.
func Active(domain string, now time.Time) (bool, string) {
	mu.RLock()
	defer mu.RUnlock()
	state, ok := states[domain]
	if !ok || !state.Enabled {
		return false, ""
	}
	if !state.Until.IsZero() && !now.Before(state.Until) {
		return false, ""
	}
	return true, state.Message
}

// Reset clears all override state. It exists for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	states = map[string]State{}
}
