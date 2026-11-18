package events

// Event model (Batch 6).
//
// Events are the fan-out record for attack transitions and
// control-plane audit actions. They carry operational facts
// only: domain and tenant names, stages, counters, the audit
// action and its already-scrubbed parameters. Secrets never
// appear in an event: audit parameters reuse the audit log's
// scrubbing (see core/api scrubParams), and no publisher
// includes credentials, keys, or tokens.

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Event types.
const (
	// TypeAttackStart fires when an attack is detected.
	TypeAttackStart = "attack.start"
	// TypeAttackStop fires when an attack ends.
	TypeAttackStop = "attack.stop"
	// TypeAudit fires for control API actions, including
	// rejected unauthenticated calls.
	TypeAudit = "audit"
	// TypeTest fires only from the TEST_WEBHOOKS action.
	TypeTest = "test"
)

// ValidType reports whether t is a known event type.
func ValidType(t string) bool {
	switch t {
	case TypeAttackStart, TypeAttackStop, TypeAudit, TypeTest:
		return true
	default:
		return false
	}
}

// Event is one fan-out record. Data holds type-specific
// fields; see the Publish* constructors for the shapes.
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Domain    string                 `json:"domain,omitempty"`
	Tenant    string                 `json:"tenant,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// NewEvent builds an event with a random id and the current
// UTC time.
func NewEvent(eventType, domain, tenant string, data map[string]interface{}) Event {
	return Event{
		ID:        newID(),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Domain:    domain,
		Tenant:    tenant,
		Data:      data,
	}
}

func newID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return hex.EncodeToString(buf[:])
	}
	// Crypto randomness is effectively never unavailable; fall
	// back to a time-based id rather than an empty one.
	return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
}
