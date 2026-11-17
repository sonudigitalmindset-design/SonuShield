package domains

// Per-API-key rate limiting (Batch 4).
//
// API keys are operator-configured ("apiKeys" in config.json).
// Each key has its own per-minute request budget on the routes
// listed in "apiKeyPaths". Keys are compared in constant time
// against the configured list, and usage is counted in fixed
// 60-second windows aligned to the wall clock. A key with a
// limit of 0 or less is unlimited. Unknown or missing keys are
// rejected; the key value is never logged.

import (
	"crypto/subtle"
	"sync"
	"time"
)

// APIKeyConfig is one operator-configured API key.
type APIKeyConfig struct {
	Key            string `json:"key"`
	Name           string `json:"name"`
	LimitPerMinute int    `json:"limitPerMinute"`
}

type apiKeyEntry struct {
	config      APIKeyConfig
	windowStart int64
	count       int
}

// APIKeyState holds one domain's API keys and their counters.
type APIKeyState struct {
	entries []*apiKeyEntry
	mu      sync.Mutex
}

// NewAPIKeyState builds the state, or returns nil when no keys
// with a non-empty value are configured. Entries with an empty
// key are dropped: an empty key must never authenticate.
func NewAPIKeyState(keys []APIKeyConfig) *APIKeyState {
	state := &APIKeyState{}
	for _, key := range keys {
		if key.Key == "" {
			continue
		}
		state.entries = append(state.entries, &apiKeyEntry{config: key})
	}
	if len(state.entries) == 0 {
		return nil
	}
	return state
}

// Check verifies a presented key. It returns (true, true) when
// the key is known and within its budget, (false, true) when
// the key is known but over budget, and (false, false) when the
// key is unknown. The counter is only incremented on success.
func (s *APIKeyState) Check(presented string) (allowed, known bool) {
	if s == nil || presented == "" {
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if len(presented) != len(entry.config.Key) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(entry.config.Key)) != 1 {
			continue
		}
		if entry.config.LimitPerMinute <= 0 {
			return true, true
		}
		window := time.Now().Unix() / 60
		if entry.windowStart != window {
			entry.windowStart = window
			entry.count = 0
		}
		if entry.count >= entry.config.LimitPerMinute {
			return false, true
		}
		entry.count++
		return true, true
	}
	return false, false
}
