package logging

// Live log tail subscriptions (Batch 8).
//
// The SSE endpoint (core/api/tail.go) subscribes here to
// receive sanitized log entries as they are written. The
// subscription hook lives in Log(), so tail entries are the
// same sanitized entries the file logger writes: query
// strings stripped, user-agents truncated, privacy mode
// applied. Audit entries are NOT broadcast: Audit writes
// through writeLine directly and never passes through Log.
// Subscribers work even when file logging is disabled: the
// tail is a live view, not a file reader.
//
// Delivery is best-effort and bounded: each subscriber has a
// 100-entry buffer, at most 16 subscribers may attach, and a
// full buffer drops new entries for that subscriber rather
// than blocking the request path. A dropped entry is lost
// silently; the tail is a live view, not an audit trail.

import "sync"

const (
	maxTailSubscribers = 16
	tailBufferSize     = 100
)

var (
	tailMu          sync.Mutex
	tailSubscribers = map[chan Entry]struct{}{}
)

// Subscribe attaches a live-tail subscriber. It reports false
// when the subscriber cap is reached; the caller should then
// answer 503. The returned unsubscribe function must be
// called when the stream ends.
func Subscribe() (chan Entry, func(), bool) {
	tailMu.Lock()
	defer tailMu.Unlock()
	if len(tailSubscribers) >= maxTailSubscribers {
		return nil, nil, false
	}
	ch := make(chan Entry, tailBufferSize)
	tailSubscribers[ch] = struct{}{}
	return ch, func() {
		tailMu.Lock()
		defer tailMu.Unlock()
		delete(tailSubscribers, ch)
		close(ch)
	}, true
}

// hasTailSubscribers reports whether any subscriber is
// attached. Used by Log to skip work when nobody is
// listening and file logging is off.
func hasTailSubscribers() bool {
	tailMu.Lock()
	defer tailMu.Unlock()
	return len(tailSubscribers) > 0
}

// broadcastTail delivers a sanitized entry to every
// subscriber, dropping it for any subscriber whose buffer is
// full. It never blocks.
func broadcastTail(entry Entry) {
	tailMu.Lock()
	defer tailMu.Unlock()
	for ch := range tailSubscribers {
		select {
		case ch <- entry:
		default:
		}
	}
}
