package domains

// Fair queuing (Batch 7).
//
// Under overload, backend capacity is shared fairly across
// client IPs so one aggressive client cannot starve others.
// The algorithm is round-robin admission over per-IP FIFO
// queues, with a global cap on in-flight origin requests:
//
//   - Each client IP has its own FIFO queue. When a request
//     arrives and a slot is free and nobody is waiting, it
//     is admitted immediately (the fast path: at normal load
//     the queue adds one mutex acquisition and no waiting).
//   - When all slots are busy, the request waits in its IP's
//     queue. Each time a slot frees, the next IP in
//     round-robin order (first-seen order, advancing one IP
//     per admission) has its head request admitted. A client
//     with 100 queued requests gets one admission per round,
//     exactly like a client with one queued request.
//   - A waiter that is not admitted within fairQueueWaitMs
//     (default 5000ms) gets a 503 with Retry-After. The total
//     number of waiters is capped; beyond the cap, requests
//     are rejected immediately with the same 503.
//
// Honest limits: this is request-count fairness with equal
// weights (equivalent to deficit round-robin with quantum 1).
// It does not weight by request cost, response size, or
// backend time, and it does not know how busy the origin
// actually is — the cap is the operator's estimate of backend
// capacity. Only origin-bound traffic is queued: cache hits,
// waiting-room answers, challenges, and reserved paths return
// before the gate, and WebSocket upgrades bypass it (they hold
// a connection indefinitely, so queueing them would stall the
// queue). The queue is per-domain, in-memory, and rebuilt on
// reload, like the other runtime state.
//
// Acquire is nil-safe: a nil queue (feature disabled, or the
// "debug" pseudo-domain) admits immediately.

import (
	"sync"
	"time"
)

// fairQueueMaxWaiters caps the total number of requests
// waiting across all IPs for one domain.
const fairQueueMaxWaiters = 4096

type fairWaiter struct {
	ready chan struct{}
}

// FairQueue is a per-domain fair admission queue.
type FairQueue struct {
	mu           sync.Mutex
	maxInflight  int
	waitTimeout  time.Duration
	inFlight     int
	queues       map[string][]*fairWaiter
	order        []string
	lastServed   int
	totalWaiting int
}

// NewFairQueue builds the queue for a domain, or nil when the
// feature is disabled or the cap is not positive.
func NewFairQueue(enabled bool, maxInflight, waitMs int) *FairQueue {
	if !enabled || maxInflight <= 0 {
		return nil
	}
	if waitMs <= 0 {
		waitMs = 5000
	}
	return &FairQueue{
		maxInflight: maxInflight,
		waitTimeout: time.Duration(waitMs) * time.Millisecond,
		queues:      map[string][]*fairWaiter{},
	}
}

// Acquire waits for an origin slot for ip. When admitted it
// returns a release function the caller must call exactly once
// when the origin request finishes. When not admitted
// (timeout or queue full) it returns admitted=false and the
// caller must answer 503.
func (q *FairQueue) Acquire(ip string) (release func(), admitted bool) {
	if q == nil {
		return func() {}, true
	}
	q.mu.Lock()
	if q.inFlight < q.maxInflight && q.totalWaiting == 0 {
		q.inFlight++
		q.mu.Unlock()
		return q.release, true
	}
	if q.totalWaiting >= fairQueueMaxWaiters {
		q.mu.Unlock()
		return nil, false
	}
	w := &fairWaiter{ready: make(chan struct{})}
	if _, ok := q.queues[ip]; !ok {
		q.queues[ip] = nil
		q.order = append(q.order, ip)
	}
	q.queues[ip] = append(q.queues[ip], w)
	q.totalWaiting++
	q.compactOrderLocked()
	q.mu.Unlock()

	timer := time.NewTimer(q.waitTimeout)
	defer timer.Stop()
	select {
	case <-w.ready:
		return q.release, true
	case <-timer.C:
		// Either still queued (removed, slot untouched) or
		// admitted concurrently (slot handed on inside
		// removeWaiter). Either way this caller is not
		// admitted and must not release.
		q.removeWaiter(ip, w)
		return nil, false
	}
}

// release returns one slot and admits the next waiter in
// round-robin order. It is called exactly once per admission.
func (q *FairQueue) release() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.inFlight--
	if q.inFlight < 0 {
		q.inFlight = 0
	}
	q.admitNextLocked()
}

// removeWaiter takes a timed-out waiter out of its queue. When
// the waiter was already admitted concurrently, the slot is
// returned and the next waiter is admitted instead.
func (q *FairQueue) removeWaiter(ip string, w *fairWaiter) {
	q.mu.Lock()
	defer q.mu.Unlock()
	queue := q.queues[ip]
	for i, cand := range queue {
		if cand == w {
			q.queues[ip] = append(queue[:i], queue[i+1:]...)
			if len(q.queues[ip]) == 0 {
				delete(q.queues, ip)
			}
			q.totalWaiting--
			return
		}
	}
	q.inFlight--
	if q.inFlight < 0 {
		q.inFlight = 0
	}
	q.admitNextLocked()
}

// admitNextLocked admits one waiter from the next non-empty IP
// queue in round-robin order. The caller holds q.mu.
func (q *FairQueue) admitNextLocked() {
	if q.inFlight >= q.maxInflight || q.totalWaiting == 0 {
		return
	}
	n := len(q.order)
	for scanned := 0; scanned < n; scanned++ {
		q.lastServed = (q.lastServed + 1) % n
		ip := q.order[q.lastServed]
		queue := q.queues[ip]
		if len(queue) == 0 {
			continue
		}
		w := queue[0]
		q.queues[ip] = queue[1:]
		if len(q.queues[ip]) == 0 {
			delete(q.queues, ip)
		}
		q.totalWaiting--
		q.inFlight++
		close(w.ready)
		return
	}
}

// compactOrderLocked rebuilds the round-robin order from the
// IPs that currently have queues, dropping stale entries so
// the order cannot grow without bound over the process
// lifetime. The caller holds q.mu.
func (q *FairQueue) compactOrderLocked() {
	if len(q.order) <= 4096 || len(q.queues) >= len(q.order)/4 {
		return
	}
	order := make([]string, 0, len(q.queues))
	for ip := range q.queues {
		order = append(order, ip)
	}
	q.order = order
	q.lastServed = 0
}

// FairQueueStats returns the current queue depth for
// diagnostics: in-flight count and total waiters.
func (q *FairQueue) FairQueueStats() (inFlight, waiting int) {
	if q == nil {
		return 0, 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.inFlight, q.totalWaiting
}
