// Package shared provides the optional multi-server state
// backend (Batch 3): a Redis-backed store for per-IP rate-limit
// counts and, when enabled, the challenge-result cache
// (CacheIps). It is inert unless the operator configures
// proxy.redis in config.json; with Redis disabled every
// package-level function is a no-op and the proxy behaves
// exactly as before.
//
// Design:
//
//   - Rate-limit counts are recorded locally first (one map
//     write per request, no network round trip in the hot
//     path) and flushed to Redis once a second with a
//     pipelined INCRBY per (window, IP). Reads sum the Redis
//     keys for the windows inside the rate-limit window plus
//     this node's unflushed counts, so a lone node with Redis
//     enabled sees the same totals it would see locally.
//   - Every Redis failure fails OPEN: Counts reports ok=false
//     and the caller falls back to the local in-memory maps,
//     and cache reads/writes are silently skipped. Redis is
//     never on the critical path of serving a request.
//   - Cache keys are SHA-256 hashes of the local cache key:
//     the local keys contain the visitor IP, fingerprint and
//     user-agent, and none of that is stored in Redis. Values
//     are the same encrypted blobs the local cache holds.
//   - The Redis password comes from the config file only. It
//     is never logged, never returned by any API action, and
//     never appears in error messages. Connection failures
//     log one generic line, throttled to once a minute.
//
// Live multi-server verification needs the operator's own
// Redis and two nodes; the store itself is verified against
// miniredis (a Redis-protocol-compatible in-memory server)
// in the unit tests and in the Batch 3 smoke harness, where
// the real proxy binary talks the real Redis protocol. See
// docs/multi-server.md.
package shared

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultTimeout bounds every Redis command. A slow or dead
// Redis must never stall request handling.
const DefaultTimeout = 100 * time.Millisecond

// DefaultFlushInterval is how often buffered counts are
// pushed to Redis. The local evaluator already refreshes
// only every five seconds, so a one-second flush lag is
// immaterial.
const DefaultFlushInterval = time.Second

// warnInterval throttles the generic "shared store
// unavailable" line: at most one per minute.
const warnInterval = time.Minute

// Kind distinguishes the two counters the proxy keeps per
// IP: all requests, and requests that failed (or skipped)
// the verification challenge.
type Kind string

const (
	// KindRequests counts every request from an IP.
	KindRequests Kind = "req"
	// KindChallenges counts challenge failures from an IP.
	KindChallenges Kind = "ck"
)

// Options configures a Store. Addr is required; Password
// may be empty (no AUTH); DB selects the Redis database.
// TLS enables TLS with the system root pool (for managed
// Redis offerings); certificate verification is always on.
// KeyPrefix namespaces every key (default "sonushield").
// WindowSeconds sizes the TTL of counter keys and should
// match the proxy rate-limit window. SharedCache enables
// the shared challenge-result cache. Now is a clock hook
// for tests; nil means time.Now.
type Options struct {
	Addr           string
	Password       string
	DB             int
	TLS            bool
	KeyPrefix      string
	WindowSeconds  int
	SharedCache    bool
	Timeout        time.Duration
	FlushInterval  time.Duration
	Now            func() time.Time
}

// Store is one Redis-backed shared-state backend.
type Store struct {
	client       *redis.Client
	prefix       string
	windowTTL    time.Duration
	sharedCache  bool
	timeout      time.Duration
	flushEvery   time.Duration
	now          func() time.Time
	mu           sync.Mutex
	pending      map[string]int64
	stop         chan struct{}
	done         chan struct{}
	lastWarnUnix atomic.Int64
}

// New connects to Redis, verifies the connection with a
// PING, and starts the flush loop. An error leaves nothing
// running: the caller keeps the proxy on local state.
func New(opts Options) (*Store, error) {
	if opts.Addr == "" {
		return nil, fmt.Errorf("shared store: no address configured")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout < 10*time.Millisecond {
		timeout = 10 * time.Millisecond
	}
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	flushEvery := opts.FlushInterval
	if flushEvery <= 0 {
		flushEvery = DefaultFlushInterval
	}
	prefix := opts.KeyPrefix
	if prefix == "" {
		prefix = "sonushield"
	}
	windowSeconds := opts.WindowSeconds
	if windowSeconds <= 0 {
		windowSeconds = 120
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	client := redis.NewClient(&redis.Options{
		Addr:         opts.Addr,
		Password:     opts.Password,
		DB:           opts.DB,
		TLSConfig:    tlsConfig(opts),
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		MaxRetries:   0,
	})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	err := client.Ping(ctx).Err()
	cancel()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("shared store: cannot reach Redis: %w", err)
	}
	s := &Store{
		client:      client,
		prefix:      prefix,
		windowTTL:   time.Duration(windowSeconds+60) * time.Second,
		sharedCache: opts.SharedCache,
		timeout:     timeout,
		flushEvery:  flushEvery,
		now:         now,
		pending:     map[string]int64{},
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go s.flushLoop()
	return s, nil
}

// tlsConfig returns a TLS client config with the system
// root pool and full verification when TLS is requested,
// or nil for a plaintext connection. There is no insecure
// mode: a managed Redis endpoint with a bad certificate
// must fail closed at connect time, and the proxy then
// runs on local state.
func tlsConfig(opts Options) *tls.Config {
	if !opts.TLS {
		return nil
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

// counterKey is the Redis key for one (kind, window, IP)
// counter. Counter keys carry the IP in the clear inside the
// operator's own Redis, the same way the local maps do.
func (s *Store) counterKey(kind Kind, window int64, ip string) string {
	return s.prefix + ":rl:" + string(kind) + ":" + itoa(window) + ":" + ip
}

// cacheKey hashes the local cache key: local keys embed the
// visitor IP, fingerprint and user-agent, and none of that
// belongs in Redis keyspace.
func (s *Store) cacheKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return s.prefix + ":cache:" + hex.EncodeToString(sum[:])
}

func itoa(v int64) string {
	return fmt.Sprintf("%d", v)
}

// trim10 aligns a unix timestamp down to a 10-second window
// boundary, matching utils.TrimTime.
func trim10(unix int64) int64 {
	return (unix / 10) * 10
}

// windows lists the 10-second window starts inside the
// rate-limit window ending at nowUnix, inclusive.
func windows(nowUnix, windowSeconds int64) []int64 {
	end := trim10(nowUnix)
	start := trim10(nowUnix - windowSeconds)
	if start < 0 {
		start = 0
	}
	out := make([]int64, 0, windowSeconds/10+1)
	for w := start; w <= end; w += 10 {
		out = append(out, w)
	}
	return out
}

// Record buffers one hit for ip in the current window. It
// never blocks on the network.
func (s *Store) Record(kind Kind, ip string) {
	if s == nil || ip == "" {
		return
	}
	key := s.counterKey(kind, trim10(s.now().Unix()), ip)
	s.mu.Lock()
	s.pending[key]++
	s.mu.Unlock()
}

// Counts returns the shared totals for ip over the windows
// inside the rate-limit window ending at nowUnix: the Redis
// sums plus this node's unflushed counts. ok=false on any
// Redis error: the caller must fall back to local state.
func (s *Store) Counts(ip string, nowUnix, windowSeconds int) (requests, challenges int, ok bool) {
	if s == nil || ip == "" {
		return 0, 0, false
	}
	ws := windows(int64(nowUnix), int64(windowSeconds))
	keys := make([]string, 0, 2*len(ws))
	for _, w := range ws {
		keys = append(keys, s.counterKey(KindRequests, w, ip))
		keys = append(keys, s.counterKey(KindChallenges, w, ip))
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	vals, err := s.client.MGet(ctx, keys...).Result()
	cancel()
	if err != nil {
		s.warn()
		return 0, 0, false
	}
	for i, v := range vals {
		if v == nil {
			continue
		}
		str, isStr := v.(string)
		if !isStr {
			continue
		}
		var count int64
		_, scanErr := fmt.Sscan(str, &count)
		if scanErr != nil {
			continue
		}
		if i%2 == 0 {
			requests += int(count)
		} else {
			challenges += int(count)
		}
	}
	// Add this node's unflushed counts so a lone node (or a
	// node between flushes) never undercounts its own traffic.
	s.mu.Lock()
	for i, key := range keys {
		if n, pending := s.pending[key]; pending {
			if i%2 == 0 {
				requests += int(n)
			} else {
				challenges += int(n)
			}
		}
	}
	s.mu.Unlock()
	return requests, challenges, true
}

// CacheGet reads a shared challenge-cache entry. The second
// result is false on a miss, when the shared cache is
// disabled, and on any Redis error.
func (s *Store) CacheGet(key string) (string, bool) {
	if s == nil || !s.sharedCache || key == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	val, err := s.client.Get(ctx, s.cacheKey(key)).Result()
	cancel()
	if err != nil {
		if err != redis.Nil {
			s.warn()
		}
		return "", false
	}
	return val, true
}

// CacheSet stores a shared challenge-cache entry with the
// given TTL. Redis errors are swallowed: the local cache
// always holds the same entry.
func (s *Store) CacheSet(key, value string, ttl time.Duration) {
	if s == nil || !s.sharedCache || key == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	err := s.client.Set(ctx, s.cacheKey(key), value, ttl).Err()
	cancel()
	if err != nil {
		s.warn()
	}
}

// Flush pushes all buffered counts to Redis with one
// pipeline (INCRBY + EXPIRE per key) and clears the buffer.
// Errors are swallowed: the buffer is still cleared, so a
// dead Redis cannot grow memory without bound. Counts lost
// to an outage are covered by the local fallback.
func (s *Store) Flush() {
	if s == nil {
		return
	}
	s.mu.Lock()
	batch := s.pending
	s.pending = map[string]int64{}
	s.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	pipe := s.client.Pipeline()
	for key, n := range batch {
		pipe.IncrBy(ctx, key, n)
		pipe.Expire(ctx, key, s.windowTTL)
	}
	_, err := pipe.Exec(ctx)
	cancel()
	if err != nil {
		s.warn()
	}
}

// flushLoop flushes buffered counts on a ticker until Close.
func (s *Store) flushLoop() {
	defer close(s.done)
	ticker := time.NewTicker(s.flushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.Flush()
		}
	}
}

// Close stops the flush loop, makes a best-effort final
// flush, and closes the Redis connection.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	close(s.stop)
	<-s.done
	s.Flush()
	return s.client.Close()
}

// warn logs one generic line about Redis being unavailable,
// throttled to once a minute. No address, password, or error
// detail is ever logged.
func (s *Store) warn() {
	now := time.Now().Unix()
	last := s.lastWarnUnix.Load()
	if now-last < int64(warnInterval/time.Second) {
		return
	}
	if s.lastWarnUnix.CompareAndSwap(last, now) {
		fmt.Println("[ ! ] [ Shared store unavailable, using local state ]")
	}
}

// --- Process-wide handle ---
//
// The proxy runs a single shared store configured from
// proxy.redis at startup. All package-level functions are
// safe to call when no store is configured.

var (
	globalMu    sync.RWMutex
	globalStore *Store
)

// Configure replaces the process-wide store with one built
// from opts. On error the previous store (if any) keeps
// running and the error is returned; the caller logs a
// generic line and continues on local state.
func Configure(opts Options) error {
	store, err := New(opts)
	if err != nil {
		return err
	}
	globalMu.Lock()
	old := globalStore
	globalStore = store
	globalMu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// Shutdown closes the process-wide store, if any.
func Shutdown() {
	globalMu.Lock()
	store := globalStore
	globalStore = nil
	globalMu.Unlock()
	if store != nil {
		store.Close()
	}
}

// Enabled reports whether a shared store is configured.
func Enabled() bool {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStore != nil
}

// active returns the current store, or nil.
func active() *Store {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStore
}

// RecordRequest buffers one request hit for ip.
func RecordRequest(ip string) {
	if s := active(); s != nil {
		s.Record(KindRequests, ip)
	}
}

// RecordChallenge buffers one challenge-failure hit for ip.
func RecordChallenge(ip string) {
	if s := active(); s != nil {
		s.Record(KindChallenges, ip)
	}
}

// Counts returns the shared totals for ip, or ok=false when
// no store is configured or Redis is unreachable.
func Counts(ip string, nowUnix, windowSeconds int) (requests, challenges int, ok bool) {
	if s := active(); s != nil {
		return s.Counts(ip, nowUnix, windowSeconds)
	}
	return 0, 0, false
}

// CacheGet reads a shared challenge-cache entry.
func CacheGet(key string) (string, bool) {
	if s := active(); s != nil {
		return s.CacheGet(key)
	}
	return "", false
}

// CacheSet stores a shared challenge-cache entry.
func CacheSet(key, value string, ttl time.Duration) {
	if s := active(); s != nil {
		s.CacheSet(key, value, ttl)
	}
}
