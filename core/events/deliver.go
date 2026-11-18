package events

// Signed webhook delivery (Batch 6).
//
// Delivery is asynchronous and best-effort: publishers enqueue
// and return immediately, so a slow or down endpoint can never
// stall request handling, the monitor loop, or an API call. A
// single worker delivers in enqueue order (SIEM consumers
// prefer ordered events) with exponential backoff on transport
// errors and 5xx responses. 4xx responses are permanent
// failures and are not retried.
//
// Authentication: every delivery carries
// X-SonuShield-Timestamp (Unix seconds, set at enqueue time)
// and X-SonuShield-Signature ("v1=" + hex HMAC-SHA256 of
// "<timestamp>.<body>" keyed by the endpoint secret). Receivers
// verify by recomputing over the raw body. Endpoints without a
// secret never deliver: unsigned delivery is not attempted.
//
// Endpoints are resolved from the live config on every
// publish, so reloads take effect without a restart. Delivery
// counters survive re-resolution (keyed by endpoint URL hash).
// The queue is bounded; when full, new events are dropped and
// counted rather than blocking the publisher.
//
// Endpoint URLs are trusted operator configuration, like the
// Discord webhook URL: only http(s) schemes are accepted, and
// requests never follow redirects.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
)

// MaxEndpoints bounds the configured endpoint list; extras
// are ignored and counted in the status.
const MaxEndpoints = 16

const (
	defaultTimeoutSeconds = 10
	defaultMaxRetries     = 3
	maxTimeoutSeconds     = 60
	maxRetries            = 10
)

// queueCap bounds the pending-delivery queue. A var so tests
// can force drops.
var queueCap = 256

// backoffBase and backoffCap shape the retry delay:
// base * 2^attempt, capped. Vars so tests can shorten them.
var (
	backoffBase = time.Second
	backoffCap  = 60 * time.Second
)

// endpoint is one resolved, deliverable endpoint.
type endpoint struct {
	index    int
	url      string
	secret   string
	format   string
	events   map[string]bool // nil means all types
	timeout  time.Duration
	retries  int
	identity string // sha256(url) prefix, for counters/status
	host     string // scheme://host only, safe for status output
}

// invalidEndpoint is a configured endpoint that cannot
// deliver, with the reason, for status reporting.
type invalidEndpoint struct {
	index  int
	host   string
	reason string
}

// resolveEndpoints validates one config snapshot. It returns
// the deliverable endpoints, the invalid ones, and how many
// entries past the cap were ignored.
func resolveEndpoints(configs []domains.EventWebhookConfig) (valid []*endpoint, invalid []invalidEndpoint, ignored int) {
	if len(configs) > MaxEndpoints {
		ignored = len(configs) - MaxEndpoints
		configs = configs[:MaxEndpoints]
	}
	for i, cfg := range configs {
		parsed, err := url.Parse(strings.TrimSpace(cfg.URL))
		host := ""
		if err == nil && parsed.Host != "" {
			host = parsed.Scheme + "://" + parsed.Host
		}
		fail := func(reason string) {
			invalid = append(invalid, invalidEndpoint{index: i, host: host, reason: reason})
		}
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			fail("url must be an http(s) URL with a host")
			continue
		}
		if cfg.Secret == "" {
			fail("a signing secret is required")
			continue
		}
		format := strings.ToLower(strings.TrimSpace(cfg.Format))
		if format == "" {
			format = "json"
		}
		if format != "json" && format != "syslog" && format != "cef" {
			fail("unknown format (want json, syslog, or cef)")
			continue
		}
		var events map[string]bool
		badFilter := ""
		if len(cfg.Events) > 0 {
			events = map[string]bool{}
			for _, name := range cfg.Events {
				if !ValidType(name) {
					badFilter = name
					break
				}
				events[name] = true
			}
		}
		if badFilter != "" {
			fail("unknown event type in filter: " + badFilter)
			continue
		}
		timeout := cfg.TimeoutSeconds
		if timeout <= 0 {
			timeout = defaultTimeoutSeconds
		}
		if timeout > maxTimeoutSeconds {
			timeout = maxTimeoutSeconds
		}
		// MaxRetries <= 0 means the default; there is no
		// zero-retry setting (retries are the point of the
		// dispatcher — a single attempt is what a down
		// endpoint would silently lose).
		retries := cfg.MaxRetries
		if retries <= 0 {
			retries = defaultMaxRetries
		}
		if retries > maxRetries {
			retries = maxRetries
		}
		sum := sha256.Sum256([]byte(cfg.URL))
		valid = append(valid, &endpoint{
			index:    i,
			url:      strings.TrimSpace(cfg.URL),
			secret:   cfg.Secret,
			format:   format,
			events:   events,
			timeout:  time.Duration(timeout) * time.Second,
			retries:  retries,
			identity: hex.EncodeToString(sum[:8]),
			host:     host,
		})
	}
	return valid, invalid, ignored
}

// sign computes the v1 HMAC signature header value.
func sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

type delivery struct {
	endpoint    *endpoint
	body        []byte
	contentType string
	timestamp   int64
	signature   string
}

type endpointCounters struct {
	delivered int64
	failed    int64
}

// Dispatcher owns one delivery queue and worker. The default
// dispatcher reads the live config; tests build their own with
// a fixed config provider.
type Dispatcher struct {
	config    func() []domains.EventWebhookConfig
	queue     chan delivery
	stop      chan struct{}
	startOnce sync.Once

	mu       sync.Mutex
	counters map[string]*endpointCounters
	dropped  int64

	client *http.Client
}

// NewDispatcher builds a dispatcher reading its endpoint list
// from config on every publish.
func NewDispatcher(config func() []domains.EventWebhookConfig) *Dispatcher {
	return &Dispatcher{
		config:   config,
		queue:    make(chan delivery, queueCap),
		stop:     make(chan struct{}),
		counters: map[string]*endpointCounters{},
		client: &http.Client{
			// Never follow redirects with signed requests.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func liveEventWebhookConfig() []domains.EventWebhookConfig {
	if domains.Config == nil {
		return nil
	}
	return domains.Config.Proxy.EventWebhooks
}

var defaultDispatcher = NewDispatcher(liveEventWebhookConfig)

// Start starts the default delivery worker exactly once. It is
// called from Serve, after config.Load has run. With no
// endpoints configured the worker idles and Publish is a
// no-op, so unconfigured proxies pay nothing.
func Start() {
	defaultDispatcher.Start()
}

// Start starts this dispatcher's worker exactly once.
func (d *Dispatcher) Start() {
	d.startOnce.Do(func() { go d.worker() })
}

// Stop terminates the worker. Terminal for this dispatcher;
// tests build a fresh dispatcher per case.
func (d *Dispatcher) Stop() {
	select {
	case <-d.stop:
	default:
		close(d.stop)
	}
}

func (d *Dispatcher) countersFor(identity string) *endpointCounters {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.counters[identity]
	if !ok {
		c = &endpointCounters{}
		d.counters[identity] = c
	}
	return c
}

// Publish enqueues ev for every matching endpoint. It never
// blocks and never panics: a full queue drops (counted) and
// any unexpected failure is swallowed, because event fan-out
// must never break the code path that published.
func (d *Dispatcher) Publish(ev Event) (queued int) {
	defer func() { _ = recover() }()
	return d.publish(ev, false)
}

// PublishTest enqueues a test event to every valid endpoint,
// ignoring type filters. It returns how many deliveries were
// queued.
func (d *Dispatcher) PublishTest() int {
	return d.publish(NewEvent(TypeTest, "", "", map[string]interface{}{
		"message": "SonuShield webhook test event",
	}), true)
}

func (d *Dispatcher) publish(ev Event, ignoreFilters bool) (queued int) {
	valid, _, _ := resolveEndpoints(d.config())
	timestamp := time.Now().Unix()
	for _, ep := range valid {
		if !ignoreFilters && ep.events != nil && !ep.events[ev.Type] {
			continue
		}
		body, contentType := Encode(ev, ep.format)
		item := delivery{
			endpoint:    ep,
			body:        body,
			contentType: contentType,
			timestamp:   timestamp,
			signature:   sign(ep.secret, timestamp, body),
		}
		select {
		case d.queue <- item:
			queued++
		default:
			d.mu.Lock()
			d.dropped++
			d.mu.Unlock()
		}
	}
	return queued
}

func (d *Dispatcher) worker() {
	for {
		select {
		case item := <-d.queue:
			d.deliver(item)
		case <-d.stop:
			return
		}
	}
}

type attemptOutcome int

const (
	outcomeDelivered attemptOutcome = iota
	outcomeRetryable
	outcomePermanent
)

func (d *Dispatcher) deliver(item delivery) {
	ep := item.endpoint
	counters := d.countersFor(ep.identity)
	delay := backoffBase
	for attempt := 0; ; attempt++ {
		switch d.attempt(item) {
		case outcomeDelivered:
			d.mu.Lock()
			counters.delivered++
			d.mu.Unlock()
			return
		case outcomePermanent:
			d.mu.Lock()
			counters.failed++
			d.mu.Unlock()
			return
		}
		if attempt >= ep.retries {
			d.mu.Lock()
			counters.failed++
			d.mu.Unlock()
			return
		}
		select {
		case <-time.After(delay):
		case <-d.stop:
			d.mu.Lock()
			counters.failed++
			d.mu.Unlock()
			return
		}
		delay *= 2
		if delay > backoffCap {
			delay = backoffCap
		}
	}
}

// attempt performs one POST: delivered on 2xx, retryable on
// transport errors and 5xx, permanent on 3xx/4xx (redirects
// are never followed, so a 3xx means the endpoint itself
// answered with one).
func (d *Dispatcher) attempt(item delivery) attemptOutcome {
	ep := item.endpoint
	ctx, cancel := context.WithTimeout(context.Background(), ep.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.url, bytes.NewReader(item.body))
	if err != nil {
		return outcomeRetryable
	}
	req.Header.Set("Content-Type", item.contentType)
	req.Header.Set("X-SonuShield-Timestamp", strconv.FormatInt(item.timestamp, 10))
	req.Header.Set("X-SonuShield-Signature", item.signature)
	resp, err := d.client.Do(req)
	if err != nil {
		return outcomeRetryable
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return outcomeDelivered
	case resp.StatusCode >= 500:
		return outcomeRetryable
	default:
		return outcomePermanent
	}
}

// EndpointStatus is one endpoint's operator-facing state. It
// never includes the URL path/query (tokens hide there) or the
// secret.
type EndpointStatus struct {
	Index         int
	Host          string
	Format        string
	Events        []string
	Valid         bool
	InvalidReason string
	Delivered     int64
	Failed        int64
}

// Status is the operator-facing dispatcher state.
type Status struct {
	Endpoints  []EndpointStatus
	Ignored    int
	QueueDepth int
	Dropped    int64
}

// Status snapshots the dispatcher: current endpoints with
// validity and counters, the queue depth, and drop count.
func (d *Dispatcher) Status() Status {
	valid, invalid, ignored := resolveEndpoints(d.config())
	d.mu.Lock()
	defer d.mu.Unlock()
	st := Status{Ignored: ignored, QueueDepth: len(d.queue), Dropped: d.dropped}
	for _, ep := range valid {
		var events []string
		if ep.events != nil {
			for name := range ep.events {
				events = append(events, name)
			}
		}
		s := EndpointStatus{
			Index: ep.index, Host: ep.host, Format: ep.format,
			Events: events, Valid: true,
		}
		if c := d.counters[ep.identity]; c != nil {
			s.Delivered = c.delivered
			s.Failed = c.failed
		}
		st.Endpoints = append(st.Endpoints, s)
	}
	for _, inv := range invalid {
		st.Endpoints = append(st.Endpoints, EndpointStatus{
			Index: inv.index, Host: inv.host, Valid: false, InvalidReason: inv.reason,
		})
	}
	return st
}

// Package-level API on the default dispatcher.

// Publish enqueues ev for every matching endpoint.
func Publish(ev Event) int {
	return defaultDispatcher.Publish(ev)
}

// PublishAttackStart publishes an attack.start event.
func PublishAttackStart(domain, tenant, kind string, stage int) {
	Publish(NewEvent(TypeAttackStart, domain, tenant, map[string]interface{}{
		"kind": kind, "stage": stage,
	}))
}

// PublishAttackStop publishes an attack.stop event.
func PublishAttackStop(domain, tenant, kind string, stage int) {
	Publish(NewEvent(TypeAttackStop, domain, tenant, map[string]interface{}{
		"kind": kind, "stage": stage,
	}))
}

// PublishAudit publishes an audit event. Params must already
// be scrubbed (see core/api scrubParams); this function never
// sees unscrubbed values.
func PublishAudit(role, action, domain, ip string, params map[string]string, success bool, errCode string) {
	data := map[string]interface{}{
		"role": role, "action": action, "success": success,
	}
	if ip != "" {
		data["ip"] = ip
	}
	if len(params) > 0 {
		data["params"] = params
	}
	if errCode != "" {
		data["error"] = errCode
	}
	Publish(NewEvent(TypeAudit, domain, "", data))
}

// PublishTest enqueues a test event to every valid endpoint,
// ignoring type filters.
func PublishTest() int {
	return defaultDispatcher.PublishTest()
}

// GetStatus snapshots the default dispatcher.
func GetStatus() Status {
	return defaultDispatcher.Status()
}
