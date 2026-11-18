package server

// Latency/TTFB recording (Batch 7).
//
// Per-domain latency samples are recorded for origin-bound
// traffic only — challenges, blocks, cache hits, and reserved
// paths are not sampled. The measurement points, stated
// exactly:
//
//   - Proxy latency: middleware entry to the start of the
//     first backend attempt. This is the time the proxy spent
//     on rules, challenges bookkeeping, the waiting room, and
//     the fair queue before fetching from the origin. The
//     response-copy tail (after the backend body finishes)
//     is NOT measured separately.
//   - TTFB (origin): start of the first backend attempt to
//     response headers of the successful attempt. With
//     backend retries, failed attempts inflate it — honestly,
//     because the client waited that long.
//   - Total (origin): start of the first backend attempt to
//     the response body being fully read (or, for 5xx error
//     bodies the proxy reads inline, to the end of that read).
//     For responses transformed by Brotli/image optimization,
//     "total" ends when the optimizer finishes its capped
//     read; oversized optimized responses are not sampled at
//     all (their wrapper is never closed — the same caveat as
//     bandwidth metering). Bodies abandoned mid-copy are not
//     sampled.
//
// Samples live in the core/latency store (a neutral package
// so the API can read them without an import cycle) and are
// summarised by GET_LATENCY. The SLA figures compare the
// origin success rate over the retained window against the
// operator's slaTarget (default 99.9): "uptime %" means
// origin success rate over that window, NOT wall-clock
// uptime.

import (
	"context"
	"io"
	"net/http"
	"time"

	"sonushield/core/latency"
)

// latencyStartKey carries the middleware-entry timestamp to
// the RoundTripper through the request context.
type latencyStartKey struct{}

// withLatencyStart returns a copy of req carrying the
// middleware-entry timestamp for latency measurement.
func withLatencyStart(req *http.Request, start time.Time) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), latencyStartKey{}, start))
}

// latencyStartFrom reads the middleware-entry timestamp back.
// It returns the zero time when the request was not stamped
// (direct RoundTripper use), in which case proxy latency is
// reported as zero.
func latencyStartFrom(req *http.Request) time.Time {
	if start, ok := req.Context().Value(latencyStartKey{}).(time.Time); ok {
		return start
	}
	return time.Time{}
}

// RecordLatency stores one origin sample for a domain. It is
// a thin alias over the shared store, kept in this package so
// the RoundTripper's error and 5xx paths read naturally.
func RecordLatency(domain string, ttfb, total, proxy time.Duration, status int, transportErr bool) {
	latency.Record(domain, ttfb, total, proxy, status, transportErr)
}

// latencyReader records one origin sample when the response
// body is closed, wrapping the metering reader so byte
// counting is unaffected. Close is idempotent: a sample is
// recorded at most once.
type latencyReader struct {
	io.ReadCloser
	domain          string
	status          int
	backendStart    time.Time
	headersAt       time.Time
	middlewareStart time.Time
	done            bool
}

func (r *latencyReader) Close() error {
	err := r.ReadCloser.Close()
	if !r.done {
		r.done = true
		now := time.Now()
		proxy := time.Duration(0)
		if !r.middlewareStart.IsZero() {
			proxy = r.backendStart.Sub(r.middlewareStart)
		}
		latency.Record(r.domain, r.headersAt.Sub(r.backendStart), now.Sub(r.backendStart), proxy, r.status, false)
	}
	return err
}
