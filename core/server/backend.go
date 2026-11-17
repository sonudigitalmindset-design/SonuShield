package server

// Backend-pool helpers for the RoundTripper (Batch 4).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sonushield/core/domains"
)

// errAllBackendsDown is the synthetic error used when the pool has
// no eligible backend. It flows through the normal backend-error
// path (stale fallback, then the error page) instead of panicking
// on a nil response.
var errAllBackendsDown = errors.New("all backends unavailable")

// backendPoolFor returns the backend pool for a domain, or nil when
// the domain has none (the "debug" pseudo-domain).
func backendPoolFor(domain string) *domains.BackendPool {
	uncasted, ok := domains.DomainsMap.Load(domain)
	if !ok {
		return nil
	}
	settings, _ := uncasted.(domains.DomainSettings)
	return settings.Pool
}

// requestReplayable reports whether a failed request may be
// retried on another backend: requests without a body always,
// and requests with a body only when GetBody can supply a fresh
// copy. A POST whose body cannot be replayed is never retried,
// so an operation is never duplicated by failover.
func requestReplayable(req *http.Request) bool {
	if req.Body == nil || req.ContentLength == 0 {
		return true
	}
	return req.GetBody != nil
}

// staleFallbackResponse serves a stale cached copy when every
// backend is down. It returns nil when there is no stale copy,
// the request is not a plain cacheable GET, or any backend is
// still eligible. The response is clearly marked with the
// standard Warning header for stale responses and Cache-Control:
// no-store, so it is never mistaken for a fresh response.
func staleFallbackResponse(req *http.Request, pool *domains.BackendPool) *http.Response {
	if req.Method != http.MethodGet || req.Header.Get("Authorization") != "" || isUpgradeRequest(req) {
		return nil
	}
	if pool == nil || !pool.AllDown() {
		return nil
	}
	uncasted, ok := domains.DomainsMap.Load(req.Host)
	if !ok {
		return nil
	}
	settings, _ := uncasted.(domains.DomainSettings)
	if settings.Cache == nil {
		return nil
	}
	status, header, body, ok := settings.Cache.LookupStale(domains.CacheKey(req))
	if !ok {
		return nil
	}
	cloned := header.Clone()
	cloned.Set("Warning", `110 - "Response is stale"`)
	cloned.Set("Cache-Control", "no-store")
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Header:        cloned,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
