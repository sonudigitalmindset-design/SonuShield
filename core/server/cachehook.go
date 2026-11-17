package server

// Edge-cache response capture (Batch 4).
//
// CacheModifyResponse runs as the ReverseProxy ModifyResponse hook
// for every domain. It stores cacheable backend responses in the
// domain's edge cache and otherwise leaves the response untouched.
// It never returns an error: any problem degrades to "don't cache"
// with the response body restored, so caching can never break
// proxying.
//
// Upgrade (WebSocket) responses are never touched: their bodies
// are live connections, not buffers.

import (
	"bytes"
	"io"
	"net/http"
	"sonushield/core/domains"
	"strings"
)

// isUpgradeRequest reports whether r asks to switch protocols
// (WebSocket). Such requests bypass the edge cache and take the
// dedicated upgrade path instead of the normal proxy flow.
func isUpgradeRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

func CacheModifyResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil || resp.Body == nil {
		return nil
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return nil
	}
	req := resp.Request
	if req.Method != http.MethodGet || req.Header.Get("Authorization") != "" || isUpgradeRequest(req) {
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

	lifetime, cacheable := domains.ResponseFreshness(resp)
	if !cacheable {
		return nil
	}

	// Read the body fully (up to the entry cap + 1 byte, so an
	// oversized body is detected without buffering it all), then
	// restore it so the client still receives the whole response.
	// The remainder of an oversized body stays in the original
	// stream behind the bytes already read.
	const capBytes = 1<<20 + 1 // 1 MB entry cap + probe byte
	body, err := io.ReadAll(io.LimitReader(resp.Body, capBytes))
	if err != nil {
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		return nil
	}
	if len(body) > 1<<20 {
		// Oversized: do not cache, and restore the unread
		// remainder behind the bytes already read.
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		return nil
	}
	// Fully read: close the original body (fully consumed, so the
	// transport connection can be reused) and serve from the buffer.
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	settings.Cache.Store(domains.CacheKey(req), resp.StatusCode, resp.Header, body, lifetime)
	return nil
}
