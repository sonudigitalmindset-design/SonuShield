package server

// Response security headers and CORS application (Batch 5).
//
// Security headers are applied to every proxied response with
// set/overwrite semantics, before the edge-cache store, so cached
// copies carry them too. CORS headers depend on the request's
// Origin and are applied after the cache store, so cached copies
// never contain another request's origin; the edge-cache serve
// path in middleware applies them again at serve time.
//
// Preflight requests are answered directly in middleware
// (HandlePreflight), without challenge, when the domain
// configures CORS. Nothing here runs when a domain configures
// neither feature.

import (
	"net/http"
	"sonushield/core/domains"
	"strconv"
	"strings"
)

// ApplySecurityHeaders sets every configured header on the
// response, overwriting any backend value. Entries that fail
// validation are skipped (they are warned about at load time).
func ApplySecurityHeaders(h http.Header, configured map[string]string) {
	for name, value := range configured {
		if !domains.ValidSecurityHeader(name, value) {
			continue
		}
		h.Set(name, value)
	}
}

// ApplyCORSHeaders adds the CORS response headers for a simple
// (non-preflight) cross-origin request. No headers are added when
// the request has no Origin, the origin is not allowed, or CORS
// is not configured. Vary: Origin is added whenever CORS is
// configured and the request carries an Origin, so caches never
// mix origins.
func ApplyCORSHeaders(h http.Header, cfg *domains.CORSConfig, req *http.Request) {
	if cfg == nil || req == nil {
		return
	}
	origin := req.Header.Get("Origin")
	if origin == "" {
		return
	}
	h.Add("Vary", "Origin")
	allowValue, ok := cfg.AllowOrigin(origin)
	if !ok {
		return
	}
	h.Set("Access-Control-Allow-Origin", allowValue)
	if cfg.AllowCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if len(cfg.ExposedHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposedHeaders, ", "))
	}
}

// splitHeaderList splits a comma-separated header value into
// trimmed tokens, dropping empties.
func splitHeaderList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// HandlePreflight answers a CORS preflight request. It reports
// true when the request was a preflight and has been answered
// (the caller must return). A preflight from a disallowed origin,
// for a disallowed method, or with disallowed headers is
// answered 403 with no CORS headers: fail closed.
func HandlePreflight(writer http.ResponseWriter, req *http.Request, cfg *domains.CORSConfig) bool {
	if cfg == nil || req.Method != http.MethodOptions {
		return false
	}
	origin := req.Header.Get("Origin")
	reqMethod := req.Header.Get("Access-Control-Request-Method")
	if origin == "" || reqMethod == "" {
		return false
	}
	writer.Header().Add("Vary", "Origin")
	requestedHeaders := splitHeaderList(req.Header.Get("Access-Control-Request-Headers"))
	allowValue, ok := cfg.AllowOrigin(origin)
	if !ok || !cfg.AllowsMethod(reqMethod) || !cfg.AllowsHeaders(requestedHeaders) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusForbidden)
		writer.Write([]byte("Forbidden."))
		return true
	}
	writer.Header().Set("Access-Control-Allow-Origin", allowValue)
	if cfg.AllowCredentials {
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	writer.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
	if allowed := cfg.PreflightAllowHeaders(requestedHeaders); allowed != "" {
		writer.Header().Set("Access-Control-Allow-Headers", allowed)
	}
	if cfg.MaxAge > 0 {
		writer.Header().Set("Access-Control-Max-Age", strconv.Itoa(cfg.MaxAge))
	}
	writer.WriteHeader(http.StatusNoContent)
	return true
}

// ModifyResponseHook is the ReverseProxy ModifyResponse hook for
// every domain: security headers first (so cached copies carry
// them), then the edge-cache store, then per-request CORS headers
// (which must never be cached).
func ModifyResponseHook(resp *http.Response) error {
	if resp == nil || resp.Request == nil {
		return nil
	}
	uncasted, ok := domains.DomainsMap.Load(resp.Request.Host)
	if !ok {
		return CacheModifyResponse(resp)
	}
	settings, _ := uncasted.(domains.DomainSettings)
	ApplySecurityHeaders(resp.Header, settings.SecurityHeaders)
	CacheModifyResponse(resp)
	ApplyCORSHeaders(resp.Header, settings.CORS, resp.Request)
	return nil
}
