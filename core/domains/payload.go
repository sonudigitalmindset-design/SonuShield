package domains

// Payload size limits (Batch 5).
//
// Every request body is bounded: the proxy-wide default
// (proxy.maxRequestBody, 32 MiB when unset), overridable per
// domain (maxBodyBytes) and per path prefix (bodyLimits, longest
// prefix wins). A negative limit means "no limit" at the level
// that sets it; a zero value inherits the next level up.
//
// Enforcement is twofold. Requests with a declared Content-Length
// over the limit are rejected with a clean 413 before any
// evaluation work. Chunked bodies (unknown length) are capped
// with http.MaxBytesReader as a backstop: an over-limit chunked
// body fails while being proxied and the client sees the generic
// backend-error page rather than a clean 413. That asymmetry is
// inherent to streaming enforcement without buffering whole
// bodies, and is documented in docs/configuration.md.
//
// Invalid route entries (empty prefix, non-positive size) are
// skipped with a warning at load time; the route then falls back
// to the domain limit. The proxy never decompresses request
// bodies, so there is no request-side decompression-bomb surface
// to guard; response handling is the standard library transport
// behavior, unchanged.

import "strings"

// DefaultMaxRequestBody is the request-body limit applied when
// neither the proxy nor the domain configures one: 32 MiB, large
// enough for normal uploads and small enough to bound abuse.
const DefaultMaxRequestBody = int64(32 << 20)

// BodyLimit is one per-route payload limit: requests whose path
// starts with Prefix are limited to MaxBytes.
type BodyLimit struct {
	Prefix   string `json:"prefix"`
	MaxBytes int64  `json:"maxBytes"`
}

// BodyLimitFor resolves the effective body limit for one request
// path: the longest matching route prefix, else the domain limit,
// else the proxy limit, else the default. It returns -1 only
// when the winning level explicitly sets a negative (unlimited)
// value.
func (s DomainSettings) BodyLimitFor(path string) int64 {
	bestLen := -1
	var best int64
	found := false
	for _, route := range s.BodyLimits {
		if route.Prefix == "" || route.MaxBytes <= 0 {
			continue
		}
		if len(route.Prefix) > bestLen && strings.HasPrefix(path, route.Prefix) {
			bestLen = len(route.Prefix)
			best = route.MaxBytes
			found = true
		}
	}
	if found {
		return best
	}
	if s.MaxBodyBytes != 0 {
		return s.MaxBodyBytes
	}
	if Config != nil && Config.Proxy.MaxRequestBody != 0 {
		return Config.Proxy.MaxRequestBody
	}
	return DefaultMaxRequestBody
}
