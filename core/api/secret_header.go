package api

import "net/http"

// SecretHeader is the canonical request header carrying an API secret
// (the proxy apisecret or a role secret) to the API, metrics, log-tail
// and dashboard endpoints.
//
// It deliberately does NOT use the historical "Proxy-Secret" spelling:
// the Fetch Standard forbids page script from setting any header whose
// name starts with "proxy-" or "sec-" (the forbidden-header rule), so
// browsers silently drop a "Proxy-Secret" header set by fetch() and
// the dashboard could never authenticate — while curl and scripts,
// which are not bound by that rule, worked fine. The legacy spelling
// is still accepted (see SecretFromRequest) so existing scripts and
// control-plane nodes keep working.
const SecretHeader = "X-SonuShield-Secret"

// legacySecretHeader is the historical spelling, accepted as a
// fallback for non-browser clients. Browsers can never send it:
// any "Proxy-*" header set by page script is silently dropped.
const legacySecretHeader = "Proxy-Secret"

// SecretFromRequest returns the API secret presented with a request:
// the canonical header when present, otherwise the legacy header.
// It returns "" when neither is present. Callers must check the
// result via proxy.ScopeForSecret (constant-time); never log it.
func SecretFromRequest(request *http.Request) string {
	if value := request.Header.Get(SecretHeader); value != "" {
		return value
	}
	return request.Header.Get(legacySecretHeader)
}
