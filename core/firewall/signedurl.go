package firewall

// Signed URLs and hotlink protection (Batch 7).
//
// Signed URLs: for paths under the operator-configured
// signedURLPaths prefixes, a request must carry a valid
// HMAC-SHA256 signature proving the operator (or the
// operator's application) authorized the URL. The signature
// scheme is:
//
//	sig = hex(HMAC-SHA256(secret, path + "\n" + exp))
//
// carried as query parameters exp (unix seconds, absolute
// expiry) and sig (64 hex characters). The path signed is the
// URL path only, without the query string. Verification is
// strict: the expiry must parse and be in the future, the
// signature must be exactly 64 hex characters, and the
// comparison is constant-time. There is no clock-skew
// allowance — operators should build their own margin into
// the expiry. Invalid or missing signatures get a generic 403
// that reveals nothing about which check failed.
//
// The secret lives only in config.json (signedURLSecret) and
// is never logged or returned by any API. With no secret or
// no paths configured, no request is checked.
//
// Hotlink protection: for paths under the hotlinkPaths
// prefixes, requests whose Referer names a host outside the
// allowlist (and outside the site's own host) are rejected
// with a generic 403. Missing or empty Referer headers are
// ALLOWED: privacy-conscious browsers and clients omit the
// header, and blocking them would break legitimate traffic.
// Only GET and HEAD requests are checked — assets are
// fetched, not posted to. Referer hostnames are compared
// case-insensitively, without ports.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// pathUnderPrefixes reports whether path starts with any of
// the configured prefixes. Empty configuration never matches.
func pathUnderPrefixes(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// SignedURLRequired reports whether the request path needs a
// valid signature: a secret is configured and the path is
// under a protected prefix.
func SignedURLRequired(secret string, paths []string, requestPath string) bool {
	return secret != "" && pathUnderPrefixes(requestPath, paths)
}

// VerifySignedURL checks the exp/sig query parameters of
// request against the operator secret. It returns false for
// any malformed, expired, or mismatched signature.
func VerifySignedURL(secret string, request *http.Request) bool {
	if secret == "" {
		return false
	}
	query := request.URL.Query()
	expRaw := query.Get("exp")
	sig := query.Get("sig")
	if expRaw == "" || len(sig) != 64 {
		return false
	}
	exp, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil || exp <= time.Now().Unix() {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(request.URL.Path))
	mac.Write([]byte("\n"))
	mac.Write([]byte(expRaw))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// SignURL builds a signed URL for path expiring at exp, for
// operators and tests. It appends exp and sig query
// parameters, preserving any existing query parameters.
func SignURL(secret, path string, exp int64, extra url.Values) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(path))
	mac.Write([]byte("\n"))
	expRaw := strconv.FormatInt(exp, 10)
	mac.Write([]byte(expRaw))
	sig := hex.EncodeToString(mac.Sum(nil))
	values := url.Values{}
	for key, vals := range extra {
		for _, v := range vals {
			values.Add(key, v)
		}
	}
	values.Set("exp", expRaw)
	values.Set("sig", sig)
	return path + "?" + values.Encode()
}

// HotlinkBlocked reports whether a GET/HEAD request for a
// protected asset path must be rejected for its Referer:
// the path is under a protected prefix, the Referer names a
// host that is neither the request's own host nor on the
// allowlist. Missing, unparsable, or same-host Referers are
// allowed.
func HotlinkBlocked(request *http.Request, paths, allowlist []string) bool {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return false
	}
	if !pathUnderPrefixes(request.URL.Path, paths) {
		return false
	}
	referer := request.Header.Get("Referer")
	if referer == "" {
		return false
	}
	refererURL, err := url.Parse(referer)
	if err != nil || refererURL.Hostname() == "" {
		return false
	}
	host := strings.ToLower(refererURL.Hostname())
	if host == strings.ToLower(request.URL.Hostname()) {
		return false
	}
	// The request Host header is authoritative for the site's
	// own host when the URL carries none (normal proxying).
	if requestHost := request.Host; requestHost != "" {
		if h, _, err := splitHostPort(requestHost); err == nil && host == strings.ToLower(h) {
			return false
		}
		if host == strings.ToLower(requestHost) {
			return false
		}
	}
	for _, allowed := range allowlist {
		if allowed == "" {
			continue
		}
		allowedHost := strings.ToLower(allowed)
		if h, _, err := splitHostPort(allowed); err == nil {
			allowedHost = strings.ToLower(h)
		}
		if host == allowedHost {
			return false
		}
	}
	return true
}

// splitHostPort splits host:port, tolerating a bare hostname.
func splitHostPort(hostport string) (string, string, error) {
	if strings.Contains(hostport, ":") {
		return net.SplitHostPort(hostport)
	}
	return hostport, "", nil
}
