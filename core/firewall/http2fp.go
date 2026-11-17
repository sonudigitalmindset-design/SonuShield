package firewall

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// SonuShield HTTP/2 connection fingerprint.
//
// This fingerprint uses ONLY the HTTP/2 signals Go's server stack
// actually exposes to a handler. Read this before expecting more:
//
//   - Observable: the HTTP version (ProtoMajor/ProtoMinor), the TLS
//     version and cipher suite, the negotiated ALPN protocol, and
//     the request headers (names only, sorted — header order is not
//     preserved, see httpfp.go).
//   - NOT observable: HTTP/2 SETTINGS frame order and values,
//     WINDOW_UPDATE increments, PRIORITY frames, and stream
//     dependencies. Neither net/http nor golang.org/x/net/http2
//     exposes connection-level frames to handlers, and the frames
//     travel inside TLS so they cannot be sniffed without
//     terminating the handshake first. Any product claiming full
//     HTTP/2 frame fingerprinting on top of Go's standard server
//     stack is either running a custom HTTP/2 implementation or
//     inventing values. SonuShield does neither.
//
// The fingerprint is therefore a weak clustering signal, like the
// sh1 HTTP fingerprint: useful as one input among others, never as
// the sole basis for blocking. It is empty for non-HTTP/2 requests.
//
// Format: h2_<version>_<tls>_<alpn>_<headers>_<flags>
//
//	version = "20" for HTTP/2.0 (other HTTP/2 versions, if Go ever
//	          serves them, render as their major/minor digits).
//	tls     = TLS version (e.g. "13" for TLS 1.3, "00" when there
//	          is no TLS state, as in h2c) + "-" + cipher suite id
//	          in hex (e.g. "1301"), or "0000" without TLS state.
//	alpn    = negotiated ALPN protocol ("h2", or "none").
//	headers = truncated SHA-256 (12 hex chars) of the sorted,
//	          comma-joined, lowercase header names. Header VALUES
//	          are never included.
//	flags   = presence bits for commonly distinguishing headers,
//	          in fixed order: accept, accept-encoding,
//	          accept-language, user-agent, cookie, referer,
//	          upgrade-insecure-requests, sec-fetch-site.
//	          "1" when present, "0" when absent.
//
// The fingerprint is exposed to firewall rules as "http.http2" and
// shown on /_bProxy/fingerprint. Like JA4, values are only
// comparable with other SonuShield-computed values.

var h2FlagHeaders = []string{
	"accept",
	"accept-encoding",
	"accept-language",
	"user-agent",
	"cookie",
	"referer",
	"upgrade-insecure-requests",
	"sec-fetch-site",
}

// ComputeHTTP2Fingerprint returns the HTTP/2 fingerprint for r, or
// "" when r is not an HTTP/2 request.
func ComputeHTTP2Fingerprint(r *http.Request) string {
	if r == nil || r.ProtoMajor != 2 {
		return ""
	}

	version := fmt.Sprintf("%d%d", r.ProtoMajor, r.ProtoMinor)

	tlsPart := "00-0000"
	alpn := "none"
	if r.TLS != nil {
		tlsPart = fmt.Sprintf("%02x-%04x", tlsVersionCode(r.TLS.Version), r.TLS.CipherSuite)
		if r.TLS.NegotiatedProtocol != "" {
			alpn = r.TLS.NegotiatedProtocol
		}
	}

	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	headersHash := "000000000000"
	if len(names) > 0 {
		sum := sha256.Sum256([]byte(strings.Join(names, ",")))
		headersHash = hex.EncodeToString(sum[:])[:12]
	}

	var flags strings.Builder
	for _, name := range h2FlagHeaders {
		if r.Header.Get(name) != "" {
			flags.WriteByte('1')
		} else {
			flags.WriteByte('0')
		}
	}

	return "h2_" + version + "_" + tlsPart + "_" + alpn + "_" + headersHash + "_" + flags.String()
}

// tlsVersionCode maps a crypto/tls version constant to its two-digit
// code used in the fingerprint. Unknown versions render as "00".
func tlsVersionCode(version uint16) uint16 {
	switch version {
	case tls.VersionTLS10:
		return 0x10
	case tls.VersionTLS11:
		return 0x11
	case tls.VersionTLS12:
		return 0x12
	case tls.VersionTLS13:
		return 0x13
	default:
		return 0x00
	}
}
