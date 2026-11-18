package server

import "strings"

// safeRedirectTarget normalises a redirect target to a
// same-origin relative path (M-1 fix). The Stage-1 challenge
// redirects back to the requested URL, and the challenge,
// memory-PoW, and passkey flows store the requested URL and
// redirect to it after verification. A request for
// "//evil.com/x" made the proxy emit "Location:
// //evil.com/x", which browsers treat as an off-site
// navigation — the trusted domain became a phishing
// redirector. This helper collapses any run of leading
// slashes to exactly one, and maps anything that is not a
// plain path (absolute URLs, empty targets) to "/".
// Callers sanitise at store time, so every later consumer
// of the stored value — server redirects and the JSON
// redirect in the passkey flow — is covered.
func safeRedirectTarget(target string) string {
	if target == "" || !strings.HasPrefix(target, "/") {
		return "/"
	}
	return "/" + strings.TrimLeft(target, "/")
}
