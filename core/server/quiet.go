package server

// Quiet mode: generic visitor-facing output.
//
// When proxy.quietMode is true, responses served to site visitors
// omit product-identifying strings: the SonuShield response header is
// not set, block messages lose the "Blocked by SonuShield." prefix,
// captcha error pages lose the product name, and the unknown-host
// message on :80 is generic. This affects only what visitors see.
//
// It never affects authorship attribution: the /_bProxy/credits
// endpoint, the LICENSE file, README/docs credits, and code-level
// credits are unchanged, and quiet mode must never be used to hide
// them.
//
// Default (quietMode unset/false) output is byte-identical to before.

import "sonushield/core/domains"

func quietMode() bool {
	return domains.Config != nil && domains.Config.Proxy.QuietMode
}

// blockMessage builds a block response body. In quiet mode the
// "Blocked by SonuShield." prefix is omitted; the detail text is
// unchanged.
func blockMessage(detail string) string {
	if quietMode() {
		return detail
	}
	return "Blocked by SonuShield.\n" + detail
}

// errorMessage builds an error response body. In quiet mode the
// product name is omitted; the detail text is unchanged.
func errorMessage(detail string) string {
	if quietMode() {
		return "Error: " + detail
	}
	return "SonuShield Error: " + detail
}

// unknownHostMessage builds the :80 response for a host with no
// configured domain. In quiet mode it names no product and mentions
// no config file.
func unknownHostMessage(host string) string {
	if quietMode() {
		return host + " does not exist."
	}
	return "SonuShield: " + host + " does not exist. If you are the owner please check your config.json if you believe this is a mistake"
}
