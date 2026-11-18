package server

// Credential-stuffing observation (Batch 8).
//
// Runs in the ModifyResponse hook: a POST to a watched path
// whose origin response carries a failure status is recorded
// as one failed login for the detector. The client IP is read
// from the x-real-ip header the middleware stamps on the
// outgoing request, so Cloudflare mode (where the IP comes
// from Cf-Connecting-Ip) is handled the same way. Failures are
// recorded under the longest matching configured prefix, never
// under the raw path, so query strings cannot multiply keys.
// With no watched paths this is a no-op.

import (
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"strings"
)

func observeStuffingResponse(resp *http.Response, settings domains.DomainSettings) {
	if resp == nil || resp.Request == nil {
		return
	}
	cfg := settings.CredentialStuffing
	if len(cfg.Paths) == 0 || resp.Request.Method != http.MethodPost {
		return
	}
	if !cfg.StuffingFailureStatus(resp.StatusCode) {
		return
	}
	path := resp.Request.URL.Path
	matched := ""
	for _, prefix := range cfg.Paths {
		if prefix != "" && strings.HasPrefix(path, prefix) && len(prefix) > len(matched) {
			matched = prefix
		}
	}
	if matched == "" {
		return
	}
	ip := resp.Request.Header.Get("x-real-ip")
	if ip == "" {
		return
	}
	firewall.RecordStuffingFailure(resp.Request.Host, matched, ip)
}
