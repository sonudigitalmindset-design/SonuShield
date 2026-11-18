package server

// On-domain dashboard gating (platform model).
//
// proxy.dashboardMode decides what the proxy itself answers
// on the dashboard path (/_bProxy/<adminsecret>/dashboard)
// and the PWA shell-asset paths:
//
//   - "local" (default, and the empty value): today's
//     behavior — the dashboard and its shell assets are
//     served on the protected domain, gated by the
//     admin-secret path.
//   - "control-plane": dashboard requests redirect (302) to
//     proxy.controlPlaneUrl, the control-plane dashboard
//     URL. Without a usable absolute http(s) URL, the
//     answer is a bare generic 404. No login form and no
//     branding leak: the redirect target is the operator's
//     own control host, and the 404 reveals nothing.
//   - "off": the paths answer a bare generic 404, as if no
//     dashboard ever lived here.
//
// Unknown values fail safe to "off", with a single warning
// for the process. The gate applies at both dashboard serve
// sites (the early authenticated-control exemption and the
// late reserved-paths switch) and both shell-asset sites, so
// no request path can bypass it. API v1/v2, metrics, SSO,
// and the log tail are unaffected: only the dashboard page
// and its shell move to the control plane.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"sonushield/core/dashboard"
	"sonushield/core/domains"
	"sonushield/core/proxy"
	"sonushield/core/utils"
)

var dashboardModeWarnOnce sync.Once

// effectiveDashboardMode returns the normalized dashboard
// mode, warning once per process when the configured value
// is unknown (and therefore disabled).
func effectiveDashboardMode() string {
	mode, ok := domains.NormalizeDashboardMode(proxy.DashboardMode)
	if !ok {
		dashboardModeWarnOnce.Do(func() {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Unknown proxy.dashboardMode value, on-domain dashboard disabled ]")
		})
	}
	return mode
}

// serveDashboardPage answers a dashboard-page request per the
// configured mode. Callers always return after calling it.
func serveDashboardPage(writer http.ResponseWriter, request *http.Request) {
	switch effectiveDashboardMode() {
	case domains.DashboardModeLocal:
		dashboard.Serve(writer, proxyBranding())
	case domains.DashboardModeControlPlane:
		if !redirectToControlPlane(writer, request) {
			dashboardNotFound(writer)
		}
	default: // "off"
		dashboardNotFound(writer)
	}
}

// serveDashboardAsset answers a PWA shell-asset request per
// the configured mode, reporting whether it handled the
// request. Non-asset paths are never handled here, so the
// caller falls through exactly as before.
func serveDashboardAsset(writer http.ResponseWriter, request *http.Request) bool {
	if !dashboard.IsShellAsset(request.URL.Path, proxy.AdminSecret) {
		return false
	}
	switch effectiveDashboardMode() {
	case domains.DashboardModeLocal:
		return dashboard.ServeAsset(writer, request.URL.Path, proxy.AdminSecret)
	case domains.DashboardModeControlPlane:
		if !redirectToControlPlane(writer, request) {
			dashboardNotFound(writer)
		}
		return true
	default: // "off"
		dashboardNotFound(writer)
		return true
	}
}

// redirectToControlPlane redirects to the operator's
// control-plane URL when it is a usable absolute http(s)
// URL, and reports whether it redirected. Anything else
// (empty, relative, non-http, unparseable) falls back to the
// bare 404: a bad URL must never produce an open redirect.
func redirectToControlPlane(writer http.ResponseWriter, request *http.Request) bool {
	target := strings.TrimSpace(proxy.ControlPlaneURL)
	if target == "" {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return false
	}
	http.Redirect(writer, request, target, http.StatusFound)
	return true
}

// dashboardNotFound writes the bare generic 404 used when
// the on-domain dashboard is disabled. No branding, no hint
// that a dashboard exists here.
func dashboardNotFound(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusNotFound)
	writer.Write([]byte("404 Not Found"))
}
