package server

// Public status page (Batch 5).
//
// An opt-in, unauthenticated endpoint for status monitoring and
// upstream scrubbing integration: GET /_bProxy/status, enabled
// only when proxy.statusPage is set. It is handled early in
// middleware, before any challenge or rate limiting, like the
// metrics endpoint. When disabled, the path falls through to the
// normal flow exactly as before.
//
// The response carries deliberately minimal data: a status
// string, uptime in seconds, and per-domain names with a healthy
// flag. No IPs, secrets, config, request counts, rates, or
// stages are exposed — nothing an attacker can use. "Healthy"
// means the domain's backend pool currently has at least one
// eligible backend (with health checks on, that means a backend
// passing probes; with them off, a backend not in failure
// cooldown). A domain with no eligible backend reports
// healthy=false; the proxy itself still answers.
//
// The companion health endpoint, GET /_bProxy/health (same
// opt-in flag), answers {"status":"ok"} with no other data. It
// exists for scrubbing providers and load balancers that poll a
// bare liveness check; it deliberately says nothing about
// domains, backends, or traffic. See docs/scrubbing-integration.md
// for the architecture this supports — and for what SonuShield
// does NOT do (no kernel XDP/eBPF filtering, no Anycast).

import (
	"encoding/json"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/proxy"
	"time"
)

// statusDomain is one domain's status-page entry: name and
// healthy flag only.
type statusDomain struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
}

// statusResponse is the whole status-page payload.
type statusResponse struct {
	Status        string         `json:"status"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	Domains       []statusDomain `json:"domains"`
}

// IsStatusRequest reports whether r is a status-page request
// that must be answered here: the exact path, and only when the
// operator enabled the status page.
func IsStatusRequest(r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.Path != "/_bProxy/status" {
		return false
	}
	return domains.Config != nil && domains.Config.Proxy.StatusPage
}

// IsHealthRequest reports whether r is a health-check request
// that must be answered here: the exact path, and only when the
// operator enabled the status page (the health endpoint shares
// that opt-in flag).
func IsHealthRequest(r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.Path != "/_bProxy/health" {
		return false
	}
	return domains.Config != nil && domains.Config.Proxy.StatusPage
}

// ServeHealth writes the bare liveness response: {"status":"ok"}
// and nothing else.
func ServeHealth(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Write([]byte(`{"status":"ok"}`))
}

// ServeStatus writes the status-page JSON response.
func ServeStatus(writer http.ResponseWriter) {
	uptime := int64(0)
	if !proxy.StartTime.IsZero() {
		uptime = int64(time.Since(proxy.StartTime).Seconds())
		if uptime < 0 {
			uptime = 0
		}
	}
	list := []statusDomain{}
	for _, name := range domains.Domains {
		uncasted, ok := domains.DomainsMap.Load(name)
		if !ok {
			continue
		}
		settings, _ := uncasted.(domains.DomainSettings)
		healthy := settings.Pool != nil && !settings.Pool.AllDown()
		list = append(list, statusDomain{Name: name, Healthy: healthy})
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	data, err := json.Marshal(statusResponse{
		Status:        "ok",
		UptimeSeconds: uptime,
		Domains:       list,
	})
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.Write(data)
}
