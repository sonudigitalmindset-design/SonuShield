package api

// Live log tail endpoint (Batch 8).
//
// GET /_bProxy/<adminsecret>/log-tail streams sanitized log
// entries as server-sent events. Authentication reuses the
// control-plane rules: a X-SonuShield-Secret header with any known
// role secret (viewer or above), or a valid SSO session
// cookie plus the CSRF header. Tenant-scoped callers receive
// only entries for their own tenant's domains. The endpoint
// is wired before the challenge flow in middleware, like
// metrics, and listed in AuthenticatedControlRequest.
//
// The stream sends one "data: <entry JSON>" event per log
// entry plus a ": heartbeat" comment every 15 seconds to keep
// intermediaries from closing idle connections. Entries are
// the same sanitized records the file logger writes: no
// bodies, cookies, query strings, or secrets. When the
// subscriber cap is reached the endpoint answers 503.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/logging"
	"sonushield/core/proxy"
	"time"
)

// IsLogTailRequest reports whether r targets the log-tail
// endpoint for the current admin secret.
func IsLogTailRequest(request *http.Request) bool {
	if proxy.AdminSecret == "" {
		return false
	}
	return request.URL.Path == "/_bProxy/"+proxy.AdminSecret+"/log-tail"
}

// ServeLogTail authenticates and streams the live log tail.
// It reports whether it handled the request.
func ServeLogTail(writer http.ResponseWriter, request *http.Request) bool {
	if !IsLogTailRequest(request) {
		return false
	}
	_, tenantScope, ok := proxy.ScopeForSecret(SecretFromRequest(request))
	if !ok {
		_, ssoOK, csrfMissing := attemptSSOAuth(request)
		if csrfMissing {
			http.Error(writer, "Forbidden", http.StatusForbidden)
			return true
		}
		if !ssoOK {
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			return true
		}
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "Streaming unsupported", http.StatusInternalServerError)
		return true
	}
	entries, unsubscribe, subscribed := logging.Subscribe()
	if !subscribed {
		http.Error(writer, "Too many tail subscribers", http.StatusServiceUnavailable)
		return true
	}
	defer unsubscribe()

	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	ctx := request.Context()
	for {
		select {
		case <-ctx.Done():
			return true
		case <-heartbeat.C:
			fmt.Fprint(writer, ": heartbeat\n\n")
			flusher.Flush()
		case entry, open := <-entries:
			if !open {
				return true
			}
			if tenantScope != "" && !domainInTenant(entry.Domain, tenantScope) {
				continue
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			fmt.Fprintf(writer, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// domainInTenant reports whether a domain belongs to a
// tenant. Unknown domains are hidden from tenant callers.
func domainInTenant(domainName, tenant string) bool {
	if domains.Config == nil {
		return false
	}
	for _, domain := range domains.Config.Domains {
		if domain.Name == domainName {
			return domain.Tenant == tenant
		}
	}
	return false
}
