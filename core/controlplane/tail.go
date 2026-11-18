package controlplane

// Live log tail through the control plane.
//
// GET /cp/log-tail?node=<name> streams the node's SSE log tail
// to the dashboard, which cannot reach the node directly (the
// node may live on another host, and the dashboard must never
// learn the node secrets). The control plane forwards the
// stream with the node's API secret and filters entries for
// scoped callers: a reseller or tenant sees only entries whose
// domain belongs to a tenant in their scope, resolved through
// the node's domain map. Entries without a domain, entries for
// unknown domains, and entries the filter cannot parse are
// dropped for scoped callers (fail closed) and passed through
// for the owner.
//
// The node requires its admin secret in the tail path, so the
// tail is unavailable (501) for a node configured without one.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"sonushield/core/domains"
)

// handleLogTail proxies one node's SSE log tail to an
// authenticated dashboard session.
func (s *Server) handleLogTail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_, account, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !requireCSRF(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	nodeName := r.URL.Query().Get("node")
	node, ok := s.nodes[nodeName]
	if !ok || nodeName == "" {
		http.Error(w, "Unknown node", http.StatusNotFound)
		return
	}
	tailPath := node.nodeURLForLogTail()
	if tailPath == "" {
		http.Error(w, "Log tail is not available for this node: no admin secret is configured for it", http.StatusNotImplemented)
		return
	}

	tenantSet := account.TenantSet()
	var domainMap map[string]string
	if tenantSet != nil {
		// Scoped callers need the domain map to filter the
		// stream. When it cannot be loaded, fail closed
		// rather than streaming unfiltered entries.
		mapped, err := node.domainTenantMap(account.Username)
		if err != nil {
			http.Error(w, "Domain map unavailable", http.StatusBadGateway)
			return
		}
		domainMap = mapped
	}

	body, status, err := node.stream(tailPath, "", account.Username)
	if err != nil {
		http.Error(w, "Node unreachable", http.StatusBadGateway)
		return
	}
	if status != http.StatusOK {
		http.Error(w, "Node refused the log tail", status)
		return
	}
	defer body.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// The node sends ": heartbeat" comments and
	// "data: <entry JSON>" events. Comments pass through;
	// data events are filtered for scoped callers.
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	ctx := r.Context()
	go func() {
		<-ctx.Done()
		body.Close()
	}()
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") && tenantSet != nil {
			if !tailEntryAllowed(line[len("data: "):], domainMap, tenantSet) {
				continue
			}
		}
		fmt.Fprintln(w, line)
		flusher.Flush()
	}
}

// tailEntryAllowed reports whether a tail entry JSON belongs to
// a tenant in the caller's scope. Unparseable entries, entries
// without a domain, and entries for domains the node does not
// report are all denied.
func tailEntryAllowed(payload string, domainMap map[string]string, tenantSet map[string]bool) bool {
	var entry struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal([]byte(payload), &entry); err != nil {
		return false
	}
	if entry.Domain == "" {
		return false
	}
	tenant, ok := domainMap[entry.Domain]
	if !ok {
		return false
	}
	return tenantSet[domains.NormalizeTenant(tenant)]
}
