package controlplane

// Node clients.
//
// Each configured node is one SonuShield proxy, reached
// through its existing authenticated control API v2. The
// control plane holds one HTTP client per node with the
// node's TLS settings (SNI override, private CA bundle, or
// test-only verification skip) and sends the node's API
// secret only as the Proxy-Secret header to that node. Node
// secrets are never logged, never returned, and never sent
// anywhere else.
//
// The control plane keeps a short-lived cache of each node's
// domain-to-tenant map (from GET_DOMAINS, which reports the
// tenant per domain) so reseller/tenant scoping can be
// enforced server-side before a call is forwarded. The proxy
// remains the source of truth: the cache only gates calls,
// never answers them.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
)

const (
	nodeTimeout      = 30 * time.Second
	nodeMaxBodyBytes = 16 << 20
	nodeMaxRespBytes = 32 << 20
	domainMapTTL     = 30 * time.Second
	domainMapStale   = 5 * time.Minute
)

// nodeClient calls one proxy node's control API.
type nodeClient struct {
	name      string
	baseURL   string
	apiSecret string
	// adminSecret is used only for the log-tail path, which
	// carries the admin secret as a path segment.
	adminSecret string
	// cpSecret signs caller-identity headers for two-person
	// approval. Empty disables the mechanism for this node.
	cpSecret string
	http     *http.Client

	mapMu      sync.Mutex
	domainMap  map[string]string
	mapFetched time.Time
}

// newNodeClient builds a client for one configured node. TLS
// misconfiguration is a startup error with a clear message;
// it never silently downgrades to an insecure client (except
// the explicit, warned insecureSkipVerify option).
func newNodeClient(node domains.ControlPlaneNode) (*nodeClient, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if node.ServerName != "" {
		tlsConfig.ServerName = node.ServerName
	}
	if node.CAFile != "" {
		pem, err := os.ReadFile(node.CAFile)
		if err != nil {
			return nil, fmt.Errorf("node %s caFile cannot be read: %w", node.Name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("node %s caFile contains no certificates", node.Name)
		}
		tlsConfig.RootCAs = pool
	}
	if node.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConnsPerHost:   8,
		ResponseHeaderTimeout: nodeTimeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   nodeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &nodeClient{
		name:        node.Name,
		baseURL:     strings.TrimRight(strings.TrimSpace(node.URL), "/"),
		apiSecret:   node.APISecret,
		adminSecret: node.AdminSecret,
		cpSecret:    node.ControlPlaneSecret,
		http:        client,
	}, nil
}

// nodeResponse is a completed node call: status, content type,
// and a size-capped body.
type nodeResponse struct {
	status      int
	contentType string
	body        []byte
}

// call performs one authenticated node API call. path must be
// a /_bProxy/ path; the caller supplies the query string
// separately so it is never confused with the path. username
// is the control-plane caller, sent (hashed, HMAC-signed) as
// the caller identity when the node has a control-plane
// secret configured.
func (n *nodeClient) call(method, path, rawQuery string, body []byte, username string) (*nodeResponse, error) {
	if !strings.HasPrefix(path, "/_bProxy/") {
		return nil, fmt.Errorf("refusing to call non-control path %q", path)
	}
	target := n.baseURL + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Proxy-Secret", n.apiSecret)
	req.Header.Set("X-SonuShield-CSRF", "1")
	if n.cpSecret != "" && username != "" {
		caller := callerIdentity(username)
		mac := hmac.New(sha256.New, []byte(n.cpSecret))
		mac.Write([]byte(caller))
		req.Header.Set("X-SonuShield-CP-Caller", caller)
		req.Header.Set("X-SonuShield-CP-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, nodeMaxRespBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > nodeMaxRespBytes {
		return nil, fmt.Errorf("node %s response exceeds the size cap", n.name)
	}
	return &nodeResponse{
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		body:        data,
	}, nil
}

// domainTenantMap returns the node's domain -> tenant map,
// refreshing it when the cache is older than domainMapTTL. On
// a refresh failure the last good map is used while it is
// younger than domainMapStale; older than that, the error
// stands and scoped callers fail closed.
func (n *nodeClient) domainTenantMap(username string) (map[string]string, error) {
	n.mapMu.Lock()
	defer n.mapMu.Unlock()
	now := time.Now()
	if n.domainMap != nil && now.Sub(n.mapFetched) < domainMapTTL {
		return n.domainMap, nil
	}
	resp, err := n.call(http.MethodGet, "/_bProxy/api/v2/GET_DOMAINS", "", nil, username)
	if err != nil {
		if n.domainMap != nil && now.Sub(n.mapFetched) < domainMapStale {
			return n.domainMap, nil
		}
		return nil, err
	}
	if resp.status != http.StatusOK {
		if n.domainMap != nil && now.Sub(n.mapFetched) < domainMapStale {
			return n.domainMap, nil
		}
		return nil, fmt.Errorf("node %s GET_DOMAINS returned status %d", n.name, resp.status)
	}
	var envelope struct {
		Success bool `json:"success"`
		Results struct {
			Domains []struct {
				Name   string `json:"NAME"`
				Tenant string `json:"TENANT"`
			} `json:"DOMAINS"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resp.body, &envelope); err != nil || !envelope.Success {
		if n.domainMap != nil && now.Sub(n.mapFetched) < domainMapStale {
			return n.domainMap, nil
		}
		return nil, fmt.Errorf("node %s GET_DOMAINS response could not be parsed", n.name)
	}
	mapped := make(map[string]string, len(envelope.Results.Domains))
	for _, domain := range envelope.Results.Domains {
		if domain.Name != "" {
			mapped[domain.Name] = domains.NormalizeTenant(domain.Tenant)
		}
	}
	n.domainMap = mapped
	n.mapFetched = now
	return mapped, nil
}

// nodeURLForLogTail returns the node's log-tail URL path, or
// "" when the node has no admin secret configured (log tail
// is then unavailable through the control plane).
func (n *nodeClient) nodeURLForLogTail() string {
	if n.adminSecret == "" {
		return ""
	}
	return "/_bProxy/" + n.adminSecret + "/log-tail"
}

// stream opens a streaming GET to the node (log tail) and
// returns the response body for the caller to pump. The
// caller closes it. No size cap applies: the stream is
// forwarded line by line with filtering.
func (n *nodeClient) stream(path, rawQuery, username string) (io.ReadCloser, int, error) {
	if !strings.HasPrefix(path, "/_bProxy/") {
		return nil, 0, fmt.Errorf("refusing to stream non-control path %q", path)
	}
	target := n.baseURL + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Proxy-Secret", n.apiSecret)
	req.Header.Set("X-SonuShield-CSRF", "1")
	if n.cpSecret != "" && username != "" {
		caller := callerIdentity(username)
		mac := hmac.New(sha256.New, []byte(n.cpSecret))
		mac.Write([]byte(caller))
		req.Header.Set("X-SonuShield-CP-Caller", caller)
		req.Header.Set("X-SonuShield-CP-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	// No client timeout on streams: the node sends heartbeats
	// and the handler ends the stream when the browser goes
	// away. Use a dedicated client without Timeout so the
	// 30s cap cannot cut a long-lived tail.
	streamClient := &http.Client{
		Transport: n.http.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := streamClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, resp.StatusCode, nil
	}
	return resp.Body, resp.StatusCode, nil
}

// validNodeURL reports whether raw is an http(s) URL with a
// host, for validation error messages that never echo secrets.
func validNodeURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}
