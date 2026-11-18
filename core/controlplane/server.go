package controlplane

// Cloudflare-style control plane: the management UI and API
// served from a separate official-style host.
//
// The control plane is a separate server mode (`sonushield
// control`). It serves the dashboard and account management
// on its own listener, and manages proxy nodes by calling
// their existing authenticated control API v2. It never
// proxies visitor traffic: every path it serves is
// management-only, and unknown paths answer 404.
//
// Authentication is session-based (username/password
// accounts in a config-managed file, or optional OIDC SSO),
// with HMAC-signed cookies and a mandatory CSRF header on
// API calls. Authorization reuses the Batch 5 tenant model:
// owners see everything, resellers manage only their
// tenants, tenants read only their own tenant — enforced
// server-side in the node API proxy, never in the UI.
//
// The on-domain dashboard route stays available as a fallback
// (proxy.dashboardMode "local", the default) until the
// operator moves to the control plane; see
// docs/control-plane.md for the migration path.

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"sonushield/core/dashboard"
	"sonushield/core/domains"
)

// Server is one control-plane instance.
type Server struct {
	cfg        *domains.ControlPlaneConfig
	configPath string
	accounts   *Store
	sessions   *sessionManager
	nodes      map[string]*nodeClient
	nodeOrder  []string
	audit      *AuditWriter
	limiter    *loginLimiter
	tlsEnabled bool

	// OIDC provider cache + in-flight login states (SSO).
	ssoProviderMu sync.Mutex
	ssoProvider   *cpOIDCProvider
	ssoStateMu    sync.Mutex
	ssoStates     map[string]*cpSSOState
}

// LoadControlPlaneConfig reads a config file and returns its
// controlPlane section, validated. The file may be a full
// proxy config.json; only the controlPlane section is used.
// Shape errors are reported without secret values.
func LoadControlPlaneConfig(path string) (*domains.ControlPlaneConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	if cfg.ControlPlane == nil {
		return nil, fmt.Errorf("%s has no \"controlPlane\" section", path)
	}
	if reason := cfg.ControlPlane.Validate(); reason != "" {
		return nil, fmt.Errorf("controlPlane: %s", reason)
	}
	return cfg.ControlPlane, nil
}

// NewServer builds a control-plane server from a config file
// path. It fails closed on any configuration problem: bad
// node TLS settings, an unreadable accounts file, or an
// unopenable audit log all refuse to start.
func NewServer(configPath string) (*Server, error) {
	cfg, err := LoadControlPlaneConfig(configPath)
	if err != nil {
		return nil, err
	}
	accounts, err := LoadStore(cfg.AccountsFilePath())
	if err != nil {
		return nil, err
	}
	audit, err := NewAuditWriter(cfg.AuditLogPath())
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	tlsEnabled := cfg.Certificate != ""
	sessions := newSessionManager(cfg.SessionSecret, cfg.SessionTTL(), tlsEnabled)
	server := &Server{
		cfg:        cfg,
		configPath: configPath,
		accounts:   accounts,
		sessions:   sessions,
		nodes:      map[string]*nodeClient{},
		audit:      audit,
		limiter:    newLoginLimiter(),
		tlsEnabled: tlsEnabled,
		ssoStates:  map[string]*cpSSOState{},
	}
	for _, nodeCfg := range cfg.Nodes {
		client, err := newNodeClient(nodeCfg)
		if err != nil {
			audit.Close()
			return nil, err
		}
		server.nodes[nodeCfg.Name] = client
		server.nodeOrder = append(server.nodeOrder, nodeCfg.Name)
		if nodeCfg.InsecureSkipVerify {
			fmt.Println("[ ! ] [ control plane: node " + nodeCfg.Name + " has insecureSkipVerify set; its certificate is not verified ]")
		}
	}
	server.warnStartup()
	return server, nil
}

// warnStartup prints the operational warnings: cleartext HTTP
// on a non-loopback address, an ephemeral session key, and a
// missing owner account.
func (s *Server) warnStartup() {
	if !s.tlsEnabled {
		host, _, _ := net.SplitHostPort(s.cfg.ListenAddr())
		if host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
			fmt.Println("[ ! ] [ control plane: no TLS certificate configured and listening on a non-loopback address; logins cross the network in cleartext ]")
		}
	}
	if s.sessions.ephemeral {
		fmt.Println("[ ! ] [ control plane: no sessionSecret configured; sessions will not survive a restart ]")
	}
	if !s.accounts.HasOwner() {
		fmt.Println("[ ! ] [ control plane: no owner account exists; run `sonushield control-setup` to create one ]")
	}
}

// ssoEnabled reports whether OIDC login is configured and
// valid on this control plane.
func (s *Server) ssoEnabled() bool {
	_, ok := s.ssoConfig()
	return ok
}

// authenticate validates the request's session cookie and
// resolves the live account. Sessions carry only a username;
// existence, disabled state, and the current role always
// come from the store.
func (s *Server) authenticate(r *http.Request) (sessionPayload, *Account, bool) {
	var session sessionPayload
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return session, nil, false
	}
	payload, ok := s.sessions.validate(cookie.Value)
	if !ok {
		return session, nil, false
	}
	account := s.accounts.Get(payload.Username)
	if account == nil || account.Disabled {
		return session, nil, false
	}
	return payload, account, true
}

// securityHeaders applies the control-plane response headers:
// no sniffing, no caching of dynamic responses, no framing,
// no referrer leakage.
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	}
}

// handler routes control-plane requests. Unknown paths answer
// a bare 404: the control plane serves management routes
// only, and nothing about the host leaks through them.
func (s *Server) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/":
				if _, _, ok := s.authenticate(r); ok {
					http.Redirect(w, r, "/dashboard", http.StatusFound)
				} else {
					http.Redirect(w, r, "/login", http.StatusFound)
				}
			case r.URL.Path == "/dashboard":
				s.handleDashboard(w, r)
			case r.URL.Path == "/cp/log-tail":
				s.handleLogTail(w, r)
			case r.URL.Path == "/manifest.webmanifest" || r.URL.Path == "/sw.js" || strings.HasPrefix(r.URL.Path, "/icons/"):
				s.handleShellAsset(w, r)
			case r.URL.Path == "/login":
				s.handleLogin(w, r)
			case r.URL.Path == "/logout":
				s.handleLogout(w, r)
			case r.URL.Path == "/setup":
				s.handleSetup(w, r)
			case r.URL.Path == "/cp/whoami":
				s.handleWhoami(w, r)
			case r.URL.Path == "/cp/nodes":
				s.handleNodes(w, r)
			case r.URL.Path == "/cp/accounts":
				s.handleAccounts(w, r)
			case r.URL.Path == "/cp/accounts/password":
				s.handleAccountPassword(w, r)
			case strings.HasPrefix(r.URL.Path, "/cp/api/"):
				s.handleNodeAPI(w, r)
			case strings.HasPrefix(r.URL.Path, "/sso/"):
				s.handleSSO(w, r)
			default:
				http.NotFound(w, r)
			}
		})
		route(w, r)
	})
}

// handleDashboard serves the shared dashboard page behind the
// session, in control-plane mode: the bootstrap script tells
// the page to use the session cookie, node-prefixed API calls,
// and the node switcher and accounts views. The page itself
// never receives a secret.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, _, ok := s.authenticate(r); !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	dashboard.ServeControlPlane(w, s.cfg.Branding, `{"cp":true}`)
}

// handleShellAsset serves a PWA shell asset (manifest, service
// worker, icons) behind the session, at the control host root.
// The assets contain no secrets or live data.
func (s *Server) handleShellAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, _, ok := s.authenticate(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !dashboard.ServeAssetSuffix(w, strings.TrimPrefix(r.URL.Path, "/")) {
		http.NotFound(w, r)
	}
}

// Run serves the control plane until the process ends. TLS
// uses the operator's certificate/key files; without them the
// server runs plain HTTP (safe only on loopback or behind a
// TLS-terminating reverse proxy — warned at startup).
func (s *Server) Run() error {
	defer s.audit.Close()
	httpServer := &http.Server{
		Addr:              s.cfg.ListenAddr(),
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	fmt.Println("SonuShield control plane listening on " + s.cfg.ListenAddr() + " (" + s.scheme() + ")")
	if s.tlsEnabled {
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		return httpServer.ListenAndServeTLS(s.cfg.Certificate, s.cfg.Key)
	}
	return httpServer.ListenAndServe()
}

// scheme names the serving scheme for the startup line.
func (s *Server) scheme() string {
	if s.tlsEnabled {
		return "https"
	}
	return "http"
}

// Run loads the config and serves the control plane. It is
// the `sonushield control` entry point.
func Run(configPath string) error {
	server, err := NewServer(configPath)
	if err != nil {
		return err
	}
	return server.Run()
}

// GenerateSetupTokenForCLI is the `sonushield control-setup`
// entry point: it prints nothing itself and returns the
// one-time token for the CLI to print exactly once.
func GenerateSetupTokenForCLI(configPath string) (string, error) {
	cfg, err := LoadControlPlaneConfig(configPath)
	if err != nil {
		return "", err
	}
	return GenerateSetupToken(cfg.AccountsFilePath())
}
