package server

// First-run setup wizard (Batch 6): a web-based guided setup that
// creates the initial config.json, replacing the terminal prompts
// for operators who prefer (or only have) a browser.
//
// The wizard runs ONLY when config.json does not exist. main()
// starts it when --wizard is passed, or automatically when there
// is no config and stdin is not a terminal (systemd, Docker, and
// other non-interactive launches, where the terminal prompts
// cannot work). An interactive launch without a config keeps the
// original terminal Generate() flow unchanged.
//
// Safety properties:
//   - Localhost-only by default (127.0.0.1:8080; overridable with
//     --wizard-listen). A remote operator reaches it over an SSH
//     tunnel. Binding it publicly is the operator's explicit
//     choice and is documented as unsafe without access control.
//   - A per-process token, embedded in the served page and
//     required on every API call, defeats cross-origin POSTs
//     from other sites while the wizard is running.
//   - The wizard never overwrites an existing config: it refuses
//     to start when config.json exists, and a setup submission
//     that finds one (it appeared after startup) fails with
//     HTTP 409 unless the submission carries explicit
//     confirmation, in which case the old file is backed up
//     before it is replaced.
//   - Inputs are validated on the server (the browser checks are
//     convenience only) and the built configuration must pass
//     ValidateConfig before anything is written. The write is
//     atomic (temp file + rename) with 0600 permissions, because
//     the file holds secrets.
//   - Secrets use crypto/rand. The operator-facing secrets
//     (admin, API) are generated in the browser with
//     crypto.getRandomValues and shown once; the three internal
//     secrets (cookie, javascript, captcha) are generated
//     server-side at save time and never leave the config file.
//     utils.RandomString is math/rand-based and is NOT used here.
//   - The health check (backend reachability) is advisory: a
//     backend that is down during setup does not block saving.
//   - After a successful save the wizard shuts down; the
//     operator restarts SonuShield to run the proxy. There is no
//     self-restart: a restart loop on a bad config would be
//     worse than a clear instruction.
//
// The generated configuration mirrors config.Generate()'s
// defaults exactly (timeouts, rate limits, stage thresholds), so
// a wizard-created config behaves like a terminal-created one.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sonushield/core/domains"
)

//go:embed wizard.html
var wizardPageHTML string

const wizardTokenHeader = "X-Wizard-Token"
const wizardMaxBody = 64 << 10

// RunWizard serves the first-run setup wizard on addr until a
// configuration is saved, then returns nil. It refuses to run
// when config.json already exists.
func RunWizard(addr string) error {
	if _, err := os.Stat("config.json"); err == nil {
		return errors.New("config.json already exists; the setup wizard only runs on first run")
	} else if !os.IsNotExist(err) {
		return err
	}
	token, err := wizardRandomToken()
	if err != nil {
		return fmt.Errorf("generating wizard token: %w", err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	fmt.Println("[ Setup wizard listening on http://" + listener.Addr().String() + " ]")
	fmt.Println("[ Open it in a browser on this machine. On a remote server, use an SSH tunnel: ssh -L 8080:127.0.0.1:8080 <server> ]")
	fmt.Println("[ The wizard stops itself once the configuration is saved; restart SonuShield afterwards. ]")
	return serveWizard(listener, "config.json", token)
}

// wizardServer is the wizard's HTTP state.
type wizardServer struct {
	configPath string
	token      string
	done       chan struct{}
}

// serveWizard serves the wizard on an existing listener until a
// configuration is saved. The token authenticates the API calls;
// the page embeds it, so only a browser that loaded the page
// from this server can submit.
func serveWizard(listener net.Listener, configPath, token string) error {
	w := &wizardServer{configPath: configPath, token: token, done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/", w.handlePage)
	mux.HandleFunc("/api/check", w.handleCheck)
	mux.HandleFunc("/api/setup", w.handleSetup)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-w.done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	if err := srv.Serve(listener); err == http.ErrServerClosed {
		return nil
	} else {
		return err
	}
}

func (w *wizardServer) shutdown() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

func (w *wizardServer) handlePage(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" || req.Method != http.MethodGet {
		http.NotFound(rw, req)
		return
	}
	page := strings.ReplaceAll(wizardPageHTML, "__WIZARD_TOKEN__", w.token)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	io.WriteString(rw, page)
}

// wizardInput is one setup submission. Overwrite is only honored
// when config.json appeared after the wizard started.
type wizardInput struct {
	Domain      string `json:"domain"`
	Backend     string `json:"backend"`
	Scheme      string `json:"scheme"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Cloudflare  bool   `json:"cloudflare"`
	AutoSSL     bool   `json:"autoSSL"`
	AdminSecret string `json:"adminSecret"`
	APISecret   string `json:"apiSecret"`
	Overwrite   bool   `json:"overwrite"`
}

// wizardBackendStatus is the advisory health-check result.
type wizardBackendStatus struct {
	Reachable  bool   `json:"reachable"`
	TLSChecked bool   `json:"tlsChecked"`
	TLSOK      bool   `json:"tlsOk"`
	Error      string `json:"error,omitempty"`
}

type wizardCheckResponse struct {
	Problems []string            `json:"problems"`
	Warnings []string            `json:"warnings"`
	Backend  wizardBackendStatus `json:"backend"`
}

func (w *wizardServer) checkToken(rw http.ResponseWriter, req *http.Request) bool {
	got := req.Header.Get(wizardTokenHeader)
	if subtle.ConstantTimeCompare([]byte(got), []byte(w.token)) != 1 {
		http.Error(rw, "missing or invalid wizard token", http.StatusForbidden)
		return false
	}
	return true
}

func (w *wizardServer) decodeInput(rw http.ResponseWriter, req *http.Request) (wizardInput, bool) {
	var input wizardInput
	dec := json.NewDecoder(io.LimitReader(req.Body, wizardMaxBody))
	if err := dec.Decode(&input); err != nil {
		http.Error(rw, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return input, false
	}
	return input, true
}

func wizardWriteJSON(rw http.ResponseWriter, status int, value interface{}) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(rw, "encoding response", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(status)
	rw.Write(data)
}

func (w *wizardServer) handleCheck(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !w.checkToken(rw, req) {
		return
	}
	input, ok := w.decodeInput(rw, req)
	if !ok {
		return
	}
	_, problems, warnings := validateWizardInput(input)
	resp := wizardCheckResponse{Problems: problems, Warnings: warnings}
	if len(problems) == 0 {
		resp.Backend = checkWizardBackend(input.Scheme, input.Backend)
	}
	wizardWriteJSON(rw, http.StatusOK, resp)
}

func (w *wizardServer) handleSetup(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !w.checkToken(rw, req) {
		return
	}
	input, ok := w.decodeInput(rw, req)
	if !ok {
		return
	}
	cfg, problems, warnings := validateWizardInput(input)
	if len(problems) > 0 {
		wizardWriteJSON(rw, http.StatusBadRequest, wizardCheckResponse{Problems: problems, Warnings: warnings})
		return
	}
	// Never overwrite without explicit confirmation.
	if _, err := os.Stat(w.configPath); err == nil && !input.Overwrite {
		wizardWriteJSON(rw, http.StatusConflict, wizardCheckResponse{
			Problems: []string{"config.json already exists. Enable the replace option to overwrite it (the existing file is backed up first)."},
			Warnings: warnings,
		})
		return
	}
	backupPath, err := writeWizardConfig(w.configPath, cfg, input.Overwrite)
	if err != nil {
		wizardWriteJSON(rw, http.StatusInternalServerError, wizardCheckResponse{
			Problems: []string{"saving config.json: " + err.Error()},
			Warnings: warnings,
		})
		return
	}
	fmt.Println("[ Setup wizard: configuration saved to " + w.configPath + " ]")
	if backupPath != "" {
		fmt.Println("[ Setup wizard: previous config backed up to " + backupPath + " ]")
	}
	wizardWriteJSON(rw, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"warnings": warnings,
		"backup":   backupPath,
	})
	w.shutdown()
}

// validateWizardInput validates one submission and, when it is
// valid, builds the configuration (Generate() defaults). Problems
// block saving; warnings do not. The returned configuration is
// nil when problems is non-empty.
func validateWizardInput(input wizardInput) (*domains.Configuration, []string, []string) {
	var problems, warnings []string

	domain := strings.TrimSpace(input.Domain)
	if !validWizardHost(domain) {
		problems = append(problems, "domain must be a valid hostname or IP address, without a scheme or port")
	}
	backendHost, backendPort, backendOK := splitWizardBackend(input.Backend)
	if !backendOK {
		problems = append(problems, "backend must be host:port, for example 127.0.0.1:8080")
	}
	scheme := strings.ToLower(strings.TrimSpace(input.Scheme))
	if scheme != "http" && scheme != "https" {
		problems = append(problems, "scheme must be http or https")
	}
	cert := strings.TrimSpace(input.Certificate)
	key := strings.TrimSpace(input.Key)
	if (cert == "") != (key == "") {
		problems = append(problems, "certificate and key must both be set, or both be empty")
	}
	if problem := wizardSecretProblem("admin secret", input.AdminSecret); problem != "" {
		problems = append(problems, problem)
	}
	if problem := wizardSecretProblem("API secret", input.APISecret); problem != "" {
		problems = append(problems, problem)
	}
	if len(problems) > 0 {
		return nil, problems, warnings
	}

	adminSecret := strings.TrimSpace(input.AdminSecret)
	apiSecret := strings.TrimSpace(input.APISecret)
	var err error
	if adminSecret == "" {
		if adminSecret, err = wizardRandomSecret(); err != nil {
			return nil, []string{"generating admin secret: " + err.Error()}, warnings
		}
	}
	if apiSecret == "" {
		if apiSecret, err = wizardRandomSecret(); err != nil {
			return nil, []string{"generating API secret: " + err.Error()}, warnings
		}
	}
	internal := map[string]string{}
	for _, name := range []string{"cookie", "javascript", "captcha"} {
		secret, err := wizardRandomSecret()
		if err != nil {
			return nil, []string{"generating " + name + " secret: " + err.Error()}, warnings
		}
		internal[name] = secret
	}

	cfg := &domains.Configuration{
		Proxy: domains.Proxy{
			Cloudflare:  input.Cloudflare,
			AdminSecret: adminSecret,
			APISecret:   apiSecret,
			AutoSSL:     input.AutoSSL,
			Timeout: domains.TimeoutSettings{
				Idle:       3,
				Read:       5,
				Write:      5,
				ReadHeader: 5,
			},
			Secrets: internal,
			Ratelimits: map[string]int{
				"requests":           1000,
				"unknownFingerprint": 150,
				"challengeFailures":  40,
				"noRequestsSent":     10,
			},
		},
		Domains: []domains.Domain{
			{
				Name:                domain,
				Backend:             net.JoinHostPort(backendHost, backendPort),
				Scheme:              scheme,
				Certificate:         cert,
				Key:                 key,
				Webhook:             domains.WebhookSettings{},
				FirewallRules:       []domains.JsonRule{},
				BypassStage1:        75,
				Stage2Difficulty:    5,
				BypassStage2:        250,
				DisableBypassStage3: 100,
				DisableRawStage3:    250,
				DisableBypassStage2: 50,
				DisableRawStage2:    75,
			},
		},
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, []string{err.Error()}, warnings
	}
	if cert == "" && !input.Cloudflare && !input.AutoSSL {
		warnings = append(warnings, "no certificate is configured and neither Cloudflare mode nor autoSSL is enabled, so this domain cannot serve HTTPS until certificates are added")
	}
	return cfg, problems, warnings
}

// wizardSecretProblem validates an operator-supplied secret. An
// empty secret is fine: a random one is generated at save time.
func wizardSecretProblem(label, secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) < 16 {
		return label + " must be at least 16 characters (or empty to generate one)"
	}
	if strings.Contains(secret, "CHANGE_ME") {
		return label + " must not contain 'CHANGE_ME'"
	}
	for _, r := range secret {
		if r <= ' ' || r == 0x7f {
			return label + " must not contain whitespace or control characters"
		}
	}
	return ""
}

// validWizardHost reports whether host is a valid DNS hostname
// (LDH labels) or an IP literal. Schemes, ports, paths, and
// empty labels are rejected.
func validWizardHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.HasSuffix(host, "-") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// splitWizardBackend splits a host:port backend, accepting
// bracketed IPv6 literals. It reports the host and port
// separately so the stored backend is normalized.
func splitWizardBackend(backend string) (host, port string, ok bool) {
	backend = strings.TrimSpace(backend)
	host, port, err := net.SplitHostPort(backend)
	if err != nil {
		return "", "", false
	}
	if !validWizardHost(host) {
		return "", "", false
	}
	if len(port) == 0 || len(port) > 5 {
		return "", "", false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return "", "", false
		}
		n = n*10 + int(port[i]-'0')
	}
	if n < 1 || n > 65535 {
		return "", "", false
	}
	return host, port, true
}

// checkWizardBackend dials the backend and, for https, completes
// a TLS handshake. The handshake skips certificate verification:
// this is a reachability check, not a trust decision. Advisory
// only; a failure never blocks saving.
func checkWizardBackend(scheme, backend string) wizardBackendStatus {
	status := wizardBackendStatus{}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", backend)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Reachable = true
	if strings.ToLower(scheme) != "https" {
		conn.Close()
		return status
	}
	status.TLSChecked = true
	host, _, _ := net.SplitHostPort(backend)
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		status.Error = "TLS handshake failed: " + err.Error()
		tlsConn.Close()
		return status
	}
	status.TLSOK = true
	tlsConn.Close()
	return status
}

// writeWizardConfig writes cfg to path atomically (temp file +
// rename, 0600). When a file already exists and overwrite is set,
// it is first renamed to a timestamped backup; the backup path is
// returned. When a file exists and overwrite is false, an error
// is returned and nothing changes.
func writeWizardConfig(path string, cfg *domains.Configuration, overwrite bool) (string, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	backupPath := ""
	if _, err := os.Stat(path); err == nil {
		if !overwrite {
			return "", errors.New("config.json already exists")
		}
		backupPath = path + ".wizard-bak-" + time.Now().Format("20060102-150405")
		if err := os.Rename(path, backupPath); err != nil {
			return "", fmt.Errorf("backing up existing config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wizard-tmp-*")
	if err != nil {
		return backupPath, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return backupPath, err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return backupPath, err
	}
	if err := tmp.Close(); err != nil {
		return backupPath, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return backupPath, err
	}
	return backupPath, nil
}

// wizardRandomSecret returns 32 crypto-random bytes, base64url
// encoded (43 characters, safe in URLs and headers).
func wizardRandomSecret() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// wizardRandomToken returns 32 crypto-random bytes, hex encoded.
func wizardRandomToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
