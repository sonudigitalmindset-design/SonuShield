package domains

// Automatic TLS certificates via Let's Encrypt (ACME HTTP-01), using
// golang.org/x/crypto/acme/autocert.
//
// Disabled by default. Enabled only with proxy.autoSSL = true in
// config.json. When enabled, a domain whose certificate and key fields
// are both empty gets its certificate from Let's Encrypt on first use;
// domains with explicit certificate/key files keep using those files,
// so mixed setups work. Certificates are cached on disk
// (proxy.autoSSLCacheDir, default "autocert-cache") and renewed
// automatically by the autocert manager.
//
// Operator requirements (see docs/configuration.md): each cert-less
// domain must resolve in public DNS to this server, TCP port 80 must
// be reachable from the internet for the HTTP-01 challenge, and
// Let's Encrypt rate limits apply. Auto SSL does nothing in Cloudflare
// mode, where there is no TLS listener.
//
// Certificates and keys obtained this way live only in the cache
// directory, which is git-ignored; they are never committed.

import (
	"crypto/tls"
	"net/http"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/acme/autocert"
)

var autoCertManager atomic.Pointer[autocert.Manager]

// ConfigureAutoCert (re)creates the Let's Encrypt manager from the
// current config. Called from Load() and ReloadConfig(). The manager
// is swapped atomically; certificates live in the on-disk cache, so
// replacing the manager loses nothing. When auto SSL is disabled, or
// the proxy runs in Cloudflare mode, the manager is cleared.
func ConfigureAutoCert() {
	if Config == nil || !Config.Proxy.AutoSSL || Config.Proxy.Cloudflare {
		autoCertManager.Store(nil)
		return
	}
	cacheDir := Config.Proxy.AutoSSLCacheDir
	if cacheDir == "" {
		cacheDir = "autocert-cache"
	}
	hostnames := make([]string, 0, len(Config.Domains))
	for _, domain := range Config.Domains {
		hostnames = append(hostnames, domain.Name)
	}
	autoCertManager.Store(&autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hostnames...),
		Cache:      autocert.DirCache(cacheDir),
		Email:      Config.Proxy.AutoSSLEmail,
	})
}

// AutoCertActive reports whether automatic certificates are enabled.
func AutoCertActive() bool {
	return autoCertManager.Load() != nil
}

// AutoCertCertificate returns a certificate from the Let's Encrypt
// manager, or (nil, nil) when auto SSL is disabled.
func AutoCertCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	manager := autoCertManager.Load()
	if manager == nil {
		return nil, nil
	}
	return manager.GetCertificate(clientHello)
}

// HandleACMEChallenge answers Let's Encrypt HTTP-01 challenge
// requests. It reports whether the request was handled; when auto SSL
// is disabled it always reports false so the normal handler runs.
func HandleACMEChallenge(writer http.ResponseWriter, request *http.Request) bool {
	manager := autoCertManager.Load()
	if manager == nil || !strings.HasPrefix(request.URL.Path, "/.well-known/acme-challenge/") {
		return false
	}
	manager.HTTPHandler(nil).ServeHTTP(writer, request)
	return true
}
