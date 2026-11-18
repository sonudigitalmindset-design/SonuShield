package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/pnc"
)

// HTTP/3 serving (Batch 3).
//
// When proxy.http3 is enabled, SonuShield serves HTTP/3 over
// QUIC on UDP (same port number as the TCP TLS listener,
// 443 by default) in addition to HTTP/1.1 and HTTP/2 over
// TCP. The same Middleware handles every request, so
// stages, challenges, rules, and rate limits apply to
// HTTP/3 traffic exactly as they do to TCP traffic, and
// every HTTP/3 request carries a QUIC fingerprint in the
// ip.quic rule field (see firewall/quic.go for what the
// fingerprint contains and what quic-go does not expose).
//
// The TLS configuration mirrors the TCP listener: the same
// per-SNI certificate selection (domains.GetCertificate),
// the same ClientHello fingerprint hook
// (firewall.Fingerprint — quic-go honors GetConfigForClient,
// so legacy fingerprints and JA4 populate for QUIC
// handshakes too), and the same curve preferences. 0-RTT
// early data is never accepted: replayable requests must
// not skip the challenge flow.
//
// Failure behavior: the HTTP/3 listener is an add-on, not
// the proxy. If the UDP socket cannot bind, one generic
// line is logged and the proxy keeps serving TCP; startup
// never fails because of HTTP/3. In Cloudflare mode there
// is no TLS listener, so HTTP/3 is ignored (Cloudflare
// terminates HTTP/3 at the edge).
//
// Discovery: HTTPS responses carry an Alt-Svc header
// advertising h3 when HTTP/3 is enabled, so browsers learn
// the endpoint without any configuration. The header is
// added by Middleware; see altSvcValue.

// startHTTP3Server starts the HTTP/3 listener in a
// goroutine when proxy.http3 is enabled. It returns
// immediately in all cases.
func startHTTP3Server() {
	if domains.Config == nil || !domains.Config.Proxy.HTTP3.Enabled {
		return
	}
	srv := newHTTP3Server(http.HandlerFunc(Middleware))
	addr := domains.Config.Proxy.HTTP3.Addr
	if addr == "" {
		addr = ":443"
	}
	srv.Addr = addr
	go func() {
		defer pnc.PanicHndl()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println("[ ! ] [ HTTP/3 listener failed, continuing without HTTP/3 ]")
		}
	}()
}

// newHTTP3Server builds the production HTTP/3 server: the
// same TLS configuration as the TCP listener (per-SNI
// certificates, the ClientHello fingerprint hook, curve
// preferences), 0-RTT disabled, and ConnContext attaching
// the QUIC connection for ip.quic fingerprinting. Factored
// out of startHTTP3Server so the in-process end-to-end
// test (http3_e2e_test.go) serves the exact production
// server over a fake packet connection.
func newHTTP3Server(handler http.Handler) *http3.Server {
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		GetConfigForClient: firewall.Fingerprint,
		GetCertificate:     domains.GetCertificate,
		Renegotiation:      tls.RenegotiateOnceAsClient,
		CurvePreferences:   tlsCurvePreferences(),
	})
	return &http3.Server{
		TLSConfig: tlsConf,
		Handler:   handler,
		QUICConfig: &quic.Config{
			// 0-RTT is never accepted: early data is
			// replayable, and replayed requests must not
			// bypass the challenge flow. This is quic-go's
			// default; it is stated explicitly so a future
			// default change cannot silently enable it.
			Allow0RTT: false,
		},
		MaxHeaderBytes: 1 << 20,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			return firewall.ContextWithQUICConn(ctx, conn)
		},
	}
}

// http3Enabled reports whether HTTP/3 serving is
// configured on. It does not prove the UDP listener bound
// successfully; see startHTTP3Server.
func http3Enabled() bool {
	return domains.Config != nil && domains.Config.Proxy.HTTP3.Enabled
}

// altSvcValue is the Alt-Svc header value advertising the
// HTTP/3 endpoint on HTTPS responses: h3 on the configured
// UDP port (443 by default), cached by clients for a day.
func altSvcValue() string {
	port := 443
	if domains.Config != nil {
		if _, portStr, err := net.SplitHostPort(domains.Config.Proxy.HTTP3.Addr); err == nil {
			if n, err := strconv.Atoi(portStr); err == nil && n > 0 && n <= 65535 {
				port = n
			}
		}
	}
	return fmt.Sprintf("h3=\":%d\"; ma=86400", port)
}
