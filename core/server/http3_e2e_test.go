package server

// End-to-end HTTP/3 test over an in-memory packet
// connection.
//
// The development VM blocks UDP sendmsg entirely (even on
// loopback), so a real QUIC handshake over sockets cannot
// run here. This test instead serves the exact production
// http3.Server (newHTTP3Server: production TLS config,
// fingerprint hook, ConnContext) over a pair of
// channel-backed net.PacketConns, and drives it with a real
// quic-go client transport. Everything above the socket
// layer is exercised for real: the QUIC + TLS 1.3
// handshake, the ClientHello fingerprint hook, the QUIC
// connection attachment, ip.quic fingerprint computation,
// and gofilter rule evaluation against the live value.
// Only UDP socket delivery itself is untested here and
// remains pending on real infrastructure (see
// docs/http3.md).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kor44/gofilter"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"sonushield/core/domains"
	"sonushield/core/firewall"
)

// pipeAddr is a fake address for the in-memory packet pair.
type pipeAddr struct{ s string }

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return a.s }

type pipeDatagram struct {
	b    []byte
	from net.Addr
}

// pipeTimeoutError is a net.Error reporting a timeout, for
// read-deadline expiry.
type pipeTimeoutError struct{}

func (pipeTimeoutError) Error() string   { return "i/o timeout" }
func (pipeTimeoutError) Timeout() bool   { return true }
func (pipeTimeoutError) Temporary() bool { return true }

// pipePacketConn is a net.PacketConn delivering datagrams
// to its peer over a channel. Reads honor SetReadDeadline;
// a deadline change wakes a blocked ReadFrom.
type pipePacketConn struct {
	local net.Addr
	inbox chan pipeDatagram

	mu           sync.Mutex
	peer         *pipePacketConn
	closed       bool
	readDeadline time.Time
	wakeCh       chan struct{}
}

func newPipePacketConnPair() (*pipePacketConn, *pipePacketConn) {
	a := &pipePacketConn{
		local:  pipeAddr{"pipe-client"},
		inbox:  make(chan pipeDatagram, 1024),
		wakeCh: make(chan struct{}),
	}
	b := &pipePacketConn{
		local:  pipeAddr{"pipe-server"},
		inbox:  make(chan pipeDatagram, 1024),
		wakeCh: make(chan struct{}),
	}
	a.peer, b.peer = b, a
	return a, b
}

func (c *pipePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		deadline := c.readDeadline
		wake := c.wakeCh
		c.mu.Unlock()

		var timer *time.Timer
		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, pipeTimeoutError{}
			}
			timer = time.NewTimer(d)
			timerCh = timer.C
		}
		select {
		case dg := <-c.inbox:
			if timer != nil {
				timer.Stop()
			}
			return copy(b, dg.b), dg.from, nil
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
			// Deadline changed (or Close); re-evaluate.
		case <-timerCh:
			return 0, nil, pipeTimeoutError{}
		}
	}
}

func (c *pipePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	peer := c.peer
	closed := c.closed
	c.mu.Unlock()
	if closed || peer == nil {
		return 0, net.ErrClosed
	}
	peer.mu.Lock()
	peerClosed := peer.closed
	peer.mu.Unlock()
	if peerClosed {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case peer.inbox <- pipeDatagram{b: cp, from: c.local}:
		return len(b), nil
	case <-time.After(5 * time.Second):
		return 0, pipeTimeoutError{}
	}
}

func (c *pipePacketConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.wakeCh)
	}
	c.mu.Unlock()
	return nil
}

func (c *pipePacketConn) LocalAddr() net.Addr { return c.local }

func (c *pipePacketConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer == nil {
		return nil
	}
	return c.peer.local
}

func (c *pipePacketConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *pipePacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	old := c.wakeCh
	c.wakeCh = make(chan struct{})
	c.mu.Unlock()
	close(old)
	return nil
}

func (c *pipePacketConn) SetWriteDeadline(_ time.Time) error {
	// Writes are bounded by a fixed 5s cap in WriteTo.
	return nil
}

// testCertificate returns a self-signed TLS certificate
// for b3.local, generated in memory.
func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "b3.local"},
		DNSNames:     []string{"b3.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func TestHTTP3EndToEndOverPipe(t *testing.T) {
	cert := testCertificate(t)

	// Snapshot the fingerprint maps: the production
	// GetConfigForClient hook (firewall.Fingerprint) must
	// run for the QUIC handshake and record an entry.
	firewall.Mutex.Lock()
	beforeConns := len(firewall.Connections)
	firewall.Mutex.Unlock()

	var (
		mu          sync.Mutex
		quicFP      string
		ruleMatched bool
		proto       string
	)
	ruleFilter, err := gofilter.NewFilter(`ip.quic contains "q1:"`)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	settings := domains.DomainSettings{
		CustomRules: []domains.Rule{
			{Filter: ruleFilter, Action: "4"},
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp := firewall.ComputeQUICFingerprint(r)
		vars := gofilter.Message{"ip.quic": fp}
		level := firewall.EvalFirewallRule(settings, vars, 0)
		mu.Lock()
		quicFP = fp
		ruleMatched = level == 4
		proto = r.Proto
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("h3-e2e-ok"))
	})

	srv := newHTTP3Server(handler)
	// Only certificate selection is overridden for the
	// test: the production GetConfigForClient fingerprint
	// hook, curve preferences, and ConnContext stay as
	// built by newHTTP3Server.
	srv.TLSConfig.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}

	clientPC, serverPC := newPipePacketConnPair()
	defer clientPC.Close()
	defer serverPC.Close()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(serverPC)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	clientTransport := &quic.Transport{Conn: clientPC}
	defer clientTransport.Close()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // test-only self-signed cert
			ServerName:         "b3.local",
			NextProtos:         []string{"h3"},
		},
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			return clientTransport.DialEarly(ctx, serverPC.LocalAddr(), tlsConf, conf)
		},
	}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://b3.local/probe", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP/3 request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Fatalf("proto = %q, want HTTP/3.0", resp.Proto)
	}
	if string(body) != "h3-e2e-ok" {
		t.Fatalf("body = %q, want h3-e2e-ok", body)
	}

	mu.Lock()
	fp, matched, seenProto := quicFP, ruleMatched, proto
	mu.Unlock()
	if !strings.HasPrefix(fp, "q1:") {
		t.Fatalf("ip.quic fingerprint = %q, want q1: prefix", fp)
	}
	if !matched {
		t.Fatalf("ip.quic rule did not match fingerprint %q", fp)
	}
	if seenProto != "HTTP/3.0" {
		t.Fatalf("handler saw proto %q, want HTTP/3.0", seenProto)
	}
	t.Logf("live QUIC fingerprint: %s", fp)

	firewall.Mutex.Lock()
	afterConns := len(firewall.Connections)
	afterJA4 := len(firewall.ConnectionsJA4)
	firewall.Mutex.Unlock()
	if afterConns <= beforeConns {
		t.Fatalf("ClientHello fingerprint hook did not record a connection (before=%d after=%d)", beforeConns, afterConns)
	}
	if afterJA4 == 0 {
		t.Fatalf("no JA4 entry recorded for the QUIC handshake")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Serve did not return after Close")
	}
}
