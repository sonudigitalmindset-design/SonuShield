package server

// WebSocket upgrade proxying with an idle timeout (Batch 4).
//
// Go's httputil.ReverseProxy already forwards WebSocket upgrades,
// and that remains the default path: when websocketIdleTimeout is
// not configured, upgrades flow through the normal reverse proxy
// exactly as before. When the operator configures an idle
// timeout, upgrades take this dedicated path instead, which
// hijacks the client connection, dials the backend (through the
// domain's backend pool, so failover applies), and copies bytes
// in both directions until either side closes or the connection
// is idle for the configured time.
//
// Hijacking is unavailable on HTTP/2 connections, where this
// path declines and the normal reverse-proxy path is used
// instead. WebSocket over HTTP/2 (RFC 8441 extended CONNECT) is
// not supported, matching the previous behavior.

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sonushield/core/domains"
	"time"
)

const (
	websocketDialTimeout = 5 * time.Second
	maxWebsocketIdle     = time.Hour
)

// proxyWebSocket handles one WebSocket upgrade. It returns true
// when the request was fully handled here (including error
// responses), and false when the caller should fall through to
// the normal reverse-proxy path (hijacking unavailable, or no
// backend pool).
func proxyWebSocket(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings) bool {
	if settings.Pool == nil {
		return false
	}
	idle := time.Duration(settings.WebsocketIdleTimeout) * time.Second
	if idle <= 0 {
		return false
	}
	if idle > maxWebsocketIdle {
		idle = maxWebsocketIdle
	}

	backend := settings.Pool.Pick()
	if backend == nil {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(writer, "Bad Gateway")
		return true
	}

	backendConn, err := dialBackend(settings.Pool.Scheme, backend.Addr)
	if err != nil {
		settings.Pool.MarkFailed(backend)
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(writer, "Bad Gateway")
		return true
	}
	settings.Pool.MarkOK(backend)
	settings.Pool.TrackStart(backend)
	defer settings.Pool.TrackEnd(backend)

	// Forward the upgrade request to the backend. RequestURI must
	// be empty for a client-side write; the Host header stays the
	// client's Host, matching the reverse proxy's behavior.
	outReq := request.Clone(request.Context())
	outReq.URL = &url.URL{Scheme: settings.Pool.Scheme, Host: backend.Addr, Path: request.URL.Path, RawQuery: request.URL.RawQuery}
	outReq.Host = request.Host
	outReq.RequestURI = ""
	outReq.Header = request.Header.Clone()
	if err := outReq.Write(backendConn); err != nil {
		backendConn.Close()
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(writer, "Bad Gateway")
		return true
	}

	backendReader := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendReader, outReq)
	if err != nil {
		backendConn.Close()
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(writer, "Bad Gateway")
		return true
	}

	// The backend declined the upgrade: answer with its response
	// through the normal writer, without hijacking.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		defer backendConn.Close()
		for name, values := range resp.Header {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.WriteHeader(resp.StatusCode)
		io.Copy(writer, resp.Body)
		return true
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		// No hijacking (HTTP/2): the upgrade already consumed
		// the backend handshake, so answer the decline here
		// rather than replaying the request.
		resp.Body.Close()
		backendConn.Close()
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(writer, "Bad Gateway")
		return true
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		resp.Body.Close()
		backendConn.Close()
		return true
	}

	// Write the 101 response manually: resp.Write would try to
	// copy the body, which for an upgrade is the live stream.
	fmt.Fprint(clientBuf, "HTTP/1.1 101 Switching Protocols\r\n")
	resp.Header.WriteSubset(clientBuf, nil)
	fmt.Fprint(clientBuf, "\r\n")
	if err := clientBuf.Flush(); err != nil {
		resp.Body.Close()
		backendConn.Close()
		clientConn.Close()
		return true
	}

	proxyBidirectional(clientConn, clientBuf.Reader, backendConn, backendReader, idle)
	resp.Body.Close()
	backendConn.Close()
	clientConn.Close()
	return true
}

func dialBackend(scheme, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: websocketDialTimeout}
	if scheme == "https" {
		return tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return dialer.Dial("tcp", addr)
}

// idleReader refreshes the read deadline before every read, so a
// connection that stays silent for the idle duration times out
// instead of lingering forever.
type idleReader struct {
	conn net.Conn
	idle time.Duration
	r    io.Reader
}

func (r *idleReader) Read(p []byte) (int, error) {
	r.conn.SetReadDeadline(time.Now().Add(r.idle))
	return r.r.Read(p)
}

// proxyBidirectional copies bytes between the client and the
// backend until either direction ends (close, error, or idle
// timeout). When the first direction ends, both connections are
// closed so the other direction unwinds immediately instead of
// waiting out the idle timeout. The caller still closes both
// connections afterwards; double close is harmless.
func proxyBidirectional(clientConn net.Conn, clientReader io.Reader, backendConn net.Conn, backendReader io.Reader, idle time.Duration) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(backendConn, &idleReader{conn: clientConn, idle: idle, r: clientReader})
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, &idleReader{conn: backendConn, idle: idle, r: backendReader})
		done <- struct{}{}
	}()
	<-done
	clientConn.Close()
	backendConn.Close()
	<-done
}
