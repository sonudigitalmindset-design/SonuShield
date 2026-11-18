package firewall

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go"
)

// QUIC fingerprinting (Batch 3): LIVE for HTTP/3 traffic.
//
// When proxy.http3 is enabled, SonuShield serves HTTP/3 over
// QUIC (UDP) alongside HTTP/1.1 and HTTP/2 over TCP, and
// every HTTP/3 request carries a QUIC fingerprint in the
// ip.quic firewall rule field. Non-QUIC requests get an
// empty value, so rules on ip.quic never match TCP traffic.
//
// What the fingerprint contains — only signals quic-go
// actually exposes about the peer, via ConnectionState:
//
//   - The negotiated QUIC version.
//   - The TLS version and cipher suite of the QUIC crypto
//     handshake, and the negotiated ALPN (always "h3").
//   - Whether the session was resumed (TLS session ticket),
//     whether 0-RTT was used, whether the peer advertised
//     QUIC datagram support, and whether it advertised
//     stream-reset partial delivery. All four are real peer
//     signals carried in the handshake.
//
// What it does NOT contain, because quic-go's public API
// does not expose it: the raw transport parameters
// (initial_max_data, max_idle_timeout, max_streams,
// ack_delay_exponent, ...), packet-level behavior, or
// version-negotiation attempts. Those values are documented
// as unobservable rather than guessed. GSO status is also
// excluded: it describes the local socket, not the client.
//
// Format: q1:<quic-version-8hex>:<tlsver-2hex>-<cipher-4hex>
// :<alpn>:<flags>, where flags are four 0/1 bits in order:
// resumed, 0-RTT used, datagrams advertised, stream-reset
// partial delivery advertised. Example:
// q1:00000001:13-1301:h3:0000
//
// The TLS ClientHello fingerprinting (legacy fingerprint
// and JA4) runs for QUIC handshakes too: quic-go honors
// tls.Config.GetConfigForClient, so the same Fingerprint
// hook records the same maps, keyed by the UDP remote
// address. Passive OS fingerprinting does not apply to
// QUIC (no TCP_INFO on a UDP socket), so ip.os and
// ip.tcpinfo stay empty for HTTP/3 requests.

// QUICRuleField is the firewall rule field name for the
// QUIC fingerprint.
const QUICRuleField = "ip.quic"

// quicConnKey is the request-context key under which the
// HTTP/3 server stores the live QUIC connection.
type quicConnKey struct{}

// ContextWithQUICConn returns ctx carrying conn, for the
// HTTP/3 server's ConnContext hook. The connection is read
// lazily per request: ConnectionState is stable once the
// handshake completes, and reading it per request avoids
// snapshotting state before the handshake finishes.
func ContextWithQUICConn(ctx context.Context, conn *quic.Conn) context.Context {
	return context.WithValue(ctx, quicConnKey{}, conn)
}

// ComputeQUICFingerprint returns the QUIC fingerprint for a
// request, or "" when the request did not arrive over HTTP/3
// or no QUIC connection is attached to its context.
func ComputeQUICFingerprint(r *http.Request) string {
	if r == nil || r.ProtoMajor != 3 {
		return ""
	}
	conn, ok := r.Context().Value(quicConnKey{}).(*quic.Conn)
	if !ok || conn == nil {
		return ""
	}
	return FingerprintFromQUICState(conn.ConnectionState())
}

// FingerprintFromQUICState formats a QUIC connection state
// as a fingerprint string. It is a pure function of the
// exposed state so it can be unit-tested without a live
// connection.
func FingerprintFromQUICState(st quic.ConnectionState) string {
	alpn := st.TLS.NegotiatedProtocol
	if alpn == "" {
		alpn = "none"
	}
	flags := []byte{'0', '0', '0', '0'}
	if st.TLS.DidResume {
		flags[0] = '1'
	}
	if st.Used0RTT {
		flags[1] = '1'
	}
	if st.SupportsDatagrams.Remote {
		flags[2] = '1'
	}
	if st.SupportsStreamResetPartialDelivery.Remote {
		flags[3] = '1'
	}
	return fmt.Sprintf("q1:%08x:%02x-%04x:%s:%s",
		uint32(st.Version), tlsVersionCode(st.TLS.Version), st.TLS.CipherSuite, alpn, string(flags))
}
