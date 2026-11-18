package server

// Post-quantum TLS and ECH status (Batch 6).
//
// Post-quantum key exchange: Go 1.24 negotiates X25519MLKEM768
// (a hybrid of X25519 and the ML-KEM-768 post-quantum KEM) by
// default, preferring it over classic X25519 whenever the client
// offers it. SonuShield keeps that default: with no configuration
// the HTTPS listener negotiates the hybrid group with any modern
// client that offers it, and falls back to classic groups with
// older clients. The operator can turn the hybrid group off with
// proxy.tlsDisablePostQuantum, which restricts the listener to
// the classic groups (X25519, P-256, P-384, P-521) — for example
// when a middlebox mishandles the larger ClientHello. The
// setting only affects the listener; outbound connections keep
// Go's defaults.
//
// This was verified with real handshakes, not assumed: a client
// offering ONLY X25519MLKEM768 completes a handshake against the
// default listener and fails against a listener with the hybrid
// group disabled, which proves the group is actually negotiated
// rather than merely offered. See the Batch 6 smoke harness.
//
// Encrypted ClientHello (ECH): NOT supported. Go's crypto/tls
// has no server-side ECH support as of Go 1.24, and SonuShield
// does not claim otherwise. The Server Name Indication in the
// ClientHello is therefore still visible to network observers.
// The honest path forward is a future Go release with ECH
// support, or terminating TLS in front of SonuShield with a
// dedicated terminator that implements ECH (for example a
// Cloudflare-style edge) and forwarding the inner SNI. Until
// then, ECH stays documented as unavailable; no code here
// pretends to implement it.

import (
	"crypto/tls"
	"sonushield/core/domains"
)

// tlsCurvePreferences returns the key-exchange group preferences
// for the HTTPS listener. A nil result means Go's default, which
// prefers X25519MLKEM768 and falls back to the classic groups.
// When the operator disables post-quantum key exchange, only the
// classic groups are offered.
func tlsCurvePreferences() []tls.CurveID {
	if domains.Config != nil && domains.Config.Proxy.TLSDisablePostQuantum {
		return []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	}
	return nil
}
