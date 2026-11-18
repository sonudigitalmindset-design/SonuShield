package firewall

import "net/http"

// QUIC fingerprinting: reserved, INACTIVE (Batch 6 honesty limit).
//
// There is no QUIC listener in SonuShield today: the proxy serves
// HTTP/1.1 and HTTP/2 over TCP only, and HTTP/3 (QUIC over UDP)
// is Batch 3 work, deliberately sequenced last. Without a QUIC
// transport there is no QUIC traffic to fingerprint, so this file
// computes nothing and invents no values. What it reserves is the
// shape of the feature, so Batch 3 has a defined place to land:
//
//   - Rule field: ip.quic. It is present in the firewall
//     evaluation message with an empty value, so expressions
//     referencing it compile (in config files) but never match.
//     The API rule validator deliberately does NOT allow it yet:
//     like the other never-populated fields, accepting it would
//     create rules that look live but do nothing. When Batch 3
//     populates it, the validator allowlist gains the field in
//     the same change.
//   - Planned fingerprint format (to be finalized against the
//     QUIC stack Batch 3 adopts): the QUIC version, the ordered
//     transport-parameter set, and the TLS ClientHello fields
//     carried inside QUIC crypto, hashed the way JA4 hashes the
//     TLS handshake — a stable string per client stack, empty
//     for non-QUIC traffic. No values are bundled or assumed
//     until real QUIC handshakes are observable.
//
// ComputeQUICFingerprint returns the QUIC fingerprint for a
// request. It always returns "" today: no request reaching this
// proxy arrived over QUIC. The signature takes the request so
// the call site in middleware does not change when Batch 3 adds
// a QUIC listener.

// QUICRuleField is the firewall rule field name reserved for the
// QUIC fingerprint.
const QUICRuleField = "ip.quic"

// ComputeQUICFingerprint returns "" for every request: there is
// no QUIC listener yet (see the file header). It exists so the
// evaluation message carries the reserved field, and so Batch 3
// only has to fill in this function.
func ComputeQUICFingerprint(_ *http.Request) string {
	return ""
}
