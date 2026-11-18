package domains

// Origin-signal configuration (Batch 8).
//
// OriginSignalsConfig holds the shared secret that origin
// servers use to authenticate signals posted to
// POST /_bProxy/origin-signal (see server/originsignal.go).
// The secret is config-only, never logged, never returned by
// any API action, and redacted from exports and backups. With
// no secret configured the endpoint does not exist: requests
// fall through to the origin like any unknown path.
//
// Signals carry {domain, type, ip, path}. Today the only
// type is "login_failure", which feeds the credential
// stuffing detector (Batch 8, item 3) for the domain's
// watched paths. No usernames, passwords, or other
// credentials are ever sent: the signal proves only that a
// login failed from an IP on a path.

// OriginSignalsConfig is the proxy-level origin-signal
// configuration (proxy.originSignals).
type OriginSignalsConfig struct {
	Secret string `json:"secret"`
}
