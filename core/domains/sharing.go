package domains

// Threat sharing configuration (Batch 8).
//
// ThreatSharingConfig names the peer SonuShield instances
// this proxy exchanges threat indicators with. Sharing is
// opt-in and peer-to-peer: there is no central server, no
// bundled feed, and no peer is contacted unless the operator
// lists it. Each peer has its own shared secret (config-only,
// never logged or returned by the API) used to HMAC-sign
// every exchange. Indicators carry only an IP or fingerprint,
// a short reason, and an expiry — no PII beyond the indicator
// itself. See core/sharing for the protocol and the store.

// SharingPeer is one peer instance: a display name, the base
// URL of the peer's proxy (for example
// "https://peer.example.com"), and the shared secret both
// sides configured for this pairing.
type SharingPeer struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	SharedSecret string `json:"sharedSecret"`
}

// ThreatSharingConfig is the proxy-level threat-sharing
// configuration (proxy.threatSharing). PullIntervalSeconds
// defaults to 300 (minimum 60). PushOnCanary, when true,
// shares the attacker's IP/fingerprint with peers when a
// canary token is tripped.
type ThreatSharingConfig struct {
	Enabled             bool          `json:"enabled"`
	Peers               []SharingPeer `json:"peers"`
	PullIntervalSeconds int           `json:"pullIntervalSeconds"`
	PushOnCanary        bool          `json:"pushOnCanary"`
}

// SharingPullInterval resolves the pull interval with the
// documented default and floor, in seconds.
func (c ThreatSharingConfig) SharingPullInterval() int {
	if c.PullIntervalSeconds <= 0 {
		return 300
	}
	if c.PullIntervalSeconds < 60 {
		return 60
	}
	return c.PullIntervalSeconds
}

// SharingPeerBySecret finds a peer whose secret matches,
// comparing in constant time. An empty secret never matches.
func (c ThreatSharingConfig) SharingPeerBySecret(secret string) (SharingPeer, bool) {
	if secret == "" {
		return SharingPeer{}, false
	}
	for _, peer := range c.Peers {
		if peer.SharedSecret != "" && subtleEqual(peer.SharedSecret, secret) {
			return peer, true
		}
	}
	return SharingPeer{}, false
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	diff := 0
	for i := 0; i < len(a); i++ {
		diff |= int(a[i] ^ b[i])
	}
	return diff == 0
}
