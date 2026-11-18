package sharing

// Threat sharing network (Batch 8).
//
// SonuShield instances the operator explicitly peers with
// exchange threat indicators: bad IPs and fingerprints with a
// short reason and an expiry. There is no central server and
// no bundled feed. Sharing is off unless
// proxy.threatSharing.enabled is true and at least one peer
// with a shared secret is configured.
//
// Protocol: GET /_bProxy/threat-sharing/indicators returns
// this instance's local indicators as JSON; POST to the same
// path submits indicators. Every request carries
// X-SonuShield-Sharing: t=<unix seconds>,s=<hex HMAC-SHA256>
// where the MAC covers timestamp, method, path, and the
// SHA-256 of the body. Timestamps must be within 300 seconds.
// A request is accepted when ANY configured peer secret
// verifies it (peers are few; the secret identifies the
// pairing). The handler lives in core/server (sharing.go);
// this package owns the store, the signing, and the pull/push
// loops.
//
// Indicators expire (default 1 hour, clamped to 24 hours) and
// are pruned lazily. Received indicators raise suspicion by
// one level on matching requests — they never block on their
// own. Peer errors fail open: a failed pull keeps the
// previously received indicators until they expire. Only
// error transitions are logged, so a dead peer does not spam
// the log.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sonushield/core/domains"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// sharingPath is the peer endpoint path.
	sharingPath = "/_bProxy/threat-sharing/indicators"
	// maxClockSkewSeconds bounds the signature timestamp.
	maxClockSkewSeconds = 300
	// maxIndicatorTTL bounds indicator lifetime.
	maxIndicatorTTL = 24 * time.Hour
	// defaultIndicatorTTL applies when none is supplied.
	defaultIndicatorTTL = time.Hour
	// maxIndicatorsPerPeer bounds stored indicators per source.
	maxIndicatorsPerPeer = 10000
	// maxPeerBody bounds peer request/response bodies.
	maxPeerBody = 1 << 20
)

// Indicator is one shared threat indicator.
type Indicator struct {
	Type      string    `json:"type"` // "ip" or "fingerprint"
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expiresAt"`
	Source    string    `json:"source,omitempty"`
}

// validate normalizes and checks an indicator, applying the
// default/clamped expiry. It reports whether the indicator is
// usable.
func (ind *Indicator) validate(now time.Time) bool {
	switch ind.Type {
	case "ip":
		if net.ParseIP(ind.Value) == nil {
			return false
		}
	case "fingerprint":
		if ind.Value == "" || len(ind.Value) > 256 {
			return false
		}
	default:
		return false
	}
	if len(ind.Reason) > 64 {
		ind.Reason = ind.Reason[:64]
	}
	if ind.ExpiresAt.IsZero() || ind.ExpiresAt.Before(now) {
		ind.ExpiresAt = now.Add(defaultIndicatorTTL)
	}
	if ind.ExpiresAt.After(now.Add(maxIndicatorTTL)) {
		ind.ExpiresAt = now.Add(maxIndicatorTTL)
	}
	return true
}

var (
	mu         sync.Mutex
	cfg        domains.ThreatSharingConfig
	enabled    bool
	local      = map[string]Indicator{}
	received   = map[string]Indicator{}
	peerState  = map[string]*peerStatus{}
	loopOnce   sync.Once
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

type peerStatus struct {
	LastSuccessUnix int64
	LastError       string
	Failing         bool
}

// Configure installs the sharing configuration and starts the
// pull loop when sharing is enabled. A reload replaces the
// config but keeps the stored indicators.
func Configure(c domains.ThreatSharingConfig) {
	mu.Lock()
	cfg = c
	enabled = c.Enabled && len(usablePeers(c)) > 0
	for _, peer := range cfg.Peers {
		if _, ok := peerState[peer.Name]; !ok {
			peerState[peer.Name] = &peerStatus{}
		}
	}
	shouldStart := enabled
	mu.Unlock()
	if shouldStart {
		loopOnce.Do(func() { go pullLoop() })
	}
}

func usablePeers(c domains.ThreatSharingConfig) []domains.SharingPeer {
	var out []domains.SharingPeer
	for _, peer := range c.Peers {
		if peer.Name != "" && peer.URL != "" && peer.SharedSecret != "" {
			out = append(out, peer)
		}
	}
	return out
}

// Enabled reports whether sharing is active.
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled
}

// PushOnCanary reports whether canary hits are shared.
func PushOnCanary() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled && cfg.PushOnCanary
}

// Config returns a copy of the current configuration (for the
// peer endpoint handler). Secrets stay in this copy; callers
// must never log or return it.
func Config() domains.ThreatSharingConfig {
	mu.Lock()
	defer mu.Unlock()
	return cfg
}

func indicatorKey(ind Indicator) string {
	return ind.Type + ":" + ind.Value
}

// AddLocal adds an indicator to the local set, shared with
// peers on pull/push. ttlSeconds <= 0 means the default.
func AddLocal(ind Indicator, ttlSeconds int) bool {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().UTC()
	if ttlSeconds > 0 {
		ind.ExpiresAt = now.Add(time.Duration(ttlSeconds) * time.Second)
	}
	if !ind.validate(now) {
		return false
	}
	ind.Source = "local"
	if len(local) >= maxIndicatorsPerPeer && local[indicatorKey(ind)].Value == "" {
		pruneLocked(now)
		if len(local) >= maxIndicatorsPerPeer {
			return false
		}
	}
	local[indicatorKey(ind)] = ind
	return true
}

// RemoveLocal deletes a local indicator.
func RemoveLocal(indType, value string) bool {
	mu.Lock()
	defer mu.Unlock()
	key := indType + ":" + value
	if _, ok := local[key]; !ok {
		return false
	}
	delete(local, key)
	return true
}

// LocalIndicators returns the non-expired local indicators.
func LocalIndicators() []Indicator {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().UTC()
	pruneLocked(now)
	out := make([]Indicator, 0, len(local))
	for _, ind := range local {
		out = append(out, ind)
	}
	return out
}

// Receive stores indicators submitted by a peer, tagged with
// the peer's name.
func Receive(source string, inds []Indicator) int {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().UTC()
	kept := 0
	for _, ind := range inds {
		if !ind.validate(now) {
			continue
		}
		ind.Source = source
		key := indicatorKey(ind)
		if _, ok := received[key]; !ok && len(received) >= maxIndicatorsPerPeer {
			pruneLocked(now)
			if len(received) >= maxIndicatorsPerPeer {
				continue
			}
		}
		received[key] = ind
		kept++
	}
	return kept
}

// Lookup reports whether an IP or TLS fingerprint matches a
// non-expired received indicator. Local indicators are not
// consulted: they describe what this instance shares, and the
// operator enforces those locally through rules and lists.
func Lookup(ip, fingerprint string) bool {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().UTC()
	if ind, ok := received["ip:"+ip]; ok {
		if ind.ExpiresAt.After(now) {
			return true
		}
	}
	if fingerprint != "" {
		if ind, ok := received["fingerprint:"+fingerprint]; ok && ind.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

// Status reports the sharing state for the API: enabled, peer
// health, and indicator counts. Secrets are never included.
func Status() (bool, []map[string]interface{}, int, int) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().UTC()
	pruneLocked(now)
	peers := []map[string]interface{}{}
	for _, peer := range cfg.Peers {
		state := peerState[peer.Name]
		entry := map[string]interface{}{
			"NAME": peer.Name,
			"URL":  peer.URL,
		}
		if state != nil {
			entry["LAST_SUCCESS"] = state.LastSuccessUnix
			entry["LAST_ERROR"] = state.LastError
		}
		peers = append(peers, entry)
	}
	return enabled, peers, len(local), len(received)
}

func pruneLocked(now time.Time) {
	for key, ind := range local {
		if !ind.ExpiresAt.After(now) {
			delete(local, key)
		}
	}
	for key, ind := range received {
		if !ind.ExpiresAt.After(now) {
			delete(received, key)
		}
	}
}

// Sign builds the X-SonuShield-Sharing header value for a
// request: t=<unix>,s=<hex HMAC-SHA256(secret,
// timestamp + "\n" + method + "\n" + path + "\n" +
// hex(sha256(body)))>.
func Sign(secret, method, path string, body []byte, now time.Time) string {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	bodyHash := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(bodyHash[:])))
	return "t=" + timestamp + ",s=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature header against the configured peer
// secrets and returns the matching peer. The body must be the
// exact bytes received.
func Verify(header, method, path string, body []byte, now time.Time) (domains.SharingPeer, bool) {
	var timestampStr, signature string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestampStr = kv[1]
		case "s":
			signature = kv[1]
		}
	}
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return domains.SharingPeer{}, false
	}
	if delta := now.Unix() - timestamp; delta > maxClockSkewSeconds || delta < -maxClockSkewSeconds {
		return domains.SharingPeer{}, false
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return domains.SharingPeer{}, false
	}
	c := Config()
	for _, peer := range usablePeers(c) {
		bodyHash := sha256.Sum256(body)
		mac := hmac.New(sha256.New, []byte(peer.SharedSecret))
		mac.Write([]byte(timestampStr + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(bodyHash[:])))
		if hmac.Equal(mac.Sum(nil), sigBytes) {
			return peer, true
		}
	}
	return domains.SharingPeer{}, false
}

// pullLoop periodically fetches indicators from every peer.
// Fail-open: errors keep the previous indicators.
func pullLoop() {
	for {
		interval := time.Duration(Config().SharingPullInterval()) * time.Second
		time.Sleep(interval)
		PullAll()
	}
}

// PullAll fetches indicators from every configured peer now.
func PullAll() {
	c := Config()
	for _, peer := range usablePeers(c) {
		pullFrom(peer)
	}
}

func pullFrom(peer domains.SharingPeer) {
	url := strings.TrimRight(peer.URL, "/") + sharingPath
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		notePeerError(peer, err.Error())
		return
	}
	request.Header.Set("X-SonuShield-Sharing", Sign(peer.SharedSecret, http.MethodGet, sharingPath, nil, time.Now().UTC()))
	response, err := httpClient.Do(request)
	if err != nil {
		notePeerError(peer, err.Error())
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPeerBody+1))
	if err != nil || int64(len(body)) > maxPeerBody || response.StatusCode != http.StatusOK {
		notePeerError(peer, fmt.Sprintf("status %d", response.StatusCode))
		return
	}
	var inds []Indicator
	if err := json.Unmarshal(body, &inds); err != nil {
		notePeerError(peer, "bad response")
		return
	}
	Receive(peer.Name, inds)
	notePeerSuccess(peer)
}

// PushAll posts the local indicators to every peer now.
func PushAll() {
	c := Config()
	inds := LocalIndicators()
	body, err := json.Marshal(inds)
	if err != nil {
		return
	}
	for _, peer := range usablePeers(c) {
		pushTo(peer, body)
	}
}

func pushTo(peer domains.SharingPeer, body []byte) {
	url := strings.TrimRight(peer.URL, "/") + sharingPath
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		notePeerError(peer, err.Error())
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-SonuShield-Sharing", Sign(peer.SharedSecret, http.MethodPost, sharingPath, body, time.Now().UTC()))
	response, err := httpClient.Do(request)
	if err != nil {
		notePeerError(peer, err.Error())
		return
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		notePeerError(peer, fmt.Sprintf("status %d", response.StatusCode))
		return
	}
	notePeerSuccess(peer)
}

func notePeerError(peer domains.SharingPeer, message string) {
	mu.Lock()
	defer mu.Unlock()
	state, ok := peerState[peer.Name]
	if !ok {
		state = &peerStatus{}
		peerState[peer.Name] = state
	}
	wasFailing := state.Failing
	state.Failing = true
	state.LastError = message
	if !wasFailing {
		fmt.Println("[ ! ] [ threat sharing: peer \"" + peer.Name + "\" unreachable: " + message + " ]")
	}
}

func notePeerSuccess(peer domains.SharingPeer) {
	mu.Lock()
	defer mu.Unlock()
	state, ok := peerState[peer.Name]
	if !ok {
		state = &peerStatus{}
		peerState[peer.Name] = state
	}
	state.Failing = false
	state.LastError = ""
	state.LastSuccessUnix = time.Now().UTC().Unix()
}
