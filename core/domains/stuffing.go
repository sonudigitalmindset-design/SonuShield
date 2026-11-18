package domains

// Credential stuffing configuration (Batch 8).
//
// StuffingConfig names the login-shaped paths whose failed
// responses the proxy watches, and the thresholds at which a
// pattern counts as credential stuffing. No credential data is
// ever inspected: the detector counts failed responses (by
// status code) per IP and across distinct IPs. See
// firewall/stuffing.go for the detection rules and
// docs/configuration.md for the documented defaults.

import "strings"

// StuffingConfig is the per-domain credential-stuffing
// configuration (domain.credentialStuffing). Paths lists the
// path prefixes watched (empty means the feature is off);
// FailureStatuses lists the origin statuses that count as a
// failed login (default 401, 403); PerIPThreshold is the
// per-IP failure count in the window that flags one IP
// (default 10); DistributedThreshold is the distinct-IP count
// with failures on one path in the window that flags a
// distributed attempt (default 20); WindowSeconds is the
// observation window (default 300); Mode is "log" (default,
// log only) or "block" (flagged requests get a suspicion bump
// toward the captcha challenge).
type StuffingConfig struct {
	Paths                []string `json:"paths"`
	FailureStatuses      []int    `json:"failureStatuses"`
	PerIPThreshold       int      `json:"perIpThreshold"`
	DistributedThreshold int      `json:"distributedThreshold"`
	WindowSeconds        int      `json:"windowSeconds"`
	Mode                 string   `json:"mode"`
}

// StuffingDefaults are the detection defaults, documented in
// docs/configuration.md.
const (
	DefaultStuffingPerIPThreshold       = 10
	DefaultStuffingDistributedThreshold = 20
	DefaultStuffingWindowSeconds        = 300
)

// StuffingEffective resolves a StuffingConfig to its effective
// settings, applying defaults for unset values. It reports
// whether the feature is enabled at all (paths configured).
func (c StuffingConfig) StuffingEffective() (enabled bool, statuses []int, perIP, distributed, window int, block bool) {
	if len(c.Paths) == 0 {
		return false, nil, 0, 0, 0, false
	}
	statuses = c.FailureStatuses
	if len(statuses) == 0 {
		statuses = []int{401, 403}
	}
	perIP = c.PerIPThreshold
	if perIP <= 0 {
		perIP = DefaultStuffingPerIPThreshold
	}
	distributed = c.DistributedThreshold
	if distributed <= 0 {
		distributed = DefaultStuffingDistributedThreshold
	}
	window = c.WindowSeconds
	if window <= 0 {
		window = DefaultStuffingWindowSeconds
	}
	block = strings.ToLower(strings.TrimSpace(c.Mode)) == "block"
	return true, statuses, perIP, distributed, window, block
}

// StuffingPath reports whether path is watched by this config.
func (c StuffingConfig) StuffingPath(path string) bool {
	for _, prefix := range c.Paths {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// StuffingFailureStatus reports whether status counts as a
// failed login under this config.
func (c StuffingConfig) StuffingFailureStatus(status int) bool {
	_, statuses, _, _, _, _ := c.StuffingEffective()
	for _, s := range statuses {
		if s == status {
			return true
		}
	}
	return false
}
