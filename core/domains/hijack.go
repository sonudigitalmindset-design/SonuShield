package domains

// Session hijack configuration (Batch 8).
//
// SessionHijackConfig names the application session cookie
// whose reuse the proxy watches. The challenge cookie itself
// is a poor signal for this (it is bound to the client IP by
// construction), so the operator names their own session
// cookie — for example "PHPSESSID" or "sessionid". With no
// cookie named, the feature is off. See
// firewall/hijack.go for the detection rules.

import "strings"

// SessionHijackConfig is the per-domain session-hijack
// configuration (domain.sessionHijack). Cookie is the session
// cookie name; Mode is "log" (default, log only) or "block"
// (flagged requests get a suspicion bump toward the captcha
// challenge).
type SessionHijackConfig struct {
	Cookie string `json:"cookie"`
	Mode   string `json:"mode"`
}

// HijackBlock reports whether enforcement mode is on.
func (c SessionHijackConfig) HijackBlock() bool {
	return strings.ToLower(strings.TrimSpace(c.Mode)) == "block"
}
