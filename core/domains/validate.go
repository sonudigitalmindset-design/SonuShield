package domains

// Shared validation helpers for values that appear both in the
// config file and in API requests.

import (
	"net"
	"regexp"
	"strings"
)

var ruleActionPattern = regexp.MustCompile(`^[+-]?[0-9]+$`)

// ValidRuleAction reports whether a firewall rule action is spelled
// the way the evaluator expects: a plain integer (static suspicion
// level) or +N / -N (adjust the level and keep evaluating). Anything
// else would fail or crash request evaluation, which indexes the
// action's first byte and scans the rest as an integer.
func ValidRuleAction(action string) bool {
	return ruleActionPattern.MatchString(action)
}

// ValidHostname reports whether host is a valid DNS hostname (LDH
// labels) or an IP literal. Schemes, ports, paths, underscores,
// and empty labels are rejected. Single labels (localhost,
// intranet names) are accepted: the proxy matches Host headers
// literally, so any name a client can send is a usable domain
// name. (The setup wizard applies the same rules; see
// server.validWizardHost, kept separate because the wizard
// predates this helper.)
func ValidHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.HasSuffix(host, "-") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// SplitBackend splits a host:port backend, accepting bracketed
// IPv6 literals. It reports the host and port separately so the
// stored backend can be normalized with net.JoinHostPort.
func SplitBackend(backend string) (host, port string, ok bool) {
	backend = strings.TrimSpace(backend)
	host, port, err := net.SplitHostPort(backend)
	if err != nil {
		return "", "", false
	}
	if !ValidHostname(host) {
		return "", "", false
	}
	if len(port) == 0 || len(port) > 5 {
		return "", "", false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return "", "", false
		}
		n = n*10 + int(port[i]-'0')
	}
	if n < 1 || n > 65535 {
		return "", "", false
	}
	return host, port, true
}
