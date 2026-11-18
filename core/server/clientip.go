package server

import "net"

// clientIPFromRemoteAddr extracts the client IP from a
// RemoteAddr ("IP:port" or "[IPv6]:port"). The old code split
// on ":" and took the first field, which turned every IPv6
// client into "[" in logs and reports. net.SplitHostPort
// handles both families; an unparseable address falls back to
// the raw value, exactly like the audit peer-IP helpers.
func clientIPFromRemoteAddr(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
