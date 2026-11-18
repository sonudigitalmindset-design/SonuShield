//go:build !linux

package firewall

import "net"

// CollectTCPInfo is unavailable off Linux: TCP_INFO is a
// Linux-specific socket option, and Go exposes no equivalent on
// other platforms. Callers treat the false result as "not
// observed", so ip.os stays "unknown" there.
func CollectTCPInfo(conn net.Conn) (TCPInfoSignals, bool) {
	return TCPInfoSignals{}, false
}
