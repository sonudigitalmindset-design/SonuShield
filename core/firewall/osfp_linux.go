//go:build linux

package firewall

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// TCP_INFO Options bitmask values, from include/uapi/linux/tcp.h.
// x/sys/unix does not export these constants.
const (
	tcpiOptTimestamps = 1
	tcpiOptSACK       = 2
	tcpiOptWScale     = 4
)

// CollectTCPInfo reads the kernel's TCP_INFO for an accepted
// connection. It returns false on any failure (non-TCP
// connection, wrapped connection without a file descriptor,
// unsupported platform): the caller treats that as "not
// observed" and the client stays "unknown".
func CollectTCPInfo(conn net.Conn) (TCPInfoSignals, bool) {
	raw := unwrapConn(conn)
	sc, ok := raw.(syscall.Conn)
	if !ok {
		return TCPInfoSignals{}, false
	}
	sysConn, err := sc.SyscallConn()
	if err != nil {
		return TCPInfoSignals{}, false
	}
	var info *unix.TCPInfo
	ctrlErr := sysConn.Control(func(fd uintptr) {
		var err error
		info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			info = nil
		}
	})
	if ctrlErr != nil || info == nil {
		return TCPInfoSignals{}, false
	}
	return TCPInfoSignals{
		SndMSS:     int(info.Snd_mss),
		RcvMSS:     int(info.Rcv_mss),
		RTTMicros:  info.Rtt,
		WScale:     info.Options&tcpiOptWScale != 0,
		Timestamps: info.Options&tcpiOptTimestamps != 0,
		SACK:       info.Options&tcpiOptSACK != 0,
		Available:  true,
	}, true
}

// unwrapConn follows NetConn() wrappers (for example a TLS
// connection wrapping the raw TCP connection) until it reaches
// a connection that exposes its file descriptor, or gives up
// after a few hops.
func unwrapConn(conn net.Conn) net.Conn {
	for i := 0; i < 4; i++ {
		if _, ok := conn.(syscall.Conn); ok {
			return conn
		}
		wrapper, ok := conn.(interface{ NetConn() net.Conn })
		if !ok || wrapper.NetConn() == nil {
			return conn
		}
		conn = wrapper.NetConn()
	}
	return conn
}
