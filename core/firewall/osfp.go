package firewall

// Passive OS fingerprinting (Batch 7).
//
// SonuShield infers a client OS family ONLY from signals the
// kernel genuinely exposes for an accepted TCP connection, read
// once at accept time via the TCP_INFO socket option (Linux
// only). Nothing is probed, no packet is crafted, and no value
// is ever invented: when a signal is unavailable the client
// stays "unknown".
//
// Signals actually used (all from struct tcp_info):
//
//   - snd_mss / rcv_mss: the MSS values negotiated for the
//     connection (Snd_mss / Rcv_mss).
//   - rtt_us: the smoothed round-trip time in microseconds
//     (Rtt). Exposed raw in ip.tcpinfo; it is a network
//     measurement, not an OS signal, and is never used for
//     classification.
//   - The TCP_INFO options bitmask: whether window scaling,
//     timestamps, and SACK were negotiated (Options bits
//     TCPI_OPT_WSCALE / TCPI_OPT_TIMESTAMPS / TCPI_OPT_SACK).
//
// Classic p0f signals that are NOT available and are NOT
// claimed:
//
//   - TTL, the DF flag, the IP ID, and the TCP options order:
//     Go's net/http never exposes raw IP/TCP headers, and
//     TCP_INFO does not carry them.
//   - The window scale VALUE: TCP_INFO reports only whether
//     window scaling was negotiated, not the scale factor.
//   - The initial window size: Snd_wnd/Rcv_wnd are current
//     values that change with congestion control, not the
//     SYN-time window, so they are not used.
//
// Classification is entirely operator-defined. The operator
// supplies signature mappings in proxy.osSignatures; a client
// matches a signature only when every specified field matches
// (unspecified fields match anything). With no signatures
// configured, ip.os is always "unknown" and ip.tcpinfo still
// reports the raw signals. The values are exposed as firewall
// rule fields (ip.os, ip.tcpinfo) and on the /_bProxy/fingerprint
// page. In Cloudflare mode there is no connection-state hook, so
// no signals are collected and every client is "unknown".
//
// State is bounded: one small record per open connection, keyed
// by RemoteAddr, deleted when the connection closes or is
// hijacked, exactly like the TLS fingerprint maps.

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"sonushield/core/domains"
)

// TCPInfoSignals is the set of genuinely observable TCP signals
// for one accepted connection.
type TCPInfoSignals struct {
	SndMSS     int
	RcvMSS     int
	RTTMicros  uint32
	WScale     bool
	Timestamps bool
	SACK       bool
	// Available is true when the signals were actually read
	// from the kernel. A zero value means "not observed".
	Available bool
}

// String renders the raw signals for the ip.tcpinfo rule field.
// It is empty when nothing was observed.
func (s TCPInfoSignals) String() string {
	if !s.Available {
		return ""
	}
	var b strings.Builder
	b.WriteString("snd_mss=")
	b.WriteString(strconv.Itoa(s.SndMSS))
	b.WriteString(",rcv_mss=")
	b.WriteString(strconv.Itoa(s.RcvMSS))
	b.WriteString(",rtt_us=")
	b.WriteString(strconv.FormatUint(uint64(s.RTTMicros), 10))
	b.WriteString(",wscale=")
	b.WriteString(boolBit(s.WScale))
	b.WriteString(",ts=")
	b.WriteString(boolBit(s.Timestamps))
	b.WriteString(",sack=")
	b.WriteString(boolBit(s.SACK))
	return b.String()
}

func boolBit(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

var (
	osSignalsMu sync.Mutex
	osSignals   = map[string]TCPInfoSignals{}
)

// StoreTCPInfo records the observed signals for one connection.
func StoreTCPInfo(remoteAddr string, signals TCPInfoSignals) {
	if remoteAddr == "" {
		return
	}
	osSignalsMu.Lock()
	osSignals[remoteAddr] = signals
	osSignalsMu.Unlock()
}

// SignalsFor returns the observed signals for a connection, or
// a zero value when nothing was observed.
func SignalsFor(remoteAddr string) TCPInfoSignals {
	osSignalsMu.Lock()
	defer osSignalsMu.Unlock()
	return osSignals[remoteAddr]
}

// ForgetTCPInfo drops the signals for a closed connection.
func ForgetTCPInfo(remoteAddr string) {
	osSignalsMu.Lock()
	delete(osSignals, remoteAddr)
	osSignalsMu.Unlock()
}

var (
	osSignaturesMu sync.RWMutex
	osSignatures   []domains.OSSignature
)

// SetOSSignatures installs the operator-supplied signature
// mappings. Signatures with an empty label are dropped; the rest
// are used in order, first match wins.
func SetOSSignatures(signatures []domains.OSSignature) {
	kept := make([]domains.OSSignature, 0, len(signatures))
	for _, sig := range signatures {
		if strings.TrimSpace(sig.Label) == "" {
			continue
		}
		kept = append(kept, sig)
	}
	osSignaturesMu.Lock()
	osSignatures = kept
	osSignaturesMu.Unlock()
}

// ClassifyOS returns the label of the first signature whose
// specified fields all match the observed signals, or
// "unknown" when nothing was observed or nothing matches.
func ClassifyOS(signals TCPInfoSignals) string {
	if !signals.Available {
		return "unknown"
	}
	osSignaturesMu.RLock()
	defer osSignaturesMu.RUnlock()
	for _, sig := range osSignatures {
		if signatureMatches(sig, signals) {
			return sig.Label
		}
	}
	return "unknown"
}

// signatureMatches reports whether every field the operator
// specified in sig matches the observed signals. A zero MSS
// means "any"; a nil option pointer means "any".
func signatureMatches(sig domains.OSSignature, signals TCPInfoSignals) bool {
	if sig.SndMSS != 0 && sig.SndMSS != signals.SndMSS {
		return false
	}
	if sig.RcvMSS != 0 && sig.RcvMSS != signals.RcvMSS {
		return false
	}
	if sig.WScale != nil && *sig.WScale != signals.WScale {
		return false
	}
	if sig.Timestamps != nil && *sig.Timestamps != signals.Timestamps {
		return false
	}
	if sig.SACK != nil && *sig.SACK != signals.SACK {
		return false
	}
	return true
}

// DescribeOSSignatures returns a summary of the configured
// signatures for diagnostics. It contains labels and match
// fields only — never client data.
func DescribeOSSignatures() string {
	osSignaturesMu.RLock()
	defer osSignaturesMu.RUnlock()
	if len(osSignatures) == 0 {
		return "none configured"
	}
	labels := make([]string, 0, len(osSignatures))
	for _, sig := range osSignatures {
		labels = append(labels, sig.Label)
	}
	return fmt.Sprintf("%d signature(s): %s", len(osSignatures), strings.Join(labels, ", "))
}
