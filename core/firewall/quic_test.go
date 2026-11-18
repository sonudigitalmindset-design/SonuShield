package firewall

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestFingerprintFromQUICState(t *testing.T) {
	base := quic.ConnectionState{
		Version: quic.Version1,
		TLS: tls.ConnectionState{
			Version:            tls.VersionTLS13,
			CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
			NegotiatedProtocol: "h3",
		},
	}
	got := FingerprintFromQUICState(base)
	want := "q1:00000001:13-1301:h3:0000"
	if got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}

	// Each flag bit flips independently.
	resumed := base
	resumed.TLS.DidResume = true
	if got := FingerprintFromQUICState(resumed); !strings.HasSuffix(got, ":1000") {
		t.Fatalf("resumed fingerprint = %q, want suffix :1000", got)
	}
	zeroRTT := base
	zeroRTT.Used0RTT = true
	if got := FingerprintFromQUICState(zeroRTT); !strings.HasSuffix(got, ":0100") {
		t.Fatalf("0-RTT fingerprint = %q, want suffix :0100", got)
	}
	dgram := base
	dgram.SupportsDatagrams.Remote = true
	if got := FingerprintFromQUICState(dgram); !strings.HasSuffix(got, ":0010") {
		t.Fatalf("datagram fingerprint = %q, want suffix :0010", got)
	}
	srpd := base
	srpd.SupportsStreamResetPartialDelivery.Remote = true
	if got := FingerprintFromQUICState(srpd); !strings.HasSuffix(got, ":0001") {
		t.Fatalf("stream-reset fingerprint = %q, want suffix :0001", got)
	}

	// A different QUIC version or cipher suite changes the
	// fingerprint; identical states are stable.
	other := base
	other.Version = quic.Version2
	if FingerprintFromQUICState(other) == want {
		t.Fatal("QUIC v2 state produced the v1 fingerprint")
	}
	otherCipher := base
	otherCipher.TLS.CipherSuite = tls.TLS_CHACHA20_POLY1305_SHA256
	if FingerprintFromQUICState(otherCipher) == want {
		t.Fatal("ChaCha state produced the AES fingerprint")
	}
	if again := FingerprintFromQUICState(base); again != want {
		t.Fatalf("repeat fingerprint = %q, want %q", again, want)
	}

	// Missing ALPN renders as "none", never empty.
	noALPN := base
	noALPN.TLS.NegotiatedProtocol = ""
	if got := FingerprintFromQUICState(noALPN); !strings.Contains(got, ":none:") {
		t.Fatalf("no-ALPN fingerprint = %q, want :none: segment", got)
	}
}

func TestComputeQUICFingerprintEmptyPaths(t *testing.T) {
	if got := ComputeQUICFingerprint(nil); got != "" {
		t.Fatalf("nil request = %q, want empty", got)
	}
	http1 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	http1.ProtoMajor = 1
	if got := ComputeQUICFingerprint(http1); got != "" {
		t.Fatalf("HTTP/1.1 request = %q, want empty", got)
	}
	http2 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	http2.ProtoMajor = 2
	if got := ComputeQUICFingerprint(http2); got != "" {
		t.Fatalf("HTTP/2 request = %q, want empty", got)
	}
	// An HTTP/3 request with no QUIC connection attached
	// (e.g. a synthetic request) fingerprints empty rather
	// than panicking.
	http3 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	http3.ProtoMajor = 3
	if got := ComputeQUICFingerprint(http3); got != "" {
		t.Fatalf("HTTP/3 request without a connection = %q, want empty", got)
	}
}
