package firewall

import (
	"crypto/tls"
	"strings"
	"testing"
)

// JA4: the "a" section renders version, SNI, counts, and ALPN per
// the FoxIO specification. An empty ClientHello renders all
// zero placeholders.
func TestComputeJA4FromPartsEmpty(t *testing.T) {
	got := ComputeJA4FromParts(JA4Parts{})
	if got != "t00i000000_000000000000_000000000000" {
		t.Fatalf("empty JA4 = %q", got)
	}
}

func TestComputeJA4FromPartsSections(t *testing.T) {
	p := JA4Parts{
		HighestVersion: 0x0304,
		HasSNI:         true,
		Ciphers:        []uint16{0x1301, 0x1302, 0x1303},
		Extensions:     []uint16{0x0000, 0x0010, 0x002b, 0x000b},
		FirstALPN:      "h2",
		HasALPN:        true,
		SigAlgs:        []uint16{0x0403, 0x0804},
	}
	got := ComputeJA4FromParts(p)
	parts := strings.Split(got, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 %q has %d sections, want 3", got, len(parts))
	}
	if parts[0] != "t13d0304h2" {
		t.Fatalf("JA4 a-section = %q, want t13d0304h2", parts[0])
	}
	for _, h := range parts[1:] {
		if len(h) != 12 {
			t.Fatalf("JA4 hash section %q is %d chars, want 12", h, len(h))
		}
		for _, c := range h {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Fatalf("JA4 hash section %q is not lowercase hex", h)
			}
		}
	}
}

// GREASE values must not change the fingerprint anywhere.
func TestComputeJA4GREASEInvariant(t *testing.T) {
	base := JA4Parts{
		HighestVersion: 0x0303,
		HasSNI:         true,
		Ciphers:        []uint16{0x1301, 0xc02f},
		Extensions:     []uint16{0x0000, 0x002b},
		FirstALPN:      "http/1.1",
		HasALPN:        true,
		SigAlgs:        []uint16{0x0403},
	}
	greased := base
	greased.Ciphers = []uint16{0x0a0a, 0x1301, 0xc02f, 0x1a1a}
	greased.Extensions = []uint16{0x0a0a, 0x0000, 0x002b, 0xfafa}
	greased.SigAlgs = []uint16{0x0a0a, 0x0403}
	if ComputeJA4FromParts(base) != ComputeJA4FromParts(greased) {
		t.Fatalf("GREASE changed JA4: %q vs %q", ComputeJA4FromParts(base), ComputeJA4FromParts(greased))
	}
}

// The cipher hash sorts its input; the signature-algorithm list
// keeps client order.
func TestComputeJA4Ordering(t *testing.T) {
	a := JA4Parts{Ciphers: []uint16{0x1301, 0x1302}, Extensions: []uint16{0x002b}, SigAlgs: []uint16{0x0403, 0x0804}}
	b := JA4Parts{Ciphers: []uint16{0x1302, 0x1301}, Extensions: []uint16{0x002b}, SigAlgs: []uint16{0x0403, 0x0804}}
	if ComputeJA4FromParts(a) != ComputeJA4FromParts(b) {
		t.Fatal("cipher order changed the JA4")
	}
	c := JA4Parts{Ciphers: []uint16{0x1301, 0x1302}, Extensions: []uint16{0x002b}, SigAlgs: []uint16{0x0804, 0x0403}}
	if ComputeJA4FromParts(a) == ComputeJA4FromParts(c) {
		t.Fatal("signature-algorithm order did not change the JA4")
	}
}

func TestComputeJA4Versions(t *testing.T) {
	cases := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0301: "10", 0x0300: "s3", 0x9999: "00"}
	for version, want := range cases {
		got := ComputeJA4FromParts(JA4Parts{HighestVersion: version})
		if !strings.HasPrefix(got, "t"+want) {
			t.Fatalf("version %#04x: JA4 = %q, want prefix t%s", version, got, want)
		}
	}
}

func TestComputeJA4NilHello(t *testing.T) {
	if got := ComputeJA4(nil); got != "" {
		t.Fatalf("ComputeJA4(nil) = %q, want empty", got)
	}
}

func TestComputeJA4FromHello(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2"},
	}
	got := ComputeJA4(hello)
	if !strings.HasPrefix(got, "t13d") {
		t.Fatalf("ComputeJA4 = %q, want t13d prefix", got)
	}
	if len(strings.Split(got, "_")) != 3 {
		t.Fatalf("ComputeJA4 = %q, want 3 sections", got)
	}
}
