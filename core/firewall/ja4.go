package firewall

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4 (TLS client fingerprinting) support.
//
// Specification: FoxIO JA4, https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
// (JA4 itself is BSD 3-Clause licensed; see that repository.)
//
// Format: t<version><sni><ciphers><extensions><alpn>_<cipher hash>_<extension+sigalg hash>
// Example from the specification:
//	t13d1516h2_8daaf6152771_e5627efa2ab1
//
// IMPORTANT LIMITATION — READ BEFORE COMPARING WITH EXTERNAL JA4 DATABASES:
// Go's crypto/tls does not expose the raw ClientHello or the full ordered
// extension list to GetConfigForClient; tls.ClientHelloInfo only exposes
// cipher suites, supported curves/points, signature schemes, ALPN values and
// supported versions. ComputeJA4 therefore approximates the extension list
// from those exposed fields (SNI, ALPN, supported_versions, supported_groups,
// ec_point_formats, signature_algorithms). The cipher hash and the overall
// structure follow the specification exactly, but the extension count and
// extension hash will NOT match a JA4 value computed from the raw packet by
// an external tool. Use SonuShield JA4 values for clustering and firewall
// rules within SonuShield only; do not expect them to match entries in
// external JA4 databases (e.g. ja4db). A raw-ClientHello implementation is
// future work and would require intercepting the handshake before crypto/tls
// parses it.
//
// The legacy SonuShield/balooProxy fingerprint (see Fingerprint in
// fingerprint.go) is unchanged and remains the primary classification signal;
// JA4 is computed alongside it and only fills in when the legacy fingerprint
// is unknown. JA4 lists start empty (see global/fingerprints/ja4_*.json) and
// must be populated by the operator from values observed on their own proxy
// (/_bProxy/fingerprint shows the JA4 of the current connection). No JA4
// values are invented or bundled.

// JA4Parts is the decomposed input to a JA4 fingerprint. It exists so the
// hashing logic can be tested directly against the specification's worked
// examples, independent of what Go's TLS stack exposes.
type JA4Parts struct {
	// HighestVersion is the highest TLS version offered (e.g. 0x0304).
	// Zero means unknown and renders as "00" per the specification.
	HighestVersion uint16
	// HasSNI reports whether the SNI extension (0x0000) was present.
	HasSNI bool
	// Ciphers are the offered cipher suites, in client order, GREASE included
	// (filtering happens inside ComputeJA4FromParts).
	Ciphers []uint16
	// Extensions are the offered extension IDs, GREASE included. SNI and
	// ALPN must be included here: they count towards the extension count
	// even though they are excluded from the extension hash.
	Extensions []uint16
	// FirstALPN is the first ALPN value offered, if any.
	FirstALPN string
	// HasALPN reports whether any ALPN value was offered.
	HasALPN bool
	// SigAlgs are the signature algorithms, in the order the client sent
	// them (order is significant and is preserved, per the specification).
	SigAlgs []uint16
}

// isGREASE reports whether v is a GREASE value (RFC 8701): 0x0a0a, 0x1a1a,
// ..., 0xfafa. GREASE values are ignored everywhere in JA4.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func isAlphanumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// ja4ALPN renders the ALPN part of the JA4 "a" section: the first and last
// alphanumeric characters of the first ALPN value, "00" when there is none,
// the single character doubled for a one-character value, and the first/last
// characters of the hex representation when the first or last byte is not
// alphanumeric (all per the specification).
func ja4ALPN(value string, has bool) string {
	if !has || value == "" {
		return "00"
	}
	first, last := value[0], value[len(value)-1]
	if len(value) == 1 {
		if isAlphanumeric(first) {
			return string([]byte{first, first})
		}
		hexed := hex.EncodeToString([]byte{first})
		return string([]byte{hexed[0], hexed[len(hexed)-1]})
	}
	if isAlphanumeric(first) && isAlphanumeric(last) {
		return string([]byte{first, last})
	}
	hexed := hex.EncodeToString([]byte(value))
	return string([]byte{hexed[0], hexed[len(hexed)-1]})
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func hexList(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// ComputeJA4FromParts builds a JA4 fingerprint from decomposed ClientHello
// data, following the FoxIO specification exactly for the data it is given.
func ComputeJA4FromParts(p JA4Parts) string {
	ciphers := filterGREASE(p.Ciphers)
	extensions := filterGREASE(p.Extensions)

	// Cipher count and extension count, zero-padded to 2 characters,
	// capped at 99.
	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}
	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	sni := "i"
	if p.HasSNI {
		sni = "d"
	}

	a := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(p.HighestVersion), sni, cipherCount, extCount, ja4ALPN(p.FirstALPN, p.HasALPN))

	// Section b: truncated SHA-256 of the sorted cipher list.
	b := "000000000000"
	if len(ciphers) > 0 {
		sorted := append([]uint16(nil), ciphers...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		b = hash12(hexList(sorted))
	}

	// Section c: truncated SHA-256 of the sorted extension list (SNI and
	// ALPN removed) followed by "_" and the signature algorithms in
	// original order. Empty extension list renders as all zeros.
	c := "000000000000"
	extForHash := make([]uint16, 0, len(extensions))
	for _, e := range extensions {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extForHash = append(extForHash, e)
	}
	if len(extForHash) > 0 {
		sort.Slice(extForHash, func(i, j int) bool { return extForHash[i] < extForHash[j] })
		s := hexList(extForHash)
		sigAlgs := filterGREASE(p.SigAlgs)
		if len(sigAlgs) > 0 {
			s += "_" + hexList(sigAlgs)
		}
		c = hash12(s)
	}

	return a + "_" + b + "_" + c
}

// ComputeJA4 builds a JA4 fingerprint from a tls.ClientHelloInfo. See the
// package-level limitation note at the top of this file: the extension list
// is approximated from the fields Go exposes, so the result is only
// comparable with other SonuShield-computed values.
func ComputeJA4(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}

	var highest uint16
	for _, v := range hello.SupportedVersions {
		if isGREASE(v) {
			continue
		}
		if v > highest {
			highest = v
		}
	}

	// Approximated extension list from the fields Go exposes. Extension IDs
	// are the IANA TLS extension type values:
	//	0x0000 server_name, 0x0010 application_layer_protocol_negotiation,
	//	0x002b supported_versions, 0x000a supported_groups,
	//	0x000b ec_point_formats, 0x000d signature_algorithms.
	extensions := make([]uint16, 0, 6)
	if hello.ServerName != "" {
		extensions = append(extensions, 0x0000)
	}
	if len(hello.SupportedProtos) > 0 {
		extensions = append(extensions, 0x0010)
	}
	if len(hello.SupportedVersions) > 0 {
		extensions = append(extensions, 0x002b)
	}
	if len(hello.SupportedCurves) > 0 {
		extensions = append(extensions, 0x000a)
	}
	if len(hello.SupportedPoints) > 0 {
		extensions = append(extensions, 0x000b)
	}
	if len(hello.SignatureSchemes) > 0 {
		extensions = append(extensions, 0x000d)
	}

	sigAlgs := make([]uint16, len(hello.SignatureSchemes))
	for i, s := range hello.SignatureSchemes {
		sigAlgs[i] = uint16(s)
	}

	firstALPN := ""
	if len(hello.SupportedProtos) > 0 {
		firstALPN = hello.SupportedProtos[0]
	}

	return ComputeJA4FromParts(JA4Parts{
		HighestVersion: highest,
		HasSNI:         hello.ServerName != "",
		Ciphers:        hello.CipherSuites,
		Extensions:     extensions,
		FirstALPN:      firstALPN,
		HasALPN:        len(hello.SupportedProtos) > 0,
		SigAlgs:        sigAlgs,
	})
}
