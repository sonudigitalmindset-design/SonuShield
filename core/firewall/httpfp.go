package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// SonuShield HTTP request fingerprint.
//
// This is SonuShield's own format. It is deliberately NOT JA4H: JA4H is part
// of the FoxIO JA4+ suite under the FoxIO License 1.1 (commercial use
// requires an OEM licence), and a spec-compliant JA4H also needs the original
// header transmission order, which Go's net/http does not preserve (headers
// arrive as a map). This fingerprint therefore uses sorted header names, so
// it is stable and comparable within SonuShield, and it uses its own "sh1"
// prefix so it can never be mistaken for a JA4H value.
//
// Format: sh1_<a>_<b>_<c>_<d>
//
//	a = method (first 2 chars, lowercase) + HTTP version (2 digits) +
//	    cookie present (c/n) + referer present (r/n) + header count
//	    excluding Cookie/Referer (2 digits) + Accept-Language tag
//	    (first 4 chars, hyphen stripped, zero-padded)
//	b = truncated SHA-256 (12 hex chars) of the sorted, comma-joined,
//	    lowercase header names, excluding Cookie and Referer.
//	c = truncated SHA-256 (12 hex chars) of the sorted, comma-joined
//	    cookie names. Cookie VALUES are never included.
//	d = truncated SHA-256 (12 hex chars) of the joined, normalised
//	    client-preference signals (Batch 5): the sorted
//	    Accept-Encoding tokens (q-values stripped), the full
//	    Accept-Language value (q-values stripped, lowercased,
//	    order preserved), the Upgrade-Insecure-Requests value,
//	    and the Sec-Fetch-Site and Sec-Fetch-Mode values. These
//	    are stable per client configuration, carry no identity,
//	    and are hashed so no raw header value is stored.
//
// Section d was added in Batch 5: fingerprints computed by this
// version are NOT comparable with pre-Batch-5 sh1 values, which
// had only three sections. Within one version the value is stable
// for the same client and request shape.
//
// Empty sections render as twelve zeros, mirroring the JA4 convention for
// missing data. The fingerprint is exposed to firewall rules as
// "http.fingerprint" and shown on /_bProxy/fingerprint. It is a weak,
// easily spoofed signal on its own; use it for clustering and as one input
// among others, never as the sole basis for blocking legitimate traffic.
func ComputeHTTPFingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}

	method := strings.ToLower(r.Method)
	if len(method) >= 2 {
		method = method[:2]
	} else if len(method) == 1 {
		method = method + "0"
	} else {
		method = "00"
	}

	version := fmt.Sprintf("%d%d", r.ProtoMajor, r.ProtoMinor)

	cookieFlag := "n"
	if r.Header.Get("Cookie") != "" {
		cookieFlag = "c"
	}
	refererFlag := "n"
	if r.Header.Get("Referer") != "" {
		refererFlag = "r"
	}

	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		lower := strings.ToLower(name)
		if lower == "cookie" || lower == "referer" {
			continue
		}
		names = append(names, lower)
	}
	sort.Strings(names)
	headerCount := len(names)
	if headerCount > 99 {
		headerCount = 99
	}

	lang := "0000"
	if al := r.Header.Get("Accept-Language"); al != "" {
		// Primary language tag only: before the first comma or semicolon,
		// hyphen/space stripped, lowercased, first 4 chars, zero-padded.
		if idx := strings.IndexAny(al, ",;"); idx >= 0 {
			al = al[:idx]
		}
		al = strings.ReplaceAll(al, "-", "")
		al = strings.ReplaceAll(al, " ", "")
		al = strings.ToLower(al)
		if len(al) > 4 {
			al = al[:4]
		}
		for len(al) < 4 {
			al += "0"
		}
		if al != "" {
			lang = al
		}
	}

	a := fmt.Sprintf("%s%s%s%s%02d%s", method, version, cookieFlag, refererFlag, headerCount, lang)

	b := "000000000000"
	if len(names) > 0 {
		sum := sha256.Sum256([]byte(strings.Join(names, ",")))
		b = hex.EncodeToString(sum[:])[:12]
	}

	c := "000000000000"
	cookieNames := make([]string, 0, len(r.Cookies()))
	for _, cookie := range r.Cookies() {
		cookieNames = append(cookieNames, cookie.Name)
	}
	if len(cookieNames) > 0 {
		sort.Strings(cookieNames)
		sum := sha256.Sum256([]byte(strings.Join(cookieNames, ",")))
		c = hex.EncodeToString(sum[:])[:12]
	}

	// Section d: client-preference signals. Every part is
	// normalised (q-values stripped, lowercased, trimmed) so the
	// same client produces the same value across requests.
	// Accept-Encoding tokens are sorted because their order
	// carries no preference; Accept-Language keeps its order
	// because it does.
	d := "000000000000"
	dParts := []string{
		normaliseEncodingList(r.Header.Get("Accept-Encoding")),
		normaliseLanguageList(r.Header.Get("Accept-Language")),
		strings.ToLower(strings.TrimSpace(r.Header.Get("Upgrade-Insecure-Requests"))),
		strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))),
		strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode"))),
	}
	if strings.Join(dParts, "") != "" {
		sum := sha256.Sum256([]byte(strings.Join(dParts, "|")))
		d = hex.EncodeToString(sum[:])[:12]
	}

	return "sh1_" + a + "_" + b + "_" + c + "_" + d
}

// normaliseEncodingList sorts Accept-Encoding tokens and strips
// q-values: "gzip, deflate, br;q=0.9" and "br, gzip, deflate"
// normalise to the same string.
func normaliseEncodingList(value string) string {
	if value == "" {
		return ""
	}
	tokens := make([]string, 0, 4)
	for _, token := range strings.Split(value, ",") {
		if idx := strings.IndexByte(token, ';'); idx >= 0 {
			token = token[:idx]
		}
		token = strings.ToLower(strings.TrimSpace(token))
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	sort.Strings(tokens)
	return strings.Join(tokens, ",")
}

// normaliseLanguageList strips q-values and lowercases an
// Accept-Language value, preserving tag order:
// "en-US,en;q=0.9,hi;q=0.8" becomes "en-us,en,hi".
func normaliseLanguageList(value string) string {
	if value == "" {
		return ""
	}
	tags := make([]string, 0, 4)
	for _, tag := range strings.Split(value, ",") {
		if idx := strings.IndexByte(tag, ';'); idx >= 0 {
			tag = tag[:idx]
		}
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return strings.Join(tags, ",")
}
