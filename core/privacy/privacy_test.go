package privacy

import "testing"

func TestMaskIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":                            "203.0.113.0",
		"10.0.0.1":                               "10.0.0.0",
		"2001:db8:85a3:8d3:1319:8a2e:370:7348":    "2001:db8:85a3:8d3::",
		"2001:db8::1":                            "2001:db8::",
		"not-an-ip":                              "not-an-ip",
		"":                                       "",
		"203.0.113.0":                            "203.0.113.0", // already masked: stable
		"unknown":                                "unknown",
	}
	for in, want := range cases {
		if got := MaskIP(in); got != want {
			t.Fatalf("MaskIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskCounts(t *testing.T) {
	// Privacy mode off: the map passes through unchanged.
	Set(false)
	counts := map[string]int{"203.0.113.7": 3, "203.0.113.9": 4, "other": 1}
	if got := MaskCounts(counts); len(got) != 3 || got["203.0.113.7"] != 3 {
		t.Fatalf("privacy off: MaskCounts changed the map: %v", got)
	}

	// Privacy mode on: colliding keys sum, totals preserved.
	Set(true)
	defer Set(false)
	masked := MaskCounts(counts)
	if masked["203.0.113.0"] != 7 {
		t.Fatalf("masked counts = %v, want 203.0.113.0: 7", masked)
	}
	if masked["other"] != 1 {
		t.Fatalf("masked counts lost non-IP key: %v", masked)
	}
	total := 0
	for _, v := range masked {
		total += v
	}
	if total != 8 {
		t.Fatalf("masked total = %d, want 8", total)
	}
}
