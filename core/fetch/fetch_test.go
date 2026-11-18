package fetch

import (
	"net"
	"net/netip"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	public := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"2001:4860:4860::8888", "2606:4700:4700::1111",
	}
	for _, s := range public {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Fatalf("IsPublicIP(%s) = false, want true", s)
		}
		if !IsPublicAddr(netip.MustParseAddr(s)) {
			t.Fatalf("IsPublicAddr(%s) = false, want true", s)
		}
	}
	blocked := []string{
		"10.0.0.1", "172.16.0.5", "172.31.255.255", "192.168.1.1", // RFC 1918
		"127.0.0.1", "::1", // loopback
		"169.254.1.1", "fe80::1", // link-local
		"100.64.0.1", "100.127.255.255", // CGNAT
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", // documentation
		"224.0.0.1", "ff02::1", // multicast
		"0.0.0.0", "::", // unspecified
		"fc00::1", "fd00::1", // unique-local
		// Note: 192.88.99.0/24 (deprecated 6to4 relay anycast)
		// is globally routable, so the guard allows it.
	}
	for _, s := range blocked {
		if IsPublicIP(net.ParseIP(s)) {
			t.Fatalf("IsPublicIP(%s) = true, want false", s)
		}
		if IsPublicAddr(netip.MustParseAddr(s)) {
			t.Fatalf("IsPublicAddr(%s) = true, want false", s)
		}
	}
	if IsPublicIP(nil) {
		t.Fatal("IsPublicIP(nil) = true, want false")
	}
	if IsPublicIP(net.ParseIP("not-an-ip")) {
		t.Fatal("IsPublicIP(unparseable) = true, want false")
	}
}
