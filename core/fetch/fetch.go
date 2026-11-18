package fetch

// SSRF guard for outbound fetches to public services
// (sale-readiness: M-5, L-3).
//
// Some proxy fetches take a URL from a less-trusted source
// (IMPORT_RULE_PACK takes a pack URL from an operator-role API
// caller) or from operator config for services that only ever
// live on the public internet (reputation feeds, the
// Cloudflare API, BGP data). A DialContext-level guard is the
// right layer: it applies to the initial request and to every
// redirect hop (each hop re-dials through the same Transport),
// and it dials the resolved IP it checked, so a DNS answer
// cannot change between the check and the connection
// (no rebinding race). TLS server-name verification is
// unaffected: Go's Transport derives the server name from the
// request URL, not from the dialed address.
//
// Deliberately NOT applied to: backend health probes, webhooks,
// JWKS/OIDC endpoints, and threat-sharing peers. Those
// legitimately live on private networks (private origins,
// internal alert receivers, private identity providers, peer
// proxies), and their URLs are operator-configured, so
// blocking private destinations there would break real setups
// without closing an attacker-reachable hole. See
// docs/security-audit.md.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// blockedPrefixes are the address ranges a guarded fetch must
// never connect to: RFC 1918, loopback, link-local, CGNAT
// shared space, documentation ranges, unspecified, and
// multicast, for both IPv4 and IPv6.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
		"127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "::ffff:0:0/96",
		"64:ff9b::/96", "100::/64", "2001::/32",
		"2001:2::/48", "2001:db8::/32", "2001:10::/28",
		"fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsPublicIP reports whether ip is a globally routable
// unicast address — i.e. outside every blocked prefix.
// Unparseable and non-IP inputs report false.
func IsPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return IsPublicAddr(addr)
}

// IsPublicAddr is IsPublicIP for netip.Addr values. IPv4-mapped
// IPv6 addresses are unmapped first so ::ffff:127.0.0.1 is
// correctly treated as loopback.
func IsPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return addr.IsGlobalUnicast()
}

// GuardedDialContext returns a DialContext that refuses to
// connect to non-public destinations. The host is resolved,
// every resolved address is checked, and the connection goes
// to a checked address, tried in order until one connects.
func GuardedDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	resolver := net.DefaultResolver
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := resolveAll(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("fetch: no address for %s", host)
		}
		for _, ip := range ips {
			if !IsPublicIP(ip) {
				return nil, fmt.Errorf("fetch: refusing non-public destination %s", host)
			}
		}
		var firstErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errors.New("fetch: connection failed")
	}
}

func resolveAll(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return resolver.LookupIP(ctx, "ip", host)
}
