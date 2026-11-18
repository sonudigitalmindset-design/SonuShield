package domains

// IP allow/block lists (Batch 5).
//
// Each domain may carry an allow list and a block list of IPs and
// CIDRs, with optional expiry (unix seconds, 0 = never) and a
// free-text note. Entries are managed through the API and the
// dashboard and persisted to config.json; no list is ever bundled
// with the proxy.
//
// Matching: a blocklisted IP is blocked before rate limiting
// runs; an allowlisted IP starts at susLv 0 and bypasses the
// early rate-limit and fingerprint blocks. The block list wins
// when an IP matches both. Expired entries are skipped by
// matching and pruned from the config on the next API write.
// Invalid entries (unparseable targets) are skipped with a
// warning at load time, so a typo can never lock a domain out or
// open it up.

import (
	"fmt"
	"net/netip"
	"time"
)

// IPListEntry is one allow/block list entry.
type IPListEntry struct {
	Target  string `json:"target"`
	Expires int64  `json:"expires"`
	Note    string `json:"note"`
}

// compiledIPEntry is a parsed, matchable list entry.
type compiledIPEntry struct {
	prefix  netip.Prefix
	expires int64
}

// parseIPTarget parses an entry target: a bare IP (treated as a
// /32 or /128) or a CIDR prefix.
func parseIPTarget(target string) (netip.Prefix, bool) {
	if addr, err := netip.ParseAddr(target); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Masked(), true
	}
	return netip.Prefix{}, false
}

// ValidateIPTarget reports whether target is a usable IP or CIDR.
func ValidateIPTarget(target string) bool {
	_, ok := parseIPTarget(target)
	return ok
}

// compileIPList parses entries into matchable prefixes, skipping
// expired entries silently and invalid ones with a warning.
func compileIPList(name, listName string, entries []IPListEntry) []compiledIPEntry {
	now := time.Now().Unix()
	var out []compiledIPEntry
	for _, entry := range entries {
		if entry.Expires != 0 && entry.Expires <= now {
			continue
		}
		prefix, ok := parseIPTarget(entry.Target)
		if !ok {
			fmt.Println("[ ! ] [ ignoring invalid " + listName + " entry for " + name + ": " + entry.Target + " ]")
			continue
		}
		out = append(out, compiledIPEntry{prefix: prefix, expires: entry.Expires})
	}
	return out
}

// RebuildIPLists recompiles a settings struct's lists from its
// raw entries. Called at load/reload (InitRuntime) and after API
// edits.
func (s *DomainSettings) RebuildIPLists() {
	s.IPAllowCompiled = compileIPList(s.Name, "ipAllowlist", s.IPAllowlist)
	s.IPBlockCompiled = compileIPList(s.Name, "ipBlocklist", s.IPBlocklist)
}

// IPListMatch reports whether ip is on the allow list, the block
// list, or neither. Unparseable IPs match nothing.
func (s DomainSettings) IPListMatch(ip string) (allow, block bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, false
	}
	now := time.Now().Unix()
	match := func(list []compiledIPEntry) bool {
		for _, entry := range list {
			if entry.expires != 0 && entry.expires <= now {
				continue
			}
			if entry.prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	return match(s.IPAllowCompiled), match(s.IPBlockCompiled)
}

// PruneExpiredIPEntries returns the entries that have not
// expired. Used by the API read/write paths so expired entries
// auto-drop.
func PruneExpiredIPEntries(entries []IPListEntry) []IPListEntry {
	now := time.Now().Unix()
	out := make([]IPListEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Expires != 0 && entry.Expires <= now {
			continue
		}
		out = append(out, entry)
	}
	return out
}
