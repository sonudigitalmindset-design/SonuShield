package firewall

// Search-engine bot verification (Batch 4).
//
// A user-agent that claims to be Googlebot or Bingbot is easy to
// fake, and bot impersonation is a common way to slip past
// bot-allow rules. When the operator enables fakeBotCheck, a
// claimed search bot is verified the way Google and Microsoft
// document: reverse DNS on the client IP must resolve to a
// hostname in the crawler's domain, and forward DNS on that
// hostname must resolve back to the client IP.
//
// Outcomes, exposed to firewall rules as "ip.searchbot":
//
//	""          the user-agent claims no known search bot.
//	"verified"  reverse + forward DNS both confirm the claim.
//	"fake"      DNS answered but the claim does not hold: the
//	            reverse name is outside the crawler's domain, or
//	            the forward lookup does not contain the IP.
//	"unchecked" DNS failed or timed out. This FAILS OPEN: no
//	            suspicion is added, because a DNS outage must
//	            never punish legitimate crawlers (or visitors).
//
// Verification runs only when fakeBotCheck is enabled for the
// domain and the user-agent claims a bot, and results are cached
// per IP + bot name (1 hour for verified/fake, 5 minutes for
// unchecked) so DNS lookups never happen on every request. The
// lookup timeout is 2 seconds per direction. A "fake" result adds
// the configured fakeBotSusLv (default 3) to the suspicion level.

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type botClaim struct {
	token    string
	suffixes []string
}

var searchBotClaims = []botClaim{
	{"googlebot", []string{".googlebot.com", ".google.com"}},
	{"bingbot", []string{".search.msn.com"}},
}

const (
	searchBotLookupTimeout = 2 * time.Second
	searchBotCacheTTL      = time.Hour
	searchBotUncheckedTTL  = 5 * time.Minute
	searchBotCacheMax      = 10000
)

// Resolver indirection, so tests can substitute a fake DNS without
// touching the network. Production code uses the default resolver.
var (
	searchBotLookupAddr = func(ctx context.Context, ip string) ([]string, error) {
		return net.DefaultResolver.LookupAddr(ctx, ip)
	}
	searchBotLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
)

type searchBotCacheEntry struct {
	result  string
	expires time.Time
}

var searchBotCache = struct {
	sync.Mutex
	entries map[string]searchBotCacheEntry
}{entries: map[string]searchBotCacheEntry{}}

// claimedBot returns the bot claim in a user-agent, or nil when the
// agent claims no known search bot.
func claimedBot(userAgent string) *botClaim {
	lower := strings.ToLower(userAgent)
	for i := range searchBotClaims {
		if strings.Contains(lower, searchBotClaims[i].token) {
			return &searchBotClaims[i]
		}
	}
	return nil
}

// ClassifySearchBot verifies a claimed search bot. It returns "",
// "verified", "fake", or "unchecked" as documented above.
func ClassifySearchBot(ip, userAgent string) string {
	claim := claimedBot(userAgent)
	if claim == nil || ip == "" {
		return ""
	}

	key := ip + "|" + claim.token
	now := time.Now()

	searchBotCache.Lock()
	if entry, ok := searchBotCache.entries[key]; ok && now.Before(entry.expires) {
		searchBotCache.Unlock()
		return entry.result
	}
	searchBotCache.Unlock()

	result := verifySearchBot(ip, claim)

	ttl := searchBotCacheTTL
	if result == "unchecked" {
		ttl = searchBotUncheckedTTL
	}
	searchBotCache.Lock()
	if len(searchBotCache.entries) >= searchBotCacheMax {
		for k, e := range searchBotCache.entries {
			if now.After(e.expires) {
				delete(searchBotCache.entries, k)
			}
		}
	}
	searchBotCache.entries[key] = searchBotCacheEntry{result: result, expires: now.Add(ttl)}
	searchBotCache.Unlock()

	return result
}

func verifySearchBot(ip string, claim *botClaim) string {
	ctx, cancel := context.WithTimeout(context.Background(), searchBotLookupTimeout)
	defer cancel()
	names, err := searchBotLookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "unchecked"
	}

	matched := ""
	for _, name := range names {
		trimmed := strings.TrimSuffix(strings.ToLower(name), ".")
		for _, suffix := range claim.suffixes {
			if strings.HasSuffix(trimmed, suffix) {
				matched = trimmed
				break
			}
		}
		if matched != "" {
			break
		}
	}
	if matched == "" {
		return "fake"
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), searchBotLookupTimeout)
	defer cancel2()
	addrs, err := searchBotLookupHost(ctx2, matched)
	if err != nil {
		return "unchecked"
	}
	for _, addr := range addrs {
		if addr == ip {
			return "verified"
		}
	}
	return "fake"
}

// FakeBotBump returns the suspicion bump for a fake-bot result: the
// configured value, or 3 when the operator enabled the check but
// set no (or a non-positive) bump.
func FakeBotBump(configured int) int {
	if configured <= 0 {
		return 3
	}
	return configured
}
