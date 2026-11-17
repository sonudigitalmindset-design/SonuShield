package firewall

// IP reputation: a local blocklist plus an optional external feed.
//
// The operator configures exact IPs and CIDRs in config.json
// (reputationBlocklist) and/or a feed URL (reputationFeedURL) serving a
// plain-text list, one IP or CIDR per line, with "#" comments. No list is
// bundled and no feed is contacted unless configured: there are no
// invented blocklists.
//
// A listed IP gets its suspicion level bumped (reputationSusLv, default
// 1) after firewall rules are evaluated, and firewall rules can match on
// the ip.reputation field ("listed" or ""). Feed failures never block
// anyone: the last good feed data is kept (fail-open) and a warning is
// logged. The feed is refreshed in the background; startup never blocks
// on it.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type reputationSet struct {
	ips  map[string]bool
	nets []*net.IPNet
}

type reputationFeedConfig struct {
	url      string
	interval time.Duration
}

var (
	localReputation atomic.Pointer[reputationSet]
	feedReputation  atomic.Pointer[reputationSet]
	feedConfig      atomic.Pointer[reputationFeedConfig]
	reputationBump  atomic.Int32

	feedMu      sync.Mutex
	feedRunning bool

	// Last feed fetch outcome, for operator-facing status output.
	feedStatusMu    sync.Mutex
	feedLastSuccess time.Time
	feedLastError   string

	// Guards manually triggered refreshes so repeated requests do not
	// stampede the feed URL. The background loop is unaffected.
	feedRefreshMu sync.Mutex
)

func emptyReputationSet() *reputationSet {
	return &reputationSet{ips: map[string]bool{}}
}

func parseReputationList(entries []string) *reputationSet {
	set := emptyReputationSet()
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		// Take the first field so "1.2.3.4 # comment" works.
		if fields := strings.Fields(entry); len(fields) > 0 {
			entry = fields[0]
		}
		if ip := net.ParseIP(entry); ip != nil {
			set.ips[ip.String()] = true
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			set.nets = append(set.nets, network)
			continue
		}
		fmt.Println("[ ! ] [ Ignoring invalid reputation entry: " + entry + " ]")
	}
	return set
}

func (set *reputationSet) contains(ip net.IP) bool {
	if set == nil || ip == nil {
		return false
	}
	if set.ips[ip.String()] {
		return true
	}
	for _, network := range set.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// InitReputation installs the local blocklist and the feed configuration,
// starting the background feed refresher when a feed URL is set. It is
// safe to call on every config reload: the refresher is started at most
// once, and a reload never discards feed data fetched earlier.
func InitReputation(local []string, feedURL string, intervalMinutes, bump int) {
	localReputation.Store(parseReputationList(local))

	if bump <= 0 {
		bump = 1
	}
	reputationBump.Store(int32(bump))

	interval := time.Duration(intervalMinutes) * time.Minute
	if interval < 5*time.Minute {
		interval = 5 * time.Minute
	}
	if intervalMinutes <= 0 {
		interval = 60 * time.Minute
	}
	feedConfig.Store(&reputationFeedConfig{url: feedURL, interval: interval})

	feedMu.Lock()
	if feedURL != "" && !feedRunning {
		feedRunning = true
		go refreshReputationFeedLoop()
	}
	feedMu.Unlock()
}

// ReputationBump returns the configured suspicion-level bump for listed
// IPs (default 1).
func ReputationBump() int {
	bump := int(reputationBump.Load())
	if bump <= 0 {
		return 1
	}
	return bump
}

// LookupReputation reports whether an IP is on the local blocklist or the
// fetched feed. Unparseable addresses return false.
func LookupReputation(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if localReputation.Load().contains(ip) {
		return true
	}
	return feedReputation.Load().contains(ip)
}

// ReputationStatus describes the configured feed, the sizes of the
// loaded sets, and the last fetch outcome. Counts are 0 when nothing
// is loaded; lastSuccessUnix is 0 when the feed has never loaded
// successfully; lastError is "" when the last fetch succeeded or no
// fetch has been attempted.
func ReputationStatus() (feedConfigured bool, feedIntervalMinutes int, localIPs, localNetworks, feedIPs, feedNetworks int, bump int, lastSuccessUnix int64, lastError string) {
	if cfg := feedConfig.Load(); cfg != nil {
		feedConfigured = cfg.url != ""
		feedIntervalMinutes = int(cfg.interval / time.Minute)
	}
	if set := localReputation.Load(); set != nil {
		localIPs = len(set.ips)
		localNetworks = len(set.nets)
	}
	if set := feedReputation.Load(); set != nil {
		feedIPs = len(set.ips)
		feedNetworks = len(set.nets)
	}
	bump = ReputationBump()
	feedStatusMu.Lock()
	lastSuccessUnix = feedLastSuccess.Unix()
	lastError = feedLastError
	feedStatusMu.Unlock()
	if len(lastError) > 200 {
		lastError = lastError[:200]
	}
	return
}

// RefreshReputationFeedAsync triggers a feed refresh in the background
// and reports whether one was started: false when no feed is
// configured or a manually triggered refresh is already running. The
// refresh itself is fail-open, exactly like the background loop.
func RefreshReputationFeedAsync() bool {
	cfg := feedConfig.Load()
	if cfg == nil || cfg.url == "" {
		return false
	}
	if !feedRefreshMu.TryLock() {
		return false
	}
	go func() {
		defer feedRefreshMu.Unlock()
		refreshReputationFeed()
	}()
	return true
}

// recordFeedResult stores the outcome of a feed fetch for status
// output. An empty message means success.
func recordFeedResult(errMsg string) {
	feedStatusMu.Lock()
	defer feedStatusMu.Unlock()
	if errMsg == "" {
		feedLastSuccess = time.Now()
		feedLastError = ""
	} else {
		feedLastError = errMsg
	}
}

func refreshReputationFeedLoop() {
	for {
		refreshReputationFeed()
		interval := 60 * time.Minute
		if cfg := feedConfig.Load(); cfg != nil && cfg.interval > 0 {
			interval = cfg.interval
		}
		time.Sleep(interval)
	}
}

func refreshReputationFeed() {
	cfg := feedConfig.Load()
	if cfg == nil || cfg.url == "" {
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(cfg.url)
	if err != nil {
		fmt.Println("[ ! ] [ Reputation feed fetch failed, keeping previous data: " + err.Error() + " ]")
		recordFeedResult("fetch failed: " + err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("[ ! ] [ Reputation feed returned status " + resp.Status + ", keeping previous data ]")
		recordFeedResult("feed returned status " + resp.Status)
		return
	}

	// Bound the feed size so a runaway feed cannot exhaust memory.
	const maxFeedBytes = 10 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		fmt.Println("[ ! ] [ Reputation feed read failed, keeping previous data: " + err.Error() + " ]")
		recordFeedResult("read failed: " + err.Error())
		return
	}
	if len(body) > maxFeedBytes {
		fmt.Println("[ ! ] [ Reputation feed exceeds 10 MB, keeping previous data ]")
		recordFeedResult("feed exceeds 10 MB")
		return
	}

	set := parseReputationList(strings.Split(string(body), "\n"))
	feedReputation.Store(set)
	recordFeedResult("")
	fmt.Println("[ + ] [ Reputation feed loaded: " + fmt.Sprint(len(set.ips)) + " IPs, " + fmt.Sprint(len(set.nets)) + " networks ]")
}
