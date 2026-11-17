package reports

// Attack reports (Batch 2).
//
// Build assembles a point-in-time summary for one domain from copies
// of live state: totals, current and peak request rates, the attack
// window recorded in the request logger, stage and attack flags, and
// the action counters kept by the metrics package (blocks by reason,
// challenges by stage, WAF matches by rule, backend results and
// latency). It is pure: it never locks, never touches the network,
// and copies every slice it reads, so callers may pass live structs.
//
// The per-IP and per-fingerprint tallies are PROXY-WIDE, not
// per-domain: the firewall tracks AccessIps, AccessIpsCookie and
// UnkFps globally, and this package reports them honestly labelled
// as such instead of pretending they belong to one domain. Country
// and ASN enrichment uses the operator's GeoIP database when one is
// loaded and stays empty otherwise (fail-open). Country aggregates
// are computed over the listed top IPs only.
//
// Reports contain metadata only: IP addresses, fingerprint hashes,
// counts and rates. They never contain request bodies, cookies,
// headers, or secrets.

import (
	"sort"
	"strconv"
	"time"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/metrics"
)

// DefaultTop is the number of top entries listed when the caller
// does not ask for a different amount. MaxTop bounds the work a
// single report (and its GeoIP lookups) can do.
const (
	DefaultTop = 10
	MaxTop     = 50
)

// IPEntry is one IP from the firewall tallies with its request count
// and, when a GeoIP database is loaded, its country and ASN.
type IPEntry struct {
	IP       string `json:"ip"`
	Requests int    `json:"requests"`
	Country  string `json:"country,omitempty"`
	ASN      int    `json:"asn,omitempty"`
}

// CountEntry is one ranked key/count pair, used for fingerprints
// and country aggregates.
type CountEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Report is the JSON form of an attack summary. The CSV form
// (ToCSV) renders the same data as a single flat table.
type Report struct {
	Domain      string    `json:"domain"`
	GeneratedAt time.Time `json:"generated_at"`

	WindowStart   *time.Time `json:"window_start,omitempty"`
	WindowEnd     *time.Time `json:"window_end,omitempty"`
	WindowSeconds int        `json:"window_seconds"`

	Stage            int  `json:"stage"`
	StageManuallySet bool `json:"stage_manually_set"`
	RawAttack        bool `json:"raw_attack"`
	BypassAttack     bool `json:"bypass_attack"`

	TotalRequests            int `json:"total_requests"`
	BypassedRequests         int `json:"bypassed_requests"`
	RequestsPerSecond        int `json:"requests_per_second"`
	BypassedPerSecond        int `json:"bypassed_per_second"`
	PeakRequestsPerSecond    int `json:"peak_requests_per_second"`
	PeakBypassedPerSecond    int `json:"peak_bypassed_per_second"`
	CooldownRemainingSeconds int `json:"cooldown_remaining_seconds"`

	BlocksByReason       map[string]int64 `json:"blocks_by_reason"`
	ChallengesByStage    map[string]int64 `json:"challenges_by_stage"`
	WAFMatchesByRule     map[string]int64 `json:"waf_matches_by_rule"`
	BackendRequestsOK    int64            `json:"backend_requests_ok"`
	BackendRequestsError int64            `json:"backend_requests_failed"`
	BackendLatencyAvg    *float64         `json:"backend_latency_avg_seconds,omitempty"`

	TopLimit               int          `json:"top_limit"`
	TopVerifiedIPs         []IPEntry    `json:"top_verified_ips_proxy_wide"`
	TopUnverifiedIPs       []IPEntry    `json:"top_unverified_ips_proxy_wide"`
	TopUnknownFingerprints []CountEntry `json:"top_unknown_fingerprints_proxy_wide"`
	Countries              []CountEntry `json:"countries_proxy_wide"`
}

// CopyTallies copies the firewall's global IP and fingerprint
// tallies under a read lock. Callers running under the firewall
// write lock (checkAttack) must NOT call this synchronously: the
// lock is not reentrant. Use ExportOnAttackEnd, which copies from a
// goroutine after the lock is released.
func CopyTallies() (verified, unverified, fingerprints map[string]int) {
	firewall.Mutex.RLock()
	defer firewall.Mutex.RUnlock()
	return copyCounts(firewall.AccessIps), copyCounts(firewall.AccessIpsCookie), copyCounts(firewall.UnkFps)
}

func copyCounts(src map[string]int) map[string]int {
	dst := make(map[string]int, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// Build assembles a report from copied inputs. The top argument is
// clamped to 1..MaxTop; values outside that range fall back to
// DefaultTop.
func Build(domain string, data domains.DomainData, snap metrics.Snapshot, verified, unverified, fingerprints map[string]int, top int) Report {
	if top < 1 || top > MaxTop {
		top = DefaultTop
	}

	// Copy the logger: the backing array is shared with live state
	// and may be appended to concurrently.
	logger := append([]domains.RequestLog(nil), data.RequestLogger...)

	report := Report{
		Domain:                   domain,
		GeneratedAt:              time.Now().UTC(),
		Stage:                    data.Stage,
		StageManuallySet:         data.StageManuallySet,
		RawAttack:                data.RawAttack,
		BypassAttack:             data.BypassAttack,
		TotalRequests:            data.TotalRequests,
		BypassedRequests:         data.BypassedRequests,
		RequestsPerSecond:        data.RequestsPerSecond,
		BypassedPerSecond:        data.RequestsBypassedPerSecond,
		PeakRequestsPerSecond:    data.PeakRequestsPerSecond,
		PeakBypassedPerSecond:    data.PeakRequestsBypassedPerSecond,
		CooldownRemainingSeconds: data.BufferCooldown,
		BlocksByReason:           snap.Blocks,
		ChallengesByStage:        challengesByStage(snap.Challenges),
		WAFMatchesByRule:         snap.WAFMatches,
		BackendRequestsOK:        snap.BackendOK,
		BackendRequestsError:     snap.BackendErr,
		TopLimit:                 top,
	}

	if len(logger) > 0 {
		start := logger[0].Time.UTC()
		end := logger[len(logger)-1].Time.UTC()
		report.WindowStart = &start
		report.WindowEnd = &end
		seconds := int(end.Sub(start).Seconds())
		if seconds < 0 {
			seconds = 0
		}
		report.WindowSeconds = seconds
	}

	if snap.LatencyCount > 0 {
		avg := snap.LatencySum / float64(snap.LatencyCount)
		report.BackendLatencyAvg = &avg
	}

	report.TopVerifiedIPs = topIPs(verified, top)
	report.TopUnverifiedIPs = topIPs(unverified, top)
	report.TopUnknownFingerprints = topCounts(fingerprints, top)
	report.Countries = countriesOf(report.TopVerifiedIPs, report.TopUnverifiedIPs)
	return report
}

func challengesByStage(in map[int]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for stage, count := range in {
		out["stage_"+strconv.Itoa(stage)] = count
	}
	return out
}

// topCounts ranks a tally map by count (highest first, key order
// breaks ties for stable output) and returns at most top entries.
func topCounts(tally map[string]int, top int) []CountEntry {
	entries := make([]CountEntry, 0, len(tally))
	for key, count := range tally {
		entries = append(entries, CountEntry{Key: key, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Key < entries[j].Key
	})
	if len(entries) > top {
		entries = entries[:top]
	}
	if entries == nil {
		entries = []CountEntry{}
	}
	return entries
}

// topIPs ranks an IP tally like topCounts and enriches each listed
// IP with its country and ASN when a GeoIP database is loaded.
func topIPs(tally map[string]int, top int) []IPEntry {
	ranked := topCounts(tally, top)
	entries := make([]IPEntry, 0, len(ranked))
	for _, item := range ranked {
		entry := IPEntry{IP: item.Key, Requests: item.Count}
		entry.Country, entry.ASN = firewall.LookupGeo(item.Key)
		entries = append(entries, entry)
	}
	if entries == nil {
		entries = []IPEntry{}
	}
	return entries
}

// countriesOf aggregates request counts per country over the listed
// top IPs. IPs without a known country count as "unknown", so the
// aggregate always covers every listed IP.
func countriesOf(lists ...[]IPEntry) []CountEntry {
	tally := map[string]int{}
	for _, list := range lists {
		for _, entry := range list {
			country := entry.Country
			if country == "" {
				country = "unknown"
			}
			tally[country] += entry.Requests
		}
	}
	return topCounts(tally, len(tally))
}
