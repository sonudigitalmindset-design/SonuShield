package metrics

// Prometheus metrics for SonuShield (Batch 2).
//
// What is exposed: per-domain request totals, requests per second,
// peaks, stage, and attack flags (read from the existing domain
// statistics); block and challenge counters by reason and stage;
// WAF-lite match counters by rule; backend request counts and a
// latency histogram; proxy CPU/RAM gauges; and the number of tracked
// IPs and unknown fingerprints. Fingerprint and IP values are never
// used as label values: only aggregate counts are exposed, so metric
// cardinality stays bounded no matter how many clients connect.
//
// Access control: the endpoint is DISABLED by default and must be
// enabled with proxy.metricsEnabled in config.json. When enabled it
// is served only on the exact admin-secret path
// /_bProxy/<adminsecret>/metrics, the same gating as the dashboard
// and the v1 API — the URL itself must be treated like a credential.
// The handler runs before any challenge or rate limiting, so scrapes
// are neither challenged nor counted in request statistics. When
// disabled, requests to the path fall through to the normal flow
// exactly as before. No new /admin or /user path is introduced, and
// nothing visitor-visible changes: the endpoint answers only on the
// secret path.
//
// The exposition format is written by hand (no client library) and
// follows the Prometheus text format version 0.0.4: HELP and TYPE
// lines, label escaping, and cumulative histogram buckets.

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/proxy"
)

// latencyBuckets are the histogram upper bounds in seconds. The +Inf
// bucket is implicit: every observation lands in it.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type domainCounters struct {
	blocks     map[string]int64 // reason -> count
	challenges map[int]int64    // stage -> count
	wafMatches map[string]int64 // rule name -> count
	backendOK  int64
	backendErr int64
	latencySum float64
	latencyObs []int64 // per-bucket observations, len(latencyBuckets)+1 (+Inf last)
}

var (
	mu       sync.Mutex
	counters = map[string]*domainCounters{}
)

func forDomainLocked(domain string) *domainCounters {
	c, ok := counters[domain]
	if !ok {
		c = &domainCounters{
			blocks:     map[string]int64{},
			challenges: map[int]int64{},
			wafMatches: map[string]int64{},
			latencyObs: make([]int64, len(latencyBuckets)+1),
		}
		counters[domain] = c
	}
	return c
}

// ObserveBlock records a blocked request under a fixed reason label:
// "ratelimit", "fingerprint", "waf", or "suspect".
func ObserveBlock(domain, reason string) {
	mu.Lock()
	forDomainLocked(domain).blocks[reason]++
	mu.Unlock()
}

// ObserveChallenge records a served challenge for a stage (1, 2, or 3).
func ObserveChallenge(domain string, stage int) {
	mu.Lock()
	forDomainLocked(domain).challenges[stage]++
	mu.Unlock()
}

// ObserveWAFMatch records a WAF-lite match under its rule name. Rule
// names come from a fixed built-in list, so label cardinality is
// bounded.
func ObserveWAFMatch(domain, rule string) {
	mu.Lock()
	forDomainLocked(domain).wafMatches[rule]++
	mu.Unlock()
}

// ObserveBackend records one backend round trip: its latency and
// whether the transport returned an error.
func ObserveBackend(domain string, duration time.Duration, ok bool) {
	seconds := duration.Seconds()
	mu.Lock()
	c := forDomainLocked(domain)
	if ok {
		c.backendOK++
	} else {
		c.backendErr++
	}
	c.latencySum += seconds
	placed := false
	for i, bound := range latencyBuckets {
		if seconds <= bound {
			c.latencyObs[i]++
			placed = true
			break
		}
	}
	if !placed {
		c.latencyObs[len(latencyBuckets)]++
	}
	mu.Unlock()
}

// Snapshot is a copy of one domain's counters, for attack reports.
type Snapshot struct {
	Blocks       map[string]int64
	Challenges   map[int]int64
	WAFMatches   map[string]int64
	BackendOK    int64
	BackendErr   int64
	LatencyCount int64
	LatencySum   float64
}

// SnapshotFor returns a copy of the counters for one domain. Missing
// domains yield empty (non-nil) maps.
func SnapshotFor(domain string) Snapshot {
	mu.Lock()
	defer mu.Unlock()
	snap := Snapshot{
		Blocks:     map[string]int64{},
		Challenges: map[int]int64{},
		WAFMatches: map[string]int64{},
	}
	c, ok := counters[domain]
	if !ok {
		return snap
	}
	for k, v := range c.blocks {
		snap.Blocks[k] = v
	}
	for k, v := range c.challenges {
		snap.Challenges[k] = v
	}
	for k, v := range c.wafMatches {
		snap.WAFMatches[k] = v
	}
	snap.BackendOK = c.backendOK
	snap.BackendErr = c.backendErr
	snap.LatencySum = c.latencySum
	for _, n := range c.latencyObs {
		snap.LatencyCount += n
	}
	return snap
}

// Enabled reports whether the metrics endpoint is enabled. The value
// is read live from the loaded config, so a reload applies it.
func Enabled() bool {
	return domains.Config != nil && domains.Config.Proxy.MetricsEnabled
}

// IsMetricsRequest reports whether the request targets the metrics
// endpoint: the exact admin-secret path, with a non-empty admin
// secret and metrics enabled. Anything else is not a metrics
// request and must flow through the proxy normally.
func IsMetricsRequest(request *http.Request) bool {
	if proxy.AdminSecret == "" || !Enabled() {
		return false
	}
	return request.URL.Path == "/_bProxy/"+proxy.AdminSecret+"/metrics"
}

// ServeMetrics writes the Prometheus exposition for the current
// process state. Callers must have checked IsMetricsRequest first.
func ServeMetrics(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Write(Render())
}

var labelEscaper = strings.NewReplacer("\\", `\\`, "\"", `\"`, "\n", `\n`)

func escapeLabel(value string) string {
	return labelEscaper.Replace(value)
}

func boolGauge(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func parsePercent(value string) (float64, bool) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// Render builds the full exposition text. Domain statistics are
// copied under the firewall read lock; counter state is copied under
// the metrics lock. The "debug" pseudo-domain is skipped: it exists
// only for the terminal HUD and has no real traffic.
func Render() []byte {
	var out strings.Builder

	out.WriteString("# HELP sonushield_info Proxy build information.\n")
	out.WriteString("# TYPE sonushield_info gauge\n")
	out.WriteString("sonushield_info{version=\"" + strconv.FormatFloat(proxy.ProxyVersion, 'f', -1, 64) + "\"} 1\n")

	if cpu, ok := parsePercent(proxy.CpuUsage); ok {
		out.WriteString("# HELP sonushield_cpu_usage_percent Proxy CPU usage in percent.\n")
		out.WriteString("# TYPE sonushield_cpu_usage_percent gauge\n")
		out.WriteString("sonushield_cpu_usage_percent " + strconv.FormatFloat(cpu, 'f', -1, 64) + "\n")
	}
	if ram, ok := parsePercent(proxy.RamUsage); ok {
		out.WriteString("# HELP sonushield_ram_usage_percent Proxy memory usage in percent.\n")
		out.WriteString("# TYPE sonushield_ram_usage_percent gauge\n")
		out.WriteString("sonushield_ram_usage_percent " + strconv.FormatFloat(ram, 'f', -1, 64) + "\n")
	}

	firewall.Mutex.RLock()
	domainNames := make([]string, 0, len(domains.DomainsData))
	dataByDomain := make(map[string]domains.DomainData, len(domains.DomainsData))
	for name, data := range domains.DomainsData {
		if name == "debug" {
			continue
		}
		domainNames = append(domainNames, name)
		dataByDomain[name] = data
	}
	unknownFps := len(firewall.UnkFps)
	trackedIPs := len(firewall.AccessIps)
	firewall.Mutex.RUnlock()
	sort.Strings(domainNames)

	out.WriteString("# HELP sonushield_unknown_fingerprints Number of distinct unknown TLS fingerprints seen in the rate-limit window.\n")
	out.WriteString("# TYPE sonushield_unknown_fingerprints gauge\n")
	out.WriteString("sonushield_unknown_fingerprints " + strconv.Itoa(unknownFps) + "\n")
	out.WriteString("# HELP sonushield_ips_tracked Number of distinct client IPs seen in the rate-limit window.\n")
	out.WriteString("# TYPE sonushield_ips_tracked gauge\n")
	out.WriteString("sonushield_ips_tracked " + strconv.Itoa(trackedIPs) + "\n")

	writeDomainCounter := func(metric, help string, value func(domains.DomainData) int) {
		out.WriteString("# HELP " + metric + " " + help + "\n")
		out.WriteString("# TYPE " + metric + " counter\n")
		for _, name := range domainNames {
			out.WriteString(metric + "{domain=\"" + escapeLabel(name) + "\"} " + strconv.Itoa(value(dataByDomain[name])) + "\n")
		}
	}
	writeDomainGauge := func(metric, help string, value func(domains.DomainData) string) {
		out.WriteString("# HELP " + metric + " " + help + "\n")
		out.WriteString("# TYPE " + metric + " gauge\n")
		for _, name := range domainNames {
			out.WriteString(metric + "{domain=\"" + escapeLabel(name) + "\"} " + value(dataByDomain[name]) + "\n")
		}
	}

	writeDomainCounter("sonushield_requests_total", "Total requests received, including challenged and blocked ones.", func(d domains.DomainData) int { return d.TotalRequests })
	writeDomainCounter("sonushield_requests_bypassed_total", "Requests that passed verification and reached the backend.", func(d domains.DomainData) int { return d.BypassedRequests })
	writeDomainGauge("sonushield_requests_per_second", "Total requests per second in the last second.", func(d domains.DomainData) string { return strconv.Itoa(d.RequestsPerSecond) })
	writeDomainGauge("sonushield_requests_bypassed_per_second", "Verified requests per second in the last second.", func(d domains.DomainData) string { return strconv.Itoa(d.RequestsBypassedPerSecond) })
	writeDomainGauge("sonushield_peak_requests_per_second", "Peak total requests per second during the current attack window.", func(d domains.DomainData) string { return strconv.Itoa(d.PeakRequestsPerSecond) })
	writeDomainGauge("sonushield_peak_requests_bypassed_per_second", "Peak verified requests per second during the current attack window.", func(d domains.DomainData) string { return strconv.Itoa(d.PeakRequestsBypassedPerSecond) })
	writeDomainGauge("sonushield_stage", "Current challenge stage for the domain.", func(d domains.DomainData) string { return strconv.Itoa(d.Stage) })
	writeDomainGauge("sonushield_stage_locked", "Whether the stage was set manually (1) or is automatic (0).", func(d domains.DomainData) string { return boolGauge(d.StageManuallySet) })
	writeDomainGauge("sonushield_attack_raw", "Whether a non-bypassing attack is currently detected (1) or not (0).", func(d domains.DomainData) string { return boolGauge(d.RawAttack) })
	writeDomainGauge("sonushield_attack_bypass", "Whether a bypassing attack is currently detected (1) or not (0).", func(d domains.DomainData) string { return boolGauge(d.BypassAttack) })

	mu.Lock()
	countersCopy := make(map[string]*domainCounters, len(counters))
	for name, c := range counters {
		dup := &domainCounters{
			blocks:     map[string]int64{},
			challenges: map[int]int64{},
			wafMatches: map[string]int64{},
			backendOK:  c.backendOK,
			backendErr: c.backendErr,
			latencySum: c.latencySum,
			latencyObs: append([]int64(nil), c.latencyObs...),
		}
		for k, v := range c.blocks {
			dup.blocks[k] = v
		}
		for k, v := range c.challenges {
			dup.challenges[k] = v
		}
		for k, v := range c.wafMatches {
			dup.wafMatches[k] = v
		}
		countersCopy[name] = dup
	}
	mu.Unlock()

	counterNames := make([]string, 0, len(countersCopy))
	for name := range countersCopy {
		counterNames = append(counterNames, name)
	}
	sort.Strings(counterNames)

	out.WriteString("# HELP sonushield_blocks_total Blocked requests by reason.\n")
	out.WriteString("# TYPE sonushield_blocks_total counter\n")
	for _, name := range counterNames {
		reasons := make([]string, 0, len(countersCopy[name].blocks))
		for reason := range countersCopy[name].blocks {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			out.WriteString("sonushield_blocks_total{domain=\"" + escapeLabel(name) + "\",reason=\"" + escapeLabel(reason) + "\"} " + strconv.FormatInt(countersCopy[name].blocks[reason], 10) + "\n")
		}
	}

	out.WriteString("# HELP sonushield_challenges_total Challenges served by stage.\n")
	out.WriteString("# TYPE sonushield_challenges_total counter\n")
	for _, name := range counterNames {
		stages := make([]int, 0, len(countersCopy[name].challenges))
		for stage := range countersCopy[name].challenges {
			stages = append(stages, stage)
		}
		sort.Ints(stages)
		for _, stage := range stages {
			out.WriteString("sonushield_challenges_total{domain=\"" + escapeLabel(name) + "\",stage=\"" + strconv.Itoa(stage) + "\"} " + strconv.FormatInt(countersCopy[name].challenges[stage], 10) + "\n")
		}
	}

	out.WriteString("# HELP sonushield_waf_matches_total WAF-lite rule matches by rule name.\n")
	out.WriteString("# TYPE sonushield_waf_matches_total counter\n")
	for _, name := range counterNames {
		rules := make([]string, 0, len(countersCopy[name].wafMatches))
		for rule := range countersCopy[name].wafMatches {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		for _, rule := range rules {
			out.WriteString("sonushield_waf_matches_total{domain=\"" + escapeLabel(name) + "\",rule=\"" + escapeLabel(rule) + "\"} " + strconv.FormatInt(countersCopy[name].wafMatches[rule], 10) + "\n")
		}
	}

	out.WriteString("# HELP sonushield_backend_requests_total Backend round trips by result.\n")
	out.WriteString("# TYPE sonushield_backend_requests_total counter\n")
	for _, name := range counterNames {
		c := countersCopy[name]
		out.WriteString("sonushield_backend_requests_total{domain=\"" + escapeLabel(name) + "\",result=\"ok\"} " + strconv.FormatInt(c.backendOK, 10) + "\n")
		out.WriteString("sonushield_backend_requests_total{domain=\"" + escapeLabel(name) + "\",result=\"error\"} " + strconv.FormatInt(c.backendErr, 10) + "\n")
	}

	out.WriteString("# HELP sonushield_backend_latency_seconds Backend round-trip latency in seconds.\n")
	out.WriteString("# TYPE sonushield_backend_latency_seconds histogram\n")
	for _, name := range counterNames {
		c := countersCopy[name]
		var cumulative int64
		for i, bound := range latencyBuckets {
			cumulative += c.latencyObs[i]
			out.WriteString("sonushield_backend_latency_seconds_bucket{domain=\"" + escapeLabel(name) + "\",le=\"" + strconv.FormatFloat(bound, 'g', -1, 64) + "\"} " + strconv.FormatInt(cumulative, 10) + "\n")
		}
		cumulative += c.latencyObs[len(latencyBuckets)]
		out.WriteString("sonushield_backend_latency_seconds_bucket{domain=\"" + escapeLabel(name) + "\",le=\"+Inf\"} " + strconv.FormatInt(cumulative, 10) + "\n")
		out.WriteString("sonushield_backend_latency_seconds_sum{domain=\"" + escapeLabel(name) + "\"} " + strconv.FormatFloat(c.latencySum, 'f', -1, 64) + "\n")
		out.WriteString("sonushield_backend_latency_seconds_count{domain=\"" + escapeLabel(name) + "\"} " + strconv.FormatInt(cumulative, 10) + "\n")
	}

	return []byte(out.String())
}
