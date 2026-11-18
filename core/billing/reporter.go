package billing

// Usage reporter (Batch 6): turns the per-tenant metering
// counters (see core/server/metering.go) into Stripe usage
// records, for tenants the operator mapped in proxy.stripe.
//
// Reporting semantics — read before enabling:
//
//   - Deltas only. The reporter remembers the last reported
//     counter value per tenant and metric and reports only the
//     increase since then, with action=increment. A failed
//     report leaves the baseline untouched, so the next run
//     retries the same delta with the same idempotency key.
//   - First sight baselines. The first time a tenant+metric is
//     seen, its current counter becomes the baseline and
//     nothing is reported: enabling billing never retro-bills
//     usage from before the mapping existed.
//   - Reloads lose unreported usage, never double it. Counters
//     reset on reload; when a counter reads below its baseline
//     the reporter treats the current value as a fresh delta
//     (post-reload traffic) and forgets the pre-reload
//     remainder, which is unknowable after the reset.
//   - Counters are estimates (see metering.go), so reported
//     usage is estimate-grade, not billing-grade. Challenge
//     pages, blocks, errors, and WebSocket traffic are not
//     counted; bandwidth excludes headers.
//   - Units are raw: request counts and bytes. The operator's
//     metered Stripe prices must be defined in those units.
//   - Nothing is reported without a valid secret key and at
//     least one valid mapping. Invalid mappings are skipped
//     with a reason in the status, never fatal.
//
// The background reporter re-reads the live config on every
// tick, so enabling, disabling, or re-mapping via a reload
// takes effect without a restart. ReportOnce is also exposed
// to the admin-only REPORT_STRIPE_USAGE API action.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/firewall"
)

// Metric identifies one reported usage dimension.
type Metric string

const (
	// MetricRequests counts proxied requests per tenant.
	MetricRequests Metric = "requests"
	// MetricBandwidth counts estimated bytes (in + out) per tenant.
	MetricBandwidth Metric = "bandwidth"
)

// TenantUsage is one tenant's current counter snapshot.
type TenantUsage struct {
	Requests int64
	Bytes    int64
}

type baselineKey struct {
	tenant string
	metric Metric
}

var (
	reportMu     sync.Mutex
	baselines    = map[baselineKey]int64{}
	seen         = map[baselineKey]bool{}
	lastOutcome  *ReportOutcome
	reporterOnce sync.Once
)

// TenantResult is one tenant+metric outcome of a report run.
type TenantResult struct {
	Tenant   string
	Metric   Metric
	Status   string // reported, skipped-baseline, skipped-zero, skipped-invalid, error
	Quantity int64
	Detail   string
}

// ReportOutcome is one report run, manual or scheduled.
type ReportOutcome struct {
	Time     time.Time
	Disabled bool
	Reason   string
	Results  []TenantResult
}

// liveStripeConfig returns the live Stripe settings, or a zero
// config when no config is loaded.
func liveStripeConfig() domains.StripeConfig {
	if domains.Config == nil {
		return domains.StripeConfig{}
	}
	return domains.Config.Proxy.Stripe
}

// snapshotUsage aggregates the live counters per tenant.
func snapshotUsage() map[string]TenantUsage {
	grouped := domains.TenantDomains()
	firewall.Mutex.RLock()
	defer firewall.Mutex.RUnlock()
	out := map[string]TenantUsage{}
	for tenant, names := range grouped {
		var usage TenantUsage
		for _, name := range names {
			data := domains.DomainsData[name]
			usage.Requests += int64(data.TotalRequests)
			usage.Bytes += data.BytesIn + data.BytesOut
		}
		out[tenant] = usage
	}
	return out
}

// idempotencyKey derives a deterministic key for one delta, so
// retries of the same report deduplicate server-side.
func idempotencyKey(tenant string, metric Metric, baseline, quantity int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("sonushield-stripe\n%s\n%s\n%d\n%d", tenant, metric, baseline, quantity)))
	return "sonushield-" + hex.EncodeToString(sum[:16])
}

// validateMapping checks one tenant mapping and returns the
// reason it must be skipped, or "" when it can report.
func validateMapping(m domains.StripeCustomerMapping) string {
	if !ValidCustomerID(m.CustomerID) {
		return "customerId must be a Stripe customer id (cus_...)"
	}
	if m.RequestsItemID == "" && m.BandwidthItemID == "" {
		return "no subscription item mapped"
	}
	if m.RequestsItemID != "" && !ValidSubscriptionItemID(m.RequestsItemID) {
		return "requestsItemId must be a Stripe subscription item id (si_...)"
	}
	if m.BandwidthItemID != "" && !ValidSubscriptionItemID(m.BandwidthItemID) {
		return "bandwidthItemId must be a Stripe subscription item id (si_...)"
	}
	return ""
}

// ReportOnce snapshots the counters and reports new usage for
// every mapped tenant. Concurrent calls are serialized. The
// returned outcome is also retained for status reporting.
func ReportOnce() ReportOutcome {
	reportMu.Lock()
	defer reportMu.Unlock()

	cfg := liveStripeConfig()
	outcome := ReportOutcome{Time: time.Now()}
	if !ValidSecretKey(cfg.SecretKey) {
		outcome.Disabled = true
		outcome.Reason = "stripe not configured (no valid secret key)"
		lastOutcome = &outcome
		return outcome
	}
	if len(cfg.Customers) == 0 {
		outcome.Disabled = true
		outcome.Reason = "stripe configured but no tenant mapped"
		lastOutcome = &outcome
		return outcome
	}

	client := NewClient(cfg.APIBase, cfg.SecretKey)
	usage := snapshotUsage()
	timestamp := time.Now().Unix()

	rawKeys := make([]string, 0, len(cfg.Customers))
	for tenant := range cfg.Customers {
		rawKeys = append(rawKeys, tenant)
	}
	sort.Strings(rawKeys)
	seenTenants := map[string]bool{}
	for _, rawKey := range rawKeys {
		tenant := domains.NormalizeTenant(rawKey)
		mapping := cfg.Customers[rawKey]
		if seenTenants[tenant] {
			outcome.Results = append(outcome.Results, TenantResult{
				Tenant: tenant, Status: "skipped-invalid",
				Detail: "duplicate mapping for this tenant name",
			})
			continue
		}
		seenTenants[tenant] = true
		if reason := validateMapping(mapping); reason != "" {
			outcome.Results = append(outcome.Results, TenantResult{
				Tenant: tenant, Status: "skipped-invalid", Detail: reason,
			})
			continue
		}
		u := usage[tenant] // zero when the tenant has no domains (yet)
		reportMetric := func(metric Metric, itemID string, current int64) {
			if itemID == "" {
				return
			}
			key := baselineKey{tenant, metric}
			if !seen[key] {
				seen[key] = true
				baselines[key] = current
				outcome.Results = append(outcome.Results, TenantResult{
					Tenant: tenant, Metric: metric, Status: "skipped-baseline",
					Detail: "first sight: baseline recorded, nothing reported",
				})
				return
			}
			baseline := baselines[key]
			delta := current - baseline
			if current < baseline {
				// Counter reset (reload): report the
				// post-reset value as a fresh delta.
				delta = current
			}
			if delta <= 0 {
				baselines[key] = current
				outcome.Results = append(outcome.Results, TenantResult{
					Tenant: tenant, Metric: metric, Status: "skipped-zero",
				})
				return
			}
			if err := client.ReportUsage(itemID, delta, timestamp, idempotencyKey(tenant, metric, baseline, delta)); err != nil {
				outcome.Results = append(outcome.Results, TenantResult{
					Tenant: tenant, Metric: metric, Status: "error",
					Quantity: delta, Detail: err.Error(),
				})
				return
			}
			baselines[key] = current
			outcome.Results = append(outcome.Results, TenantResult{
				Tenant: tenant, Metric: metric, Status: "reported", Quantity: delta,
			})
		}
		reportMetric(MetricRequests, mapping.RequestsItemID, u.Requests)
		reportMetric(MetricBandwidth, mapping.BandwidthItemID, u.Bytes)
	}
	lastOutcome = &outcome
	return outcome
}

// MappedTenant describes one configured mapping for status
// reporting. It never includes the secret key.
type MappedTenant struct {
	Tenant          string
	CustomerID      string
	RequestsItemID  string
	BandwidthItemID string
	Valid           bool
	InvalidReason   string
}

// Status is the operator-facing billing state: configuration
// summary plus the last report outcome.
type Status struct {
	Enabled  bool
	KeyMode  string
	Interval int
	Mapped   []MappedTenant
	Last     *ReportOutcome
}

// GetStatus returns the current billing state.
func GetStatus() Status {
	reportMu.Lock()
	defer reportMu.Unlock()
	cfg := liveStripeConfig()
	st := Status{
		Enabled:  ValidSecretKey(cfg.SecretKey),
		KeyMode:  KeyMode(cfg.SecretKey),
		Interval: clampInterval(cfg.ReportIntervalSeconds),
	}
	for tenant, mapping := range cfg.Customers {
		reason := validateMapping(mapping)
		st.Mapped = append(st.Mapped, MappedTenant{
			Tenant:          domains.NormalizeTenant(tenant),
			CustomerID:      mapping.CustomerID,
			RequestsItemID:  mapping.RequestsItemID,
			BandwidthItemID: mapping.BandwidthItemID,
			Valid:           reason == "",
			InvalidReason:   reason,
		})
	}
	sort.Slice(st.Mapped, func(i, j int) bool { return st.Mapped[i].Tenant < st.Mapped[j].Tenant })
	st.Last = lastOutcome
	return st
}

// clampInterval bounds the scheduled-report interval. Zero
// means disabled and is preserved; any other value is clamped
// to 60-86400 seconds.
func clampInterval(seconds int) int {
	if seconds == 0 {
		return 0
	}
	if seconds < 60 {
		return 60
	}
	if seconds > 86400 {
		return 86400
	}
	return seconds
}

// StartReporter starts the scheduled reporting loop exactly
// once. It is called from Serve, after config.Load has run.
// With no valid key or a zero interval the loop sleeps,
// re-checking the live config on every tick, so enabling
// billing via a reload starts reporting without a restart.
func StartReporter() {
	reporterOnce.Do(func() { go reporterLoop() })
}

func reporterLoop() {
	for {
		interval := clampInterval(liveStripeConfig().ReportIntervalSeconds)
		if interval == 0 || !ValidSecretKey(liveStripeConfig().SecretKey) {
			time.Sleep(60 * time.Second)
			continue
		}
		func() {
			defer func() { _ = recover() }()
			ReportOnce()
		}()
		time.Sleep(time.Duration(interval) * time.Second)
	}
}
