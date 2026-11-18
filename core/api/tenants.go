package api

// Multi-tenancy API (Batch 5).
//
//   - GET_TENANTS (proxy, viewer): every tenant with its domains.
//     Tenant-scoped callers are forbidden: they see only their
//     own tenant through GET_TENANT_USAGE.
//   - GET_TENANT_USAGE (proxy, viewer): per-tenant usage
//     aggregates — requests, blocked (approximated as
//     total minus bypassed, clamped at zero), and the bandwidth
//     estimate (request + response bytes). Optional "tenant"
//     param selects one tenant; tenant-scoped callers are forced
//     to their own tenant and forbidden from asking for another.
//
// Blocked is an approximation: requests that never passed a
// challenge include challenges served, blocks, and errors, and
// the counters cannot separate them. Bandwidth is an estimate:
// see core/server/metering.go.

import (
	"sort"
	"sonushield/core/domains"
	"sonushield/core/firewall"
)

// tenantDomains groups configured domain names by tenant, from
// the live settings. Delegates to domains.TenantDomains so the
// usage API and the billing reporter aggregate identically.
func tenantDomains() map[string][]string {
	return domains.TenantDomains()
}

func tenantsListResponse() map[string]interface{} {
	grouped := tenantDomains()
	names := make([]string, 0, len(grouped))
	for tenant := range grouped {
		names = append(names, tenant)
	}
	sort.Strings(names)
	list := []map[string]interface{}{}
	for _, tenant := range names {
		list = append(list, map[string]interface{}{
			"TENANT":       tenant,
			"DOMAINS":      grouped[tenant],
			"DOMAIN_COUNT": len(grouped[tenant]),
		})
	}
	return map[string]interface{}{
		"TENANTS": list,
	}
}

// tenantUsageResponse aggregates usage per tenant. tenantScope,
// when non-empty, forces the caller's own tenant.
func tenantUsageResponse(params map[string]string, tenantScope string) (map[string]interface{}, string) {
	selected := ""
	for key, value := range params {
		if key == "tenant" {
			selected = value
			continue
		}
		return nil, ERR_INVALID_PARAM
	}
	if tenantScope != "" {
		if selected != "" && selected != tenantScope {
			return nil, ERR_FORBIDDEN
		}
		selected = tenantScope
	}
	if selected != "" {
		selected = domains.NormalizeTenant(selected)
	}

	grouped := tenantDomains()
	names := make([]string, 0, len(grouped))
	for tenant := range grouped {
		if selected == "" || tenant == selected {
			names = append(names, tenant)
		}
	}
	sort.Strings(names)

	firewall.Mutex.RLock()
	defer firewall.Mutex.RUnlock()
	list := []map[string]interface{}{}
	for _, tenant := range names {
		var requests, bypassed, bytesIn, bytesOut int64
		for _, name := range grouped[tenant] {
			data := domains.DomainsData[name]
			requests += int64(data.TotalRequests)
			bypassed += int64(data.BypassedRequests)
			bytesIn += data.BytesIn
			bytesOut += data.BytesOut
		}
		blocked := requests - bypassed
		if blocked < 0 {
			blocked = 0
		}
		list = append(list, map[string]interface{}{
			"TENANT":      tenant,
			"DOMAINS":     grouped[tenant],
			"REQUESTS":    requests,
			"BLOCKED":     blocked,
			"BYTES_IN":    bytesIn,
			"BYTES_OUT":   bytesOut,
			"BYTES_TOTAL": bytesIn + bytesOut,
		})
	}
	return map[string]interface{}{
		"USAGE": list,
	}, ""
}

// tenantProxyActionAllowed reports whether a tenant-scoped caller
// may run a proxy action. Tenant callers see only their own
// domains (GET_DOMAINS, filtered) and their own usage.
func tenantProxyActionAllowed(action string) bool {
	switch action {
	case "GET_DOMAINS", "GET_TENANT_USAGE":
		return true
	default:
		return false
	}
}
