package domains

// Multi-tenancy (Batch 5).
//
// Domains are grouped per tenant by the config-file-only `tenant`
// key. Tenancy is assignment-only: it changes what tenant-scoped
// API callers can see and how usage is aggregated, never how
// requests are proxied. A domain without a tenant belongs to the
// default tenant, and single-tenant configs behave exactly as
// before.
//
// Tenant names are free-form strings; empty or whitespace-only
// values normalize to DefaultTenant. Tenant-scoped API roles
// (proxy.apiRoles values of the form "tenant:<name>:<role>")
// match the normalized name.

import (
	"sort"
	"strings"
)

// DefaultTenant is the tenant every domain belongs to unless the
// config assigns another.
const DefaultTenant = "default"

// NormalizeTenant returns the effective tenant name for a
// configured value: trimmed, or DefaultTenant when empty.
func NormalizeTenant(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return DefaultTenant
	}
	return trimmed
}

// TenantDomains groups configured domain names by tenant, from
// the live settings. The "debug" pseudo-domain is never listed
// (it is not in Domains). Shared by the usage API and the
// billing reporter so both aggregate identically.
func TenantDomains() map[string][]string {
	grouped := map[string][]string{}
	for _, name := range Domains {
		uncasted, ok := DomainsMap.Load(name)
		if !ok {
			continue
		}
		settings, _ := uncasted.(DomainSettings)
		tenant := settings.Tenant
		if tenant == "" {
			tenant = DefaultTenant
		}
		grouped[tenant] = append(grouped[tenant], name)
	}
	for _, names := range grouped {
		sort.Strings(names)
	}
	return grouped
}
