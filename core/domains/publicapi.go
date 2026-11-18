package domains

// Public API keys (Batch 6). See core/api/public.go for the
// API itself. Config-file-only: keys are never accepted
// through the API or the dashboard, never logged, and redacted
// from config exports.
//
// Each key belongs to exactly one tenant and can only read
// that tenant's usage and domains. A key shorter than
// MinPublicAPIKeyLength never matches: short keys are a
// configuration mistake, and failing closed is safer than
// serving a tenant's data to a guessable credential.
type PublicAPIKey struct {
	Key               string `json:"key"`
	Tenant            string `json:"tenant"`
	Name              string `json:"name"`
	RequestsPerMinute int    `json:"requestsPerMinute"`
}

// MinPublicAPIKeyLength is the shortest key that can ever
// authenticate to the public API.
const MinPublicAPIKeyLength = 16

// DefaultPublicAPIRateLimit is the per-key request budget per
// minute when a key sets no (or an invalid) limit.
const DefaultPublicAPIRateLimit = 60

// MaxPublicAPIRateLimit bounds per-key limits so a typo cannot
// disable rate limiting by accident.
const MaxPublicAPIRateLimit = 60000

// EffectiveRateLimit returns the key's per-minute budget:
// the configured value clamped to 1-MaxPublicAPIRateLimit,
// or the default when unset.
func (k PublicAPIKey) EffectiveRateLimit() int {
	if k.RequestsPerMinute <= 0 {
		return DefaultPublicAPIRateLimit
	}
	if k.RequestsPerMinute > MaxPublicAPIRateLimit {
		return MaxPublicAPIRateLimit
	}
	return k.RequestsPerMinute
}

// EffectiveTenant returns the tenant the key reads: the
// configured name normalized, or the default tenant when empty.
func (k PublicAPIKey) EffectiveTenant() string {
	return NormalizeTenant(k.Tenant)
}
