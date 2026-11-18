package domains

import "fmt"

// InitRuntime builds the per-domain runtime state that lives
// alongside the settings: tarpits, edge caches, waiting rooms,
// backend pools, and API-protection state. It is called once per
// domain at startup (config.Load) and on every reload
// (reloadFromConfig), right before the settings are stored, so
// both paths build identical state. Runtime state is always
// rebuilt from the config: a reload discards the old cache,
// queue, and pool health, which is the documented reload
// semantic (a reload resets per-domain state, like the counters).
//
// Stateful objects are nil when their feature is disabled, and
// every one of them is safe to use through a nil pointer, so the
// request path never needs nil checks for the "debug"
// pseudo-domain, which has no runtime state.
func InitRuntime(settings *DomainSettings, domain Domain) {
	settings.Tarpit = NewTarpitLimiter(domain.TarpitDelayMs, domain.TarpitSusLv, domain.TarpitMaxConns)
	settings.Cache = NewEdgeCache(domain.EdgeCache, domain.EdgeCacheTTL, domain.EdgeCacheMaxMB)
	settings.Waiting = NewWaitingRoom(domain.WaitingRoom, domain.WaitingRoomThreshold, domain.WaitingRoomAdmit)
	settings.FairQueue = NewFairQueue(domain.FairQueue, domain.FairQueueMaxInflight, domain.FairQueueWaitMs)
	WarnUnknownLBPolicy(domain.Name, domain.LBPolicy)
	settings.Pool = NewBackendPool(domain.Name, domain.Scheme, domain.Backends, domain.Backend, domain.LBPolicy, domain.HealthCheckEnabled, domain.HealthCheckPath, domain.HealthCheckInterval)
	settings.JWT = NewJWTVerifier(domain.Name, domain.JWTSecret, domain.JWTJWKSURL)
	if len(domain.JWTProtectedPaths) > 0 && settings.JWT == nil {
		fmt.Println("[ ! ] [ jwtProtectedPaths set for " + domain.Name + " but no jwtSecret/jwtJWKSURL configured; protected routes will reject all requests ]")
	}
	// Mobile app attestation (Batch 8): nil unless enabled with
	// paths. A verifier without verification material fails
	// closed on its paths; see NewAttestationVerifier.
	settings.Attest = NewAttestationVerifier(domain.Name, domain.Attestation)
	// Passkey challenge (Batch 8): nil unless enabled with an RP
	// ID and a credentials file. Zero enrolled credentials means
	// the captcha fallback applies.
	settings.Passkeys = NewPasskeyStore(domain.Name, domain.Passkey)
	if settings.APIKeyHeader == "" {
		settings.APIKeyHeader = "X-API-Key"
	}
	settings.APIKeys = NewAPIKeyState(domain.APIKeys)
	if len(domain.APIKeyPaths) > 0 && settings.APIKeys == nil {
		fmt.Println("[ ! ] [ apiKeyPaths set for " + domain.Name + " but no apiKeys configured; key-protected routes will reject all requests ]")
	}
	for _, route := range domain.BodyLimits {
		if route.Prefix == "" || route.MaxBytes <= 0 {
			fmt.Println("[ ! ] [ ignoring invalid bodyLimits entry for " + domain.Name + ": prefix must be non-empty and maxBytes positive ]")
		}
	}
	// CORS is validated here (Load and reload both run
	// InitRuntime): an invalid policy is disabled with a warning
	// and fails closed. Security-header entries are validated
	// the same way; invalid ones are skipped at apply time.
	settings.CORS = ValidateCORS(domain.Name, domain.CORS)
	for name, value := range domain.SecurityHeaders {
		if !ValidSecurityHeader(name, value) {
			fmt.Println("[ ! ] [ ignoring invalid securityHeaders entry for " + domain.Name + ": " + name + " ]")
		}
	}
	// IP allow/block lists are compiled here (Load and reload
	// both run InitRuntime); invalid entries warn and are skipped.
	settings.RebuildIPLists()
	// Page templates are validated here: script tags are
	// stripped and templates missing required placeholders are
	// disabled with a warning, falling back to built-in pages.
	settings.PageTemplates = ValidatePageTemplates(domain.Name, domain.PageTemplates)
}
