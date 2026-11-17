package domains

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
}
