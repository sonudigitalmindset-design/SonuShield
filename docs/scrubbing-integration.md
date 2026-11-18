# Scrubbing-Center Integration

How SonuShield fits in front of — or behind — an upstream scrubbing provider, and what it honestly cannot do.

## What SonuShield is not

SonuShield is a userspace Go reverse proxy. It cannot do kernel-level XDP/eBPF packet filtering, and it cannot do Anycast routing. Those need kernel programs, BGP announcements, and a multi-location network — none of which a single Go process on one server can provide. Nothing in this project claims otherwise, and no configuration option enables either capability.

Volumetric attacks (large UDP floods, SYN floods, anything that saturates the server's network link) must be absorbed upstream, before traffic reaches the server. SonuShield defends the application layer: HTTP floods, slow requests, credential stuffing, scraping, and bot abuse that survives the network layer.

## The supported architecture

```
Internet → Scrubbing provider / CDN → SonuShield → Origin backends
```

The scrubbing provider (for example Cloudflare, or any GRE/tunnel-based scrubbing service) absorbs volumetric traffic and forwards clean traffic to SonuShield. SonuShield then applies TLS fingerprinting, staged challenges, firewall rules, rate limits, and the WAF to what remains, and forwards only legitimate traffic to the origins.

Two deployment shapes are supported:

1. **Scrubbing provider in front, SonuShield behind it.** Enable [Cloudflare mode](configuration.md) (`proxy.cloudflare: true`) when the provider terminates TLS and sets the usual forwarding headers. Note the trade-off: in Cloudflare mode the TLS fingerprint is not available (the fingerprint is reported as `Cloudflare`), because the TLS connection terminates at the provider. The `sh1` HTTP fingerprint, firewall rules, rate limits, and challenges still apply. The provider's country header (`CF-IPCountry`) is used for Geo signals when present.

2. **SonuShield in front, provider as failover.** Point DNS at SonuShield normally, and keep the provider configured as a standby that can be switched in by a DNS change during a large attack. SonuShield's per-domain backend pools with health checks and failover keep serving while backends are healthy; the provider takes over only when the link itself is saturated.

## Integration hooks

### Health and status endpoints

Both are opt-in via `proxy.statusPage: true`, answered before any challenge or rate limiting, and carry no sensitive data:

- `GET /_bProxy/health` — bare liveness check for scrubbing providers and load balancers. Returns exactly `{"status":"ok"}`. Use this as the provider's health-check URL.
- `GET /_bProxy/status` — proxy uptime and per-domain health (`name` + `healthy` flag only). No IPs, secrets, config, counts, rates, or stages. Use this for dashboards and alerting that need to know which domains have a healthy backend.

When `statusPage` is off, both paths fall through to the normal request flow exactly as before.

### Failover signaling

Per-domain backend pools (see [Configuration](configuration.md)) support health checks, failure thresholds with cooldown, and stale-cache fallback when all backends are down. A scrubbing provider polling `/_bProxy/status` sees `healthy: false` for a domain whose backends are all down, and can route around the SonuShield instance or serve its own cached copy. The `Warning: 110` response header on stale-cache responses tells downstream caches the content is stale.

### Origin lock

When a scrubbing provider is in front, attackers may try to reach SonuShield — or the origin — directly, bypassing the scrubbing. [Origin lock](configuration.md) (`originLockSecret`) makes SonuShield add a shared-secret header on every backend request, so the origin can reject anything that did not come through the proxy. Apply the same idea one layer up: restrict inbound traffic to SonuShield to the provider's IP ranges at the firewall, so direct-to-server traffic never reaches it. The secret is config-file-only; it is never logged or returned by the API.

### Metrics and alerts

The Prometheus metrics endpoint (`/_bProxy/<adminsecret>/metrics`, opt-in) exposes request, block, and challenge counters a provider's monitoring can scrape. Attack alerts (Discord, Telegram, email) fire when a domain's suspicion level crosses the configured threshold, giving operators early warning to engage the provider's "under attack" mode manually. SonuShield does not call any provider API itself; engaging the provider's mitigation stays a human decision.

## What stays manual

- Engaging or disengaging the provider's mitigation (no provider API integration).
- DNS changes for failover between SonuShield and the provider.
- Firewall rules restricting direct access to SonuShield's IPs.
- Tuning challenge stages and thresholds for the traffic mix that survives scrubbing.

## Honest limits

No single-server proxy is 100% DDoS-proof. SonuShield raises the cost of application-layer attacks and absorbs moderate floods; a link-saturating volumetric attack needs upstream capacity SonuShield does not have. Plan for both layers: scrubbing upstream, SonuShield at the application layer, and the origin locked to proxy traffic only.
