# Roadmap

> **Mostly planned, not yet implemented.** Batches 4–8, sale-readiness, and 3 are planned work — none of it exists in the current code yet. **Batches 1 and 2 are implemented** (see their sections below). For what SonuShield can do today, see [Features](features.md).

Work is planned in batches, in this order: 1 → 2 → 4 → 5 → 6 → 7 → 8 → sale-readiness → 3. Batch 3 is the heaviest work and comes last.

## Batch 1 — Power Features ✅ Implemented

- Fresh TLS fingerprint lists and JA4 fingerprinting.
- Adaptive proof-of-work difficulty.
- Turnstile / hCaptcha challenge option (plumbing; activation needs the operator's own keys).
- Geo and ASN firewall rules (needs the operator's own GeoIP database).
- IP reputation and bad-bot feeds.
- WAF-lite rules (SQLi, XSS, WordPress login flood).
- Automatic SSL (Let's Encrypt).

Still planned from this batch's original scope: backend health checks and a cached fallback page.

## Batch 2 — Metrics, Alerts, Reports ✅ Implemented

- Prometheus metrics: secret-gated endpoint, disabled by default; per-domain counters, gauges, stage, and backend latency.
- Telegram / email alerts alongside Discord (activation needs the operator's own bot token / SMTP credentials).
- Attack reports with JSON/CSV export: `GET_ATTACK_REPORT` API action plus optional per-attack files in an operator-configured directory.
- Structured logs: optional JSON logging with rotation and privacy redaction; the default text output is unchanged.

## Batch 4 — Extra Protection and Management

- HTTP/2 fingerprinting and header-order checks.
- Honeypot traps and fake-Googlebot verification.
- Tarpit responses for abusive clients.
- Edge caching and a waiting room for traffic spikes.
- Load balancing and backend failover.
- WebSocket protection.
- API key / JWT protection with per-key limits and GraphQL depth limits.
- Dashboard roles and audit log.
- Configuration rollback.
- Rule simulator / dry-run mode.
- Firewall-level block export (nftables / fail2ban).

## Batch 5 — Detection, Management, Business

- Risk-score engine combining fingerprint, behavior, and reputation signals.
- Client-side fingerprinting (canvas, WebGL, mouse/keyboard behavior).
- Cross-domain reputation sharing.
- Timing and velocity detection for bot request patterns.
- Per-session rate limits (friendlier to users sharing one IP, e.g. mobile networks).
- Slowloris and request-smuggling guards.
- Payload size and depth limits, decompression-bomb protection.
- Origin lock (backend accepts only signed proxy requests).
- Security headers and CORS management at the proxy.
- IP manager UI (allow/block lists, expiring bans, bulk import).
- Custom challenge pages per domain, including Hindi language support.
- Log search and a geographic attack map.
- Public status page.
- Multi-tenancy and usage metering.
- GitOps configuration sync.
- SSO login for the dashboard.
- eBPF / Anycast / scrubbing-provider integration (heaviest items, need dedicated infrastructure).

## Batch 6 — Next-Generation Detection, Operations, and Business

- ECH and post-quantum TLS support; QUIC fingerprinting.
- Memory-hard proof-of-work and challenge rotation.
- Brotli compression and image optimization at the proxy.
- Origin connection pooling and a cache stampede guard.
- Edge rules engine (WASM / JS) for custom logic at the edge.
- Setup wizard, domain templates, and bulk domain import.
- CLI tool, Helm chart, and one-click installer.
- Dashboard in Hindi and English, with PWA push notifications.
- WhatsApp / SMS alerts.
- White-label support.
- Stripe billing with plans.
- Public API and SDKs.
- Outbound webhooks and SIEM export.
- Full backup and one-click migration.

## Batch 7 — Deeper Detection, Operations, and Trust

- Passive OS fingerprinting from TCP behavior, a signal independent of TLS.
- Mouse and scroll behavior checks to separate humans from bots.
- Canary tokens: planted fake API keys whose use triggers an instant ban and alert.
- Per-visitor invisible page markers for tracing leaked content.
- Fair queuing so heavy users slow down without affecting light users.
- Shadow mode: mirror live traffic to a test backend for rule testing.
- Signed URLs and hotlink protection for images and files.
- Form spam guard using hidden fields and submission velocity.
- Backend latency and TTFB tracking (p50/p95/p99) with SLA history.
- Attack timeline with automatic postmortem generation.
- Security grade scan for the site's own headers and settings.
- Certificate Transparency and dangling-subdomain alerts.
- Scheduled rules and one-click maintenance mode.
- Community rule packs (WordPress, API, gaming presets).
- Cloudflare settings import.
- Privacy mode: IP anonymization and log retention controls.
- Two-person approval for dangerous actions.

## Batch 8 — Attestation, APIs, and Control Panel Depth

- Mobile app attestation: Play Integrity / App Attest verification at the proxy.
- Passkey challenge for visitors (prove humanity once, trusted for days).
- Credential stuffing detection across distributed IPs.
- Session hijack detection (re-challenge on mid-session IP/device change).
- OpenAPI schema validation for APIs.
- DLP scanning of responses (block leaked secrets, keys, and ID patterns).
- CSP report collector with policy suggestions.
- Opt-in threat-sharing network between SonuShield deployments.
- BGP hijack alerts for the operator's prefixes.
- Live log tail in the dashboard.
- Synthetic checks from multiple regions.
- Real-user monitoring (RUM) beacon.
- On-call rotation and escalation policies.
- Visual rule builder (no-code).
- WordPress and hosting-panel (cPanel/Plesk) plugins.
- Nginx/Apache config import.
- Cache analytics with purge by tag.
- Config validator with CI check.

## Sale-Readiness

Quality work needed before the project can be evaluated seriously by a larger organization:

- Automated tests and a CI pipeline.
- Security audit.
- Real, measured benchmarks (no estimates).
- Architecture documentation and a changelog.
- Clean-history review (including the old public private key that remains in git history and must never be reused).

## Batch 3 — Heavy Work, Last

- Multi-server rate limiting with Redis.
- HTTP/3 support.
- Cloudflare API integration for automatic Under Attack mode.
- Machine-learning anomaly detection (evaluation first).

## Also Noted for Later

- Forking or vendoring the `balooPow` proof-of-work script so Stage 2 no longer depends on the original project's CDN.
- Validating the Docker image build (no Docker available in the development environment yet).
- A future Go toolchain decision: the newest `golang.org/x/*` packages and gopsutil v4.26.x require Go 1.26.

## Dashboard Management Actions

Browser-based management — stage control, firewall rule editing, and domain management from the dashboard — is planned. Dashboard v1 (read-only monitoring) already exists; see [Dashboard](dashboard.md). Authenticated API actions for reading and adjusting feature settings (adaptive proof-of-work, WAF-lite, reputation feed) already exist — see [API Reference](api.md) — but the dashboard UI does not use them yet, and stage control, rule editing, and domain management still need new API endpoints first, which do not exist yet.
