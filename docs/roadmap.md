# Roadmap

> **Mostly planned, not yet implemented.** Batches 5–8, sale-readiness, and 3 are planned work — none of it exists in the current code yet. **Batches 1, 2, and 4 and the control panel are implemented** (see their sections below). For what SonuShield can do today, see [Features](features.md).

Work is planned in batches, in this order: 1 → 2 → control panel → 4 → 5 → 6 → 7 → 8 → sale-readiness → 3. Batch 3 is the heaviest work and comes last.

## Batch 1 — Power Features ✅ Implemented

- Fresh TLS fingerprint lists and JA4 fingerprinting.
- Adaptive proof-of-work difficulty.
- Turnstile / hCaptcha challenge option (plumbing; activation needs the operator's own keys).
- Geo and ASN firewall rules (needs the operator's own GeoIP database).
- IP reputation and bad-bot feeds.
- WAF-lite rules (SQLi, XSS, WordPress login flood).
- Automatic SSL (Let's Encrypt).

Still planned from this batch's original scope: nothing — backend health checks and the cached fallback page were implemented in Batch 4.

## Batch 2 — Metrics, Alerts, Reports ✅ Implemented

- Prometheus metrics: secret-gated endpoint, disabled by default; per-domain counters, gauges, stage, and backend latency.
- Telegram / email alerts alongside Discord (activation needs the operator's own bot token / SMTP credentials).
- Attack reports with JSON/CSV export: `GET_ATTACK_REPORT` API action plus optional per-attack files in an operator-configured directory.
- Structured logs: optional JSON logging with rotation and privacy redaction; the default text output is unchanged.

## Control Panel ✅ Implemented

Browser-based management with zero terminal interaction needed for day-to-day operation:

- Stage control: `GET_STAGE` / `SET_STAGE` API actions (stage value, stage-lock, under-attack mode) and dashboard controls. Runtime-only, like the terminal `stage` command.
- Domain list and configuration: `GET_DOMAINS`, `GET_DOMAIN_CONFIG`, `SET_DOMAIN_CONFIG`. Secrets are never accepted or returned; structural settings stay config-file-only.
- Firewall rule editing: `ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE` with server-side validation (compiles, documented fields only, usable actions). Invalid rules change nothing.
- Log clearing per domain and proxy-wide (`CLEAR_LOGS`).
- Validated safe reload: the API `RELOAD` action validates `config.json` before applying it and never runs the panicking reload path on invalid input.
- Persistence: rule and domain-config changes are written to `config.json` atomically (temporary file, rotating `config.json.bak` backups, rename) and survive restarts; unknown keys in the file are preserved.
- Dashboard UI for all of the above, plus attack reports with export and the Batch 1/2 feature controls, in both themes.

## Batch 4 — Extra Protection and Management ✅ Implemented

- HTTP/2 fingerprinting from the signals Go's stack exposes (protocol/TLS/ALPN/header-hash/presence flags) as the `http.http2` rule field. Honest limit: HTTP/2 SETTINGS order/values, WINDOW_UPDATE, and PRIORITY frames are not observable via Go's `net/http`, and HTTP/1 header order is not preserved by Go — neither is claimed.
- Honeypot decoy endpoints (exact, case-sensitive match; configurable suspicion bump) and fake-Googlebot/Bingbot verification by reverse+forward DNS (fail-open on DNS errors, cached).
- Tarpit responses for confirmed-bad requests (configurable delay, capped concurrency).
- Edge caching (bounded, honors `private`/`no-store`, never caches `Set-Cookie` or authorized responses) with API purge, and a fair cookie-based waiting room for traffic spikes.
- Load balancing (round-robin / least-connections) and failover with replay-safe retries, backend health checks, and a clearly-marked stale-cache fallback when all backends are down. This closes the Batch 1 gap (health checks + cached fallback page).
- WebSocket proxying with a configurable idle timeout on a dedicated upgrade path.
- API protection: per-route JWT validation (HS256 secret or RS256/ES256 via JWKS, tokens never logged), per-API-key rate limits, and GraphQL depth/field limits — all off unless configured, failing closed per route on bad config.
- Dashboard roles (viewer/operator/admin via additional API secrets) and an audit log for every control-plane action (structured-log file when configured, else stdout; secrets never logged).
- Configuration rollback: rotating `config.json` backups with list/restore API actions and dashboard UI; restores validate like a reload and roll the file back if the reload fails.
- Rule simulator (match/no-match + fields used, nothing enforced) and per-domain dry-run mode (matches logged, no action taken), with dashboard UI.
- Firewall rule export/import as JSON with full validation (invalid imports change nothing), with dashboard UI.

Still planned from this batch's original scope: firewall-level block export (nftables / fail2ban). The JSON rule export/import above covers rule-set portability, not firewall-level blocklists.

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
