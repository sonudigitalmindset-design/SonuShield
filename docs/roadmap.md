# Roadmap

> **Mostly planned, not yet implemented.** Batches 7–8, sale-readiness, and 3 are planned work — none of it exists in the current code yet. **Batches 1, 2, 4, 5, and 6 and the control panel are implemented** (see their sections below). For what SonuShield can do today, see [Features](features.md).

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

## Batch 5 — Detection, Management, Business ✅ Implemented

- Risk-score engine combining fingerprint, behavior, and reputation signals (fixed documented weights; `ip.risk` rule field, logs, reports).
- Client fingerprinting: the `sh1` HTTP fingerprint extended with additional stable, privacy-respecting request signals (Accept-Encoding/Language patterns, client-preference headers). Deliberately **not** canvas, WebGL, or mouse/keyboard behavior scripts — no browser fingerprinting, no evercookies, no cross-site tracking.
- Cross-domain reputation sharing (opt-in per domain, fail-open).
- Timing and velocity detection for bot request patterns (log-only by default, enforcement opt-in).
- Per-session rate limits (friendlier to users sharing one IP, e.g. mobile networks).
- Slowloris and request-smuggling guards (connection cap added; slow-header timeout and ambiguous-framing normalisation inherited from Go — see [Configuration](configuration.md#slowloris-and-request-smuggling-guards)).
- Payload size limits globally and per route (32 MiB default, clean `413`). No JSON depth limiting was added; no request decompression happens, so there is no decompression-bomb surface.
- Origin lock (shared-secret header on every backend request; config-file-only secret).
- Security headers and CORS management at the proxy (fail-closed CORS validation).
- IP manager UI (allow/block lists, expiring entries, API + dashboard). Single-entry management only — no bulk import.
- Custom challenge pages per domain, including Hindi language support (safe placeholder set, scripts stripped).
- Log search and a geographic attack map (GeoIP-gated, schematic SVG, zero external assets).
- Public status page plus a bare health endpoint.
- Multi-tenancy and usage metering (tenant-scoped API roles, bandwidth estimates).
- GitOps configuration sync (validated reload path, one-way).
- SSO login for the dashboard (OIDC, PKCE, JWKS-verified tokens; paths temporary until the platform-host work).
- eBPF / Anycast / scrubbing-provider integration: honesty limit — kernel XDP/eBPF filtering and Anycast cannot be delivered by this userspace proxy. Delivered: health/status polling hooks, failover signaling, and [integration docs](scrubbing-integration.md) only. No eBPF/Anycast capability is claimed.

## Batch 6 — Next-Generation Detection, Operations, and Business ✅ Implemented

- Control-plane exemption (fix from Batch 5 findings): API/dashboard requests carrying a valid secret bypass the challenge flow, so scripted clients can unlock a locked stage; wrong-secret requests keep the previous fall-through behavior exactly.
- Post-quantum TLS: X25519MLKEM768 hybrid key exchange (Go 1.24 default), verified by real handshakes, with a `tlsDisablePostQuantum` opt-out. ECH honesty limit: Go's stdlib has no server-side ECH as of Go 1.24 — documented only, not claimed. QUIC fingerprinting honesty limit: no QUIC listener exists until Batch 3's HTTP/3 work, so only the reserved, inactive `ip.quic` field exists — no QUIC data is invented.
- Memory-hard Argon2 proof-of-work (opt-in, phone-safe defaults, pure-JS solver, no CDN/WASM) and challenge rotation across attack waves or per request (PoW / memory-hard / Turnstile / hCaptcha / captcha, per operator policy).
- Brotli compression and on-the-fly image optimization (both off by default, strict size/CPU bounds, never for non-GET or authenticated traffic).
- Origin connection pooling (configurable limits, inert by default) and a cache stampede guard (single-flight collapse of identical cache misses).
- Edge rules engine: a precompiled fast-path chain evaluated before the general rules, with identical semantics proven by differential tests. (The roadmap's original "WASM/JS" phrasing was not built; the precompiled chain is what exists.)
- Setup wizard (web-based, localhost-only, never overwrites without confirmation), domain templates (WordPress, static, API, e-commerce, plain), and validated bulk domain import (JSON/CSV, all-or-nothing).
- CLI (`run`/`validate`/`export`/`backup`/`restore`/`version`/`help`), Helm chart, and a checksum-verified install script with pinned versions. No versioned release or container image exists yet, so neither has been exercised against a published artifact.
- Dashboard Hindi/English toggle (full UI strings, persisted) and PWA support for the app shell only — never API responses or secrets, and no push notifications (the roadmap's "PWA push notifications" phrasing was not built).
- WhatsApp/SMS alerts via the operator's own Twilio-compatible account (config-file-only credentials, inert without them; mock-verified only, no live delivery tested).
- White-label branding (display name, logo URL, accent color) for the dashboard and built-in challenge pages, with the hard limit that GPL attribution — LICENSE, the credits endpoint, README/docs credits — always stays.
- Stripe usage-based billing hooks: per-tenant customer/subscription-item mapping, deltas-only idempotent usage reporting from metering counters (estimate-grade, raw units), test/live key modes. Mock-verified only; creates no customers, subscriptions, or charges.
- Versioned public API v1 for tenants/resellers (API-key auth, tenant scoping, per-key rate limits, JSON errors at any stage) plus minimal Go and Python SDKs with examples that run against a live proxy.
- Signed event webhooks (HMAC-SHA256, retry with backoff) and SIEM export formats (JSON syslog + CEF) for attack/audit events; secrets never in payloads; HTTP POST delivery only.
- Full backup export (config + rules + IP lists + tenants; secrets redacted by default, encrypted opt-in) and validated restore/migrate — a bad backup changes nothing.

Still planned from this batch's original scope: nothing — every item above is implemented, with the honesty limits noted inline.

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
