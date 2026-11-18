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

## Batch 7 — Deeper Detection, Operations, and Trust ✅ Implemented

- Passive OS fingerprinting from genuinely observable TCP signals only (MSS, RTT, negotiated options via `TCP_INFO` on Linux), classified by operator-supplied signatures — no bundled signature database, unknown stays unknown. Classic p0f signals (TTL, DF flag, option order, window-scale value, initial window) are not observable through Go's stack and are documented as unavailable.
- Mouse/scroll behavior check, collected only on challenge pages the proxy serves (presence + coarse timing buckets, no coordinates or keystrokes), log-only by default.
- Canary tokens: operator-configured decoy paths and fake credentials whose use immediately raises maximum suspicion and fires an alert. Disabled with none configured.
- Invisible markers: honeypot form fields and invisible links injected only into challenge/verification pages the proxy serves, never into origin content. Off by default.
- Fair queuing: per-IP FIFO queues with round-robin admission (deficit round-robin, quantum 1, equal weights — no cost/size weighting claimed) under overload; inert at normal load.
- Shadow mode: shadow rules and shadow WAF evaluation alongside live enforcement, logging what *would* have happened, with a comparison report. Shadow decisions never affect traffic. (Not traffic mirroring to a test backend — evaluation only.)
- Signed URLs (HMAC + expiry, strict verification, no clock-skew allowance) and Referer-based hotlink protection with an allowlist. Both off by default.
- Form spam guard: honeypot fields, submission-timing analysis, and per-form rate limits, opt-in per path, log-only mode available, generous defaults.
- Latency/TTFB tracking (p50/p95/p99, proxy vs origin split) and SLA reporting via API and dashboard, with the measurement points documented exactly.
- Attack timeline and auto-generated postmortem (JSON + readable text) from existing logs/metrics — no new data collection.
- Security grade scan: a configuration audit (TLS, headers, challenge coverage, secret hygiene without printing secrets, debug exposure), honestly labelled as not a penetration test. Never phones home.
- Certificate-expiry alerts and subdomain monitoring for operator-supplied names via system DNS (no CT-log lookup), fail-open, reusing existing alert channels.
- Scheduled rules (cron-style, timezone-aware, fail-safe on parse errors) and maintenance windows (scheduled or on-demand via API/dashboard).
- Community rule packs: importable from operator-supplied files/URLs, validated all-or-nothing, with metadata recorded. No bundled packs, no endorsement claimed.
- Cloudflare import: firewall rules from the operator's own API token (config-only, never logged), with a read-only dry-run preview before applying. Read-only until confirmed.
- Privacy mode: IP anonymization and no user-agent storage in logs/reports, shortened retention, applied consistently across logs, reports, metrics, and dashboard. Off by default.
- Two-person approval for sensitive control actions (config/backup restore, rule/domain/pack imports, Cloudflare apply, template domain creation), with pending state, expiry, and audit logging. Off by default.

## Batch 8 — Attestation, APIs, and Control Panel Depth ✅ Implemented

- Mobile app attestation: Play Integrity / App Attest style JWT verification (signature, issuer, audience, expiry, verdict claim) on operator-configured API paths, with the operator's own JWKS URL or HS256 secret. Fail-closed when configured without material. JWT-form assertions only — Apple App Attest CBOR is not parsed — and verified against mock tokens only; real-device attestation is untested here.
- Passkey challenge: an optional WebAuthn assertion challenge as a Stage 3 alternative to the captcha for enrolled users (server-side verification, single-use nonces, sign-counter checks, credentials stored only as public-key material). Falls back to the captcha when nothing is enrolled. Registration ceremony is not implemented — enrollment is out-of-band via the API.
- Credential stuffing detection: per-IP and distributed failed-login correlation (velocity thresholds, configurable paths/statuses/window), log-only by default, opt-in +2 suspicion in block mode, never an outright block. No bundled credential data, no bodies or usernames inspected.
- Session hijack detection: flags a session cookie only when two or more bound signals (IP, TLS/HTTP fingerprint, country) differ; log-only by default, never blocks on a single signal change; raw cookie values are never stored.
- OpenAPI validation: operator-supplied JSON OpenAPI 3.x specs (paths, methods, required params, schema types) with per-route log/block modes; invalid specs fail safe with a warning and no enforcement. Schema subset documented; `allOf`/`oneOf`/`anyOf`, discriminators, and `format` are not evaluated.
- DLP scanning: operator-configured regex patterns over outbound response bodies (redact or block), no bundled patterns, matched content never logged/stored/returned; oversized or encoded bodies pass unscanned (fail open).
- CSP report collector: legacy and Reporting API formats, bounded per-domain storage (200 reports) with trimmed fields, API + dashboard views; reports never influence enforcement.
- Opt-in threat-sharing network: HMAC-signed indicator exchange between explicitly peered instances — no central server, no bundled feeds, no PII; peer errors fail open; a shared indicator raises suspicion by one level, never blocks alone.
- BGP alerts: route-announcement monitoring for the operator's prefixes via RIPEstat (default, no credentials) or a custom API, alerting once per transition to an unexpected origin; fail-open, coarse-grained by the source's aggregation interval.
- Live log tail: authenticated SSE stream for the dashboard, reusing role auth, bounded buffer, sanitized entries only (audit entries never streamed).
- Synthetic checks: scheduled self-checks through the proxy (GET/HEAD, TLS verified) alerting once per failure/latency transition over existing channels; checks are ordinary requests and never touch attack statistics. Single-instance only — not multi-region.
- RUM beacon: navigation-timing buckets only, no query strings, no IPs stored, privacy-mode aware, with aggregated API + dashboard views. The snippet is served for operator embedding only — never injected into origin content, not added to challenge pages.
- On-call rotation: timezone-aware schedules with handover, escalation after N unacknowledged minutes, acknowledgement via API; falls back to all configured channels when nobody is on call.
- Visual rule builder: dashboard field/operator/value pickers generating gofilter expressions, validated server-side before saving exactly like typed rules; only documented populated fields offered.
- WordPress and hosting-panel plugins: a WordPress plugin (status in wp-admin, login-failure forwarding with an operator secret) and a cPanel/Plesk-compatible API client with install docs and hook sketches. Untested in a real WordPress/panel environment — documented as such.
- Nginx/Apache config import: a documented subset (server names, backends, TLS paths) with a dry-run preview showing exactly what would change; unparseable directives are reported, never silently dropped.
- Cache analytics with purge by path, prefix, or `Cache-Tag`, via API + dashboard; counters only.
- Config validator (`sonushield validate`, with optional `--probe-backends`) plus a GitHub Actions CI workflow running build, vet, and the validator on pushes/PRs — no secrets needed.

## Sale-Readiness

Quality work needed before the project can be evaluated seriously by a larger organization:

- Automated tests (still pending) and a CI pipeline (✅ done in Batch 8: build + vet + config validator on pushes/PRs).
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
