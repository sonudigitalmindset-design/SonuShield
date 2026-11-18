# Changelog

All dates are commit dates. SonuShield is a fork of 41Baloo's balooProxy
(GPL-3.0); the upstream project and its license/attribution are preserved —
see [LICENSE](LICENSE) and the credits endpoint. This changelog covers the
SonuShield work only; upstream history before the fork point is in the git
log.

## Baseline — balooProxy v1.5 (upstream)

The fork point: a Go reverse proxy with staged bot mitigation (cookie
redirect, proof-of-work, captcha), TLS fingerprinting, firewall rules,
Cloudflare mode, a terminal HUD, and a Discord webhook. All SonuShield work
below builds on that base without changing the `/_bProxy/` prefix, cookie
names, or challenge flow semantics.

## 17 November 2026

### Phase 1 — Modernization (`600c113`, `11d43d8`)

- Go 1.24 toolchain, updated dependencies, multi-stage Dockerfile.
- Removed a committed build artifact (`oryxBuildBinary`) and ignored it.

### Rebrand to SonuShield (`267eb03`–`609f148`)

- Module renamed to `sonushield`; user-visible strings rebranded.
- README rewritten; dead images/links fixed.
- Fingerprint lists and version info fetched from the SonuShield repo.
- Removed the committed default TLS certificate/key; added a dev
  certificate generator. (The old cert/key remain in git history — see
  [History Review](docs/history-review.md). Never reuse them.)

### Dashboard v1 (`2ff017a`, `8a6580c`)

- Read-only web monitoring dashboard; documented in the README.

### Docs split (`ccfb9b7`–`f915993`)

- Animated SVG diagrams for the docs; README content split into focused
  pages; README reduced to a minimal landing page.

### Batch 1 — Fingerprinting, challenges, reputation

- JA4 fingerprinting and refreshed fingerprint lists.
- Adaptive proof-of-work difficulty.
- Turnstile/hCaptcha challenge option (plumbing; keys are the operator's).
- Geo/ASN firewall rules via an operator-supplied GeoIP database.
- IP reputation: local blocklist + optional feed.
- WAF-lite request inspection, log-only by default.
- Automatic TLS certificates via Let's Encrypt.
- Quiet mode for visitor-facing output (`proxy.quietMode`).
- Authenticated API actions for the new feature controls.

### Batch 2 — Observability

- Prometheus metrics endpoint, disabled by default.
- Telegram and email alerts alongside Discord.
- Attack reports with JSON/CSV export.
- Optional structured JSON logging with rotation.

### Control panel

- Atomic `config.json` persistence for dashboard edits.
- Stage, log-clear, domain list/config, and firewall-rule CRUD API actions
  with validation.
- Validated safe reload via the API `RELOAD` action (`SafeReload`); the raw
  reload path stays terminal-only.
- Dashboard UI for stages, rules, settings, logs, reports, and reload.

### Batch 4 — Edge, backends, API protection

- HTTP/2 fingerprint from observable signals only (frame-level signals are
  not exposed by Go's server stack — documented, not invented).
- Honeypot decoy endpoints; fake search-bot verification via reverse+forward
  DNS; tarpit delay for confirmed-bad requests.
- Edge caching with API purge; waiting room for traffic spikes.
- Load balancing, failover, health checks, stale-cache fallback.
- WebSocket proxying with configurable idle timeout.
- API protection: JWT, API keys, GraphQL limits.
- API roles (viewer/operator/admin) + audit log.
- Config rollback: rotating backups, list/restore API, dashboard UI.
- Rule simulator + per-domain dry-run mode, dashboard UI.
- Firewall rule export/import, dashboard UI.
- Fix: expired cache entries retained for the stale fallback.

> Batch 3 (multi-server/Redis state sharing, HTTP/3, Cloudflare API
> integration, ML classification) needs the operator's servers and was
> sequenced last; it is not part of this changelog yet. See
> [Roadmap](docs/roadmap.md).

## 18 November 2026

### Batch 5 — Scoring, hardening, tenancy

- Composite risk score (`ip.risk` rule field, logs, reports).
- sh1 HTTP fingerprint extended with client-preference signals (section d).
- Cross-domain reputation sharing (opt-in per domain).
- Timing and velocity detection (log-only by default, opt-in enforcement).
- Per-session rate limits keyed to the challenge cookie.
- Slowloris per-IP connection cap + request-smuggling guard.
- Payload size limits (proxy default 32 MiB, per-domain and per-route).
- Origin-lock shared-secret header (config-file-only secret).
- Security headers + per-domain CORS; invalid config fails closed.
- IP allow/block lists with expiry, API actions + dashboard UI.
- Custom challenge-page templates + Hindi pages (English byte-identical).
- Log search + attack map (JSON-log backed, GeoIP-gated).
- Opt-in public status page, minimal data only.
- Multi-tenancy + metering, tenant-scoped API roles.
- GitOps config-as-code sync via validated `SafeReload`.
- SSO/OIDC login for the dashboard; scrubbing-center integration hooks
  (documented honesty limits only — no scrubbing capacity is claimed).

### Batch 6 — Performance, packaging, platform features

- Fix: authenticated API/dashboard requests exempt from the challenge flow.
- Post-quantum TLS (X25519MLKEM768) verification + opt-out; ECH documented
  as unavailable (Go's stdlib has no ECH support — no code pretends
  otherwise).
- QUIC fingerprint field reserved, inactive until HTTP/3 (Batch 3).
- Memory-hard Argon2id Stage-2 puzzle; challenge rotation across attack
  waves; Brotli compression + image optimization; origin pooling + stampede
  guard — all off/inert by default.
- Precompiled edge-rules engine, evaluated before the general rules.
- First-run setup wizard (web-based, localhost-only, never overwrites).
- Domain templates + validated bulk import (JSON/CSV, all-or-nothing).
- CLI subcommands, Helm chart, checksum-verified install script.
- Dashboard Hindi/English toggle + app-shell-only PWA.
- WhatsApp/SMS alerts via the operator's Twilio-compatible account.
- White-label operator branding for dashboard + challenge pages.
- Stripe usage-based billing hooks for multi-tenancy.
- Versioned public API v1 + Go/Python SDKs.
- Signed event webhooks + SIEM export formats.
- Backup export + validated restore/migrate (secrets redacted by default).

### Batch 7 — Detection, operations, privacy

- Passive OS fingerprinting from TCP_INFO signals only (TTL/DF unavailable
  — documented).
- Mouse/scroll behaviour signal on challenge pages; canary tokens; invisible
  markers on challenge pages only.
- Fair queuing with round-robin admission; shadow mode for rules and WAF
  patterns.
- HMAC signed URLs + hotlink protection; form spam guard for POST endpoints.
- Latency/TTFB tracking + SLA reporting; attack timeline + auto-generated
  postmortem; security grade scan (configuration audit).
- Certificate-expiry + subdomain monitoring alerts (no CT-log lookup).
- Scheduled rules + maintenance windows.
- Community rule packs (operator-supplied only; none bundled).
- Cloudflare firewall-rule import with dry-run preview (mock-tested only).
- Privacy mode (stored-PII minimization).
- Two-person approval for sensitive control actions.
- Dashboard controls for insights, approvals, maintenance, packs, and
  Cloudflare import.
- Fix: `ip.os`, `ip.tcpinfo`, `ip.behavior` registered with gofilter.
- Fix: log ring cap no longer tied to terminal height (`GET_LOGS` returned
  nothing without a TTY).

### Batch 8 — API security, integrations, validation

- Mobile app attestation (JWT-form integrity tokens on API paths).
- Passkey (WebAuthn assertion) challenge as a captcha alternative.
- Credential-stuffing detection (per-IP + distributed, log-only default).
- Session-hijack detection (two-signal rule, log-only default).
- OpenAPI request validation (JSON specs, per-route log/block).
- DLP scanning (operator patterns, redact/block, no matched content logged).
- CSP report collector (legacy + Reporting API, dashboard view).
- Threat-sharing network (HMAC peer exchange, opt-in, fail-open).
- BGP alerts (RIPEstat + custom source, fail-open, transition alerts).
- Live log tail (SSE, role auth, dashboard view).
- Synthetic checks (transition alerts, latency thresholds, no attack-stat
  pollution).
- RUM beacon (timing buckets only, operator-embedded snippet, dashboard view).
- On-call rotation (schedule resolution, responder routing, escalation, ACK API).
- Visual rule builder (field/operator/value pickers, server-side validation).
- Origin-signal endpoint + WordPress plugin + hosting-panel client
  (untested in real WordPress/panel environments).
- nginx/Apache import (dry-run preview, nothing silently dropped, dashboard panel).
- Cache analytics + selective purge (path, prefix, tag).
- Detailed config validator + CI workflow (build, vet, validate).
- Fix: CSP collector accepts camelCase Reporting API bodies.

### Platform model — separate control plane

- Control-plane config model, dashboard-mode values, caller-identity
  plumbing.
- Control-plane server: accounts (bcrypt), login, node API proxy.
- OIDC SSO on the control host.
- Dashboard on the control host with the shared UI (node switcher, Accounts
  view).
- `dashboardMode` flag on the proxy (`local` / `control-plane` / `off`).
- Node Host-header routing + v2 response-key alignment (found by the live
  harness).
- Login exists only on the control-plane listener — no `/admin`, `/user`,
  or `/login` paths on protected domains.

### Animation refresh

- Eased SMIL motion language across all docs diagrams.
- Dashboard motion: theme easing, view entrances, loading shimmer, bar
  growth (reduced-motion honored).
- Challenge pages: soft entrances, breathing loader dots, eased controls
  (CSS-only, no JavaScript behaviour changes).
- Motion was never visually verified (no headless browser in the build
  environment) — it needs an eyeball on the live pages.

### Sale-readiness

- Security audit fixes: `GET_IP_CACHE` admin-only + count-only (H-1);
  bounded API v1 body reads (H-2); same-origin redirect sanitizer (M-1,
  later hardened against backslash/control-byte bypasses); opt-in backend
  TLS verification (M-2); escaped 5xx error pages + sandboxed iframe (M-3);
  `HttpOnly` on the Stage-1 cookie (M-4); rule-pack directory confinement +
  guarded URL fetches (M-5); tenant approval scoping (M-6); constant-time
  secret comparison (L-1); SSRF guard on API-influenced outbound URLs
  (L-3); `CacheIps` hourly expiry (L-4). See
  [Security Audit](docs/security-audit.md).
- Follow-up audit pass over the platform-model and animation commits: no
  new findings.
- Pre-existing bug fixes: stdin-EOF CPU spin in the monitor command loop;
  `:80` redirect dropping the query string; IPv6 clients showing as `[`.
- Committed Go test suite (47 tests, 7 packages); `go test ./...` in CI.
- Load generator committed as `tools/bench/`; benchmark docs with VM-local
  numbers and server-run instructions.
- Architecture documentation + request-pipeline schematic.

## Known limitations (carried forward)

- Live GeoIP, Turnstile/hCaptcha, and ACME flows are unverifiable without
  operator keys and a real domain; Docker builds are unvalidated (no Docker
  in the build environment).
- WordPress/panel plugins, the Cloudflare import, and real-IdP SSO are
  mock-tested or untested in real environments.
- Community rule packs: none bundled; the operator supplies their own.
- gofilter rejects quoted IP literals in rule expressions (bare literals
  only) — documented in [Firewall Rules](docs/firewall-rules.md).
- Batch 3 (multi-server state, HTTP/3, Cloudflare API, ML) is not
  implemented; nodes share no runtime state.
- No server is 100% DDoS-proof; see
  [Architecture](docs/architecture.md#honest-limits).
