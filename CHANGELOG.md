# Changelog

All dates are commit dates. SonuShield is a fork of 41Baloo's balooProxy
(GPL-3.0); the upstream project and its license/attribution are preserved —
see [LICENSE](LICENSE) and the credits endpoint. This changelog covers the
SonuShield work only; upstream history before the fork point is in the git
log.

## Unreleased — Next-Gen Cyber-Obsidian Design System (SW v18)

- The whole dashboard UI is rebuilt on one strict Cyber-Obsidian
  design system: `--bg-canvas #05070E`, `--bg-sidebar #080B14`,
  `--bg-card rgba(13,18,30,0.78)` + blur 20px, `--bg-input #090D18`,
  `--border-subtle rgba(255,255,255,0.07)`,
  `--border-highlight rgba(255,255,255,0.15)`,
  `--accent-primary #38BDF8`, `--accent-safe #10B981`,
  `--accent-warn #F59E0B`, `--accent-danger #EF4444`,
  `--text-primary #F8FAFC`, `--text-secondary #94A3B8`,
  `--text-muted #64748B` (dark defaults; light mode keeps its own
  tokens and the toggle still works — no theme reset was needed).
- Typography is now one scale everywhere: Plus Jakarta Sans for
  headings/UI (self-hosted, see below), JetBrains Mono for IPs,
  metrics, expressions and logs; H1 22px/700, card titles 14px/600,
  KPI numbers 28px JetBrains Mono tabular-nums, body/table 13px/1.5,
  micro labels 11px/600 uppercase. No stray font sizes remain.
- Layout: sidebar 240px with a glowing cyan 3px active pill, 64px
  glass top bar with 34px header controls, 1680px content width,
  24px outer padding, 20px gaps, 14px card radius, 20px card
  padding; all buttons/inputs 38px high, 8px radius, 13px; primary
  buttons use a blue gradient with a top inner highlight.
- Motion: cards reveal with a 45ms stagger (`cardReveal`, 380ms);
  card hover lifts 3px in 220ms with a cyan top edge and deep
  shadow; every sub-tab family (Firewall, Domains, Settings,
  Reports, Insights) has a sliding neon underline that glides
  250ms to the selected tab; the Connected dot and the active
  Stage badge pulse; toasts and tooltips were re-tokened to the
  new variables (behaviour unchanged).
- Fonts are self-hosted, never a CDN: Plus Jakarta Sans
  Regular/Medium/SemiBold/Bold woff2 (latin subset, OFL) vendored
  under `core/dashboard/fonts/` and served as protected shell
  assets, exactly like the existing JetBrains Mono files; the old
  Inter embeds were removed. The dashboard stays fully
  offline-capable. No API endpoint, element ID, or JS logic
  changed.

## Unreleased — Overview Live Request Flow (SW v17)

- The Overview hero is now a full-width (320px) LIVE request-flow
  diagram (inline SVG, modelled 1:1 on `docs/assets/request-flow.svg`,
  dark theme): two lanes on the left — Real visitor (top) and Bot /
  attacker (bottom) — a dark SonuShield box in the center with three
  rows (TLS fingerprint, Firewall rules, Challenge stage 1–3), Your
  backend top-right, and a red dashed Blocked box bottom-right.
  Arrows: visitor → shield, shield → backend (green), bot → shield,
  shield → blocked (red). The 3D Earth/shield/server scene is retired
  and the Three.js script tag is removed from the page (the vendored
  file stays in the repo, unused by the page).
- Packets are driven ONLY by the 3s poll the dashboard already
  fetches — no new API calls: green packets flow visitor → shield →
  backend at a rate proportional to bypassed rps, red packets flow
  bot → shield → Blocked box at a rate proportional to (total −
  bypassed) rps (each capped at 20/s, max 44 live packets). Packets
  ride the SVG lane paths (`getPointAtLength`), with a 5px glowing
  trail + halo (r=12) + bright core (r=6), so a still frame always shows
  streaks, not dots. Red packets flash the shield on impact and pulse the
  Blocked box; each green arrival pulses a "passed" label at the
  backend. At 0 rps the diagram idles honestly ("Awaiting live
  traffic") — no fake packets are ever shown.
- The Challenge row highlights the CURRENT live Stage (1/2/3 from
  the API); the Blocked box shows the live blocked all-time count
  (total − bypassed). Stage >= 2 or Under Attack glows the SonuShield
  box amber/crimson and shows the floating HUD badge "SHIELD ENGAGED:
  BLOCKING THREATS".
- The "Test Attack Simulation" switch (top-right, labelled
  SIMULATION, dashboard-local visual only — no backend calls, no real
  traffic, no config changes) floods the bot lane with red packets
  (55/s, 40+ live) that all get blocked with a visible shield flash +
  blocked-box pulse, while a small green trickle (1.5/s) still passes.
  OFF returns to live-driven flow.
- The hero keeps the same renderer reporting, now for the flow:
  `console.info("[SonuShield] flow renderer: svg-live | svg-live-step
  (reduced-motion) | svg-static (reason)")` + `data-flow-renderer` on
  `#heroShield`. If the packet engine fails, the static diagram + CSS
  shine still show — never a blank box. All motion is transform/opacity
  only and pauses when the tab is hidden; under prefers-reduced-motion
  the packets step once per poll tick instead of animating smoothly.
- KPI counter tweens (exact landing), the neon Requests chart +
  scanline, card hover shimmer, and drawer slide-ins are unchanged.

### Live request-flow engine fix (SW v17)

- Bug: zero packets moved on any lane even at 7,245 rps / 0 bypassed.
  Root cause: `flowTick` stopped the rAF loop permanently whenever
  `document.hidden || reducedMotion` was true, with no restart path —
  and `reducedMotion` is a one-time `matchMedia` flag that is on for
  many phones/desktops, so the engine died on its very first frame. A
  second kill path: any exception inside the tick body happened before
  the `requestAnimationFrame` line, so one bad frame killed the loop
  forever.
- Fix: the loop is now exception-proof (tick body in try/catch, rAF
  always rescheduled in a finally); reduced-motion never kills the
  engine — it switches to step mode, where `flowPollStep()` advances
  packets one discrete jump per 3s poll tick; `startFlow()` is called
  defensively when Overview becomes visible, on connect, and after
  every successful poll, and a stall watchdog restarts the loop if no
  frame advances for 10s while visible. Packets are also bigger and
  brighter (5px trail, r=12 halo, r=6 core) so a still frame at high
  rps shows a dense stream. Spawn math, lanes, caps, badges, sim, and
  the idle state are unchanged.

### Final UI/UX polish pass (SW v17)

- Number stability: a shared `.num` class (`font-variant-numeric:
  tabular-nums`, plus the same rule on chart SVG text and all table
  cells) is applied to every live metric, KPI counter, CPU/RAM number,
  latency/TTFB number, bar value, and numeric table cell, so digits no
  longer jitter or shift horizontally during the 3s live updates.
  Counting logic is untouched — CSS only.
- Glass tooltips: a subtle `(?)` info icon now sits next to Bypassed
  requests (Overview), Stage 1/2/3 (Stage view), Adaptive proof-of-work
  and Rules dry-run mode (Settings). Hover, keyboard focus, or tap
  shows a floating dark-glass tooltip with a plain-language explanation
  (verified against the code: bypassed = passed without a challenge;
  stages = cookie / JS proof-of-work / captcha, escalating; Adaptive PoW
  scales puzzle difficulty with bypassed requests per second between the
  configured bounds; dry-run only logs matches, never blocks). New i18n
  keys `tipBypassed`, `tipStage`, `tipAdaptivePow`, `tipDryRun`,
  `infoAria` (en+hi).
- Glass toast notifications: a bottom-right toast system (dark glass,
  green check / red alert SVG icons, auto-dismiss in 4s with a progress
  bar, hover pauses the timer, close button, `aria-live="polite"`) now
  confirms settings saved, rules created/updated, and config reloaded.
  The inline status lines and the error banner are unchanged — errors
  still persist inline; toasts are for success confirmations only.
  There were no `alert(` calls in the dashboard to replace. New i18n
  keys `configReloaded`, `toastDismiss` (en+hi).
- Better empty states: the traffic/CPU/RAM chart empty states and the
  top-IPs/tables "No data in this window yet" box are now a centered
  minimal indicator — a pulsing emerald radar dot + "Sensor active —
  awaiting traffic" (new i18n key `sensorActive`, en+hi). Same element
  IDs and show/hide logic; zero traffic still shows zero, nothing is
  faked. Other "nothing configured yet" states (no rules, no domains,
  no backups…) keep their specific messages.
- Refined spacing & contrast: `.card` and `.panel` padding is now a
  consistent 20px everywhere; dark-mode borders were already exactly
  `1px solid rgba(255,255,255,0.08)` via `--border` (verified, kept),
  light mode keeps its own crisp `#e2e8f0` border; hover transitions on
  buttons, table rows, and sidebar links are now a uniform 150ms
  (`--dur-fast`), inside the design system's 150–300ms range.

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
- Clean-history review: full-history scan (265 commits, 1,358 blobs) with
  values redacted; `.gitignore` hardened against committing live configs,
  account files, and audit logs.
- balooPow evaluation: the solver repository carries no license, so
  vendoring is not permitted — the CDN dependency stands, documented in
  the [Roadmap](docs/roadmap.md).

### Batch 3 — Multi-server, HTTP/3, Cloudflare auto-UAM, ML evaluation (`333e1e3`, `d779c8c`, `1279f90`, `454bdac`, `b5fc9d0`, `2bbacc0`, `c55c31b`)

- Hardening: `applyRuleAction("")` can no longer panic on an empty
  action (safe no-op, evaluation continues).
- Optional Redis-backed shared rate-limit counts + challenge-result
  cache (`proxy.redis`, off by default, fail-open; go-redis v9 pinned
  to the Go 1.24 ceiling). Verified against miniredis + one live
  node; real Redis + two live nodes still pending. See
  [Multi-Server](docs/multi-server.md).
- HTTP/3 + QUIC fingerprinting (`proxy.http3`, off by default;
  quic-go v0.59 pinned to the Go 1.24 ceiling). The reserved `ip.quic`
  rule field carries real observed data only; unobservable signals
  are documented, not guessed. Verified by an in-process end-to-end
  test (UDP is blocked on the build VM); socket delivery and browser
  interop untested. See [HTTP/3](docs/http3.md).
- Cloudflare auto Under Attack Mode (plumbing only, per-domain,
  config-file-only token): raises the zone security level while an
  attack is detected and restores it after. Verified against a mock
  Cloudflare API; no real API call made. See
  [Cloudflare Auto-UAM](docs/cloudflare-auto-uam.md).
- ML anomaly evaluation: offline evaluation of a z-score detector
  over existing signals (`tools/ml-eval`), beating the
  count-threshold baseline on synthetic harness traffic under a
  pre-registered rule (test F1 0.842 vs 0.710, precision 1.000).
  The evaluated detector shipped as an experimental, log-only,
  off-by-default signal (`proxy.anomalyDetection`) with the
  evaluation's constants baked in and the synthetic-data caveats
  stated. See [ML Evaluation](docs/ml-evaluation.md).
- Release workflow fix (`5f3a25e`, separate commit): `contents: write`
  permission + maintained release action; the release job is green
  again.
- Dashboard connect fix: the API-secret field is a visible text field
  (not password-masked) so paste mistakes are visible and password
  managers stop interfering; pasted values are trimmed, interior
  whitespace is rejected with a specific hint, and a failed connect
  now reports how many characters were sent. Service-worker shell
  version bumped to v2 so browsers pick up the new shell.
- API-secret header fix (dashboard Connect never worked in any
  browser): the secret was sent as a `Proxy-Secret` header, but the
  Fetch Standard forbids page script from setting any header starting
  with `proxy-` or `sec-`, so browsers silently dropped it and every
  dashboard Connect failed while curl worked. The canonical header is
  now `X-SonuShield-Secret` (dashboard, control-plane node calls,
  panel plugin); the server still accepts the legacy `Proxy-Secret`
  spelling for scripts and older clients. See [API
  Reference](docs/api.md).
- Dashboard redesign (original enterprise console layout, light theme
  now the default): slimmer top bar, grouped sidebar navigation,
  compact stat row, dense tables with shaded headers, 1px-border
  cards, and system fonts only — no external resources, no copied
  branding. All views, IDs, and translations are unchanged. The
  Overview gains one addition: a lightweight SVG traffic sparkline
  drawn only from the totals the existing 3s poll already fetches
  (no new API calls). Service-worker shell bumped to v4 so browsers
  pick up the new shell.
- Theme migration: browsers that saved the old dark default now get
  the new light default once (a one-time versioned reset of the saved
  theme choice); afterwards the Dark/Light toggle works as before and
  the explicit choice is respected. Service-worker shell bumped to v5.
- Dashboard fixes + skill-guided redesign (UI/UX Pro Max,
  "Accessible & Ethical" system): (1) a `[hidden]{display:none!important}`
  rule so the `hidden` attribute is no longer defeated by flex display
  rules — the control-plane-only Accounts nav item and Node dropdown
  no longer leak into the local dashboard; (2) the Accounts view is
  guarded in local mode — instead of fetching the control-plane-only
  endpoint and showing an empty error, it explains that accounts are
  managed on the control-plane host; (3) the four `errApiPrefix`
  call sites now concatenate the message instead of passing it as an
  unused `t()` argument, so API errors show their real detail (a full
  audit found this was the only placeholder mismatch). Visuals follow
  the persisted design-system tokens exactly in light mode (navy
  #0F172A, blue CTA #0369A1, #F8FAFC background) with a same-family
  dark adaptation; 4px radii, dense spacing, crisp 1px borders, and
  error boxes restyled as card-background with a red left bar. The
  top bar no longer wraps at desktop widths. Motion follows the
  skill's "Stagger List" preset translated to CSS (250-300ms
  entrances, 30ms stagger) plus a one-time sparkline draw-in; all
  motion respects prefers-reduced-motion. Service-worker shell
  bumped to v6.

### Full visual overhaul (UI/UX Pro Max, "Accessible & Ethical" system)

- README restructured as a trust-first landing page (hero, proof
  table with verified numbers only, capability overview, quick
  start, docs index); no invented stats, testimonials, or logos.
- Docs: uniform header pattern (title, purpose, nav line) across
  all 29 pages; plain callouts converted to GitHub alert callouts;
  stale roadmap wording fixed (the banner claimed Batches 7–8,
  sale-readiness, and 3 were unimplemented; all are implemented,
  and the test count is now 76 tests / 11 packages). No technical
  fact changed without verification against the code.
- Diagrams: the skill-token color pass covers all 128 SVGs (hero
  banner, architecture, flagship attack-defense journey, and the
  114 feature schematics). Only hex colors changed — geometry,
  text, and all SMIL animations are untouched, verified by valid
  XML + identical animation counts + before/after frame renders.
  Dark-background elements keep light-blue accents so they stay
  visible; warning amber, status greens, and the destructive red
  keep their meanings.
- Visitor-facing pages (challenge, memory-PoW, captcha, passkey,
  provider verification, waiting room, backend errors,
  maintenance): skill tokens, system font stacks, visible focus
  states. Still generic and unbranded, quiet-mode behaviour
  unchanged, all JavaScript and Go template placeholders
  identical, no new external requests.
- Operator-facing pages (control-plane sign-in/setup, SSO failure
  pages, setup wizard): same token system, 4px radii, visible
  3px focus rings, 200ms control transitions. Branding and the
  orange shield mark are unchanged; auth, CSRF, placeholders, and
  redirects are untouched.
- Dashboard consistency pass only: the traffic chart now always
  renders its axis and gridlines, so a zero-traffic chart reads
  as a working chart at zero instead of a broken one; the
  attack-map grid lines use the slate token so they stay visible
  in both themes. IDs, translations, secret-header sends, and the
  theme-migration bootstrap are unchanged. Service-worker shell
  bumped to v7.
- Visual verification: none of this was eyeballed on the build VM
  (no browser for screenshots); the rendered-frame checks above
  verify structure and motion, not taste. The live pages still
  need an eyeball.

### Dashboard real-time graphs (UI/UX Pro Max chart guidance)

- Overview: the requests sparkline is now a full real-time chart
  (labelled requests/sec axis, time axis, 60-sample / 3-minute
  history, legend with dash-differentiated series, designed empty
  state, one-time draw-in). New server-load panel: CPU and RAM
  percent-over-time charts on a fixed 0-100% scale with now/min/max
  summaries, fed by the proxy stats the 3s poll already fetches.
- More graphs from already-loaded data, no new API calls: bars for
  requests per second by domain and requests by tenant; bars above
  the attack report's blocks/challenges/WAF count tables; RUM
  average-time-per-phase bars; latency percentile bars (TTFB vs
  total); an RPS-vs-allowed line chart on the attack timeline; and
  shadow-outcome bars. Views with no in-page series data (rules, IP
  lists, stage, settings, approvals, accounts, about) intentionally
  got none, and the attack map, grade, and certificate tables were
  left as adequate. All charts use the skill tokens, viewBox
  scaling, and the existing reduced-motion guard; chart legibility
  at real widths is unverified by eye (no browser on the build VM).
  Service-worker shell bumped to v8.

### Dashboard Cyber-Dark redesign (UI/UX Pro Max dark-dashboard guidance)

- Theme: Cyber-Dark is now the default (`#090D16` canvas, `#111827`
  elevated cards; one-time migration v3 so returning users see it
  once, an explicit toggle afterwards is still respected). Light
  mode stays fully functional. Cards and panels get a glass top
  highlight, multi-layered soft shadows, and a `translateY(-2px)`
  hover-lift on metric cards; status pills and stage badges glow
  subtly. Content width is now 1600px, so wide monitors keep no
  empty right margin.
- Overview: 12-column grid — KPI row (requests, bypassed, CPU/RAM
  with radial mini-gauges, stage badge), full-width requests area
  chart (now with a gradient fill under the line), server-load
  charts, then Top IPs and Unknown Fingerprints split 50/50. A new
  hero banner carries a custom isometric shield/node graphic that
  pulses emerald while connected and calm, amber under attack or at
  Stage 2, red at Stage 3+, grey while disconnected — driven only
  by the connection/stage state the page already tracks.
- Firewall page: Active Rules table is the main view with a primary
  "+ Create Firewall Rule" button; Add-a-Rule and the Visual Rule
  Builder now live in a slide-over drawer (Visual Builder / Raw
  Expression toggle inside; Escape, backdrop click, and the close
  button all close it; editing a rule opens the drawer on Raw).
  Simulator, Rule Packs, and Import & Export are sub-tabs at the
  top of the page. All forms, IDs, and JS logic are unchanged; tab
  switching is show/hide only.
- Typography: Inter for UI labels and JetBrains Mono for IPs,
  firewall expressions, hostnames, and live counters — both
  self-hosted as OFL latin-subset woff2 files embedded in the
  binary and served as protected shell assets (no CDN, no new
  public routes; +80,908 bytes of fonts). Lucide-style icons are
  hand-inlined SVG paths; no icon library. Service-worker shell
  bumped to v9.
- Fix (19 Nov): the Active Rules panel was missing its closing
  `</div>`, so the Simulator, Packs, and Import & Export panels
  were nested inside it — switching to any of them hid the whole
  Firewall page. One closing tag added; the page is now
  tag-balanced. Service-worker shell bumped to v10.

### Dashboard refactor: Domains, Settings, Reports, Insights

- Container is now `max-width:1680px` centered, so wide monitors keep
  no dead right margin. Cards and panels are translucent glass
  (`#111827` at 90% with `backdrop-filter: blur(12px)`) with the
  existing top-edge inner glow and layered shadows.
- Domains: `+ Add Domain` opens a slide-over drawer with the existing
  "New domain from template" form (closes on successful create, as
  the rule drawer does); three sub-tabs — Configured Domains &
  Inspector (default), Tenants & Usage, Bulk Import (JSON / Nginx /
  Apache in a 2-column grid). Clicking a domain opens a split-view
  inspector: metrics and config summary on the left, quick actions
  (edge-cache purge) on the right, from the same loads as before.
- Settings: four sub-tabs — Traffic & Attack Thresholds, WAF &
  Proof-of-Work, System & Proxy Features (status values now render
  as badges), Config Backups — plus a sticky bottom action bar that
  appears when a field changes and calls the existing Save / Reload
  handlers; it hides again once values are freshly loaded.
- Reports: the four KPI cards keep their values and gain glowing
  icons; the middle row is a 7/5 grid with the attack map (now with
  a theme-aware ocean disc behind the globe) beside Challenges by
  Stage + Backend Health; the six data tables share one tabbed card
  so empty states stop wasting vertical space.
- Insights: hero row splits 4/8 — a radial-gauge Security Grade card
  (live grade and score drive the ring; emerald for A/B, amber for
  C, red for D/F, never a hardcoded grade) beside Latency & SLA
  telemetry with p50/p95/p99 pills. Deep diagnostics are sub-tabs:
  Configuration Audit Checklist (All / Warnings / Passed filter
  pills), Attack Timeline & Postmortem, Shadow Report & RUM, and
  Certificates & Subdomains.
- No IDs, data attributes, API calls, form handlers, or JS state
  logic were renamed or rebuilt; sections were moved, renderers
  split across existing containers. Service-worker shell bumped to
  v11.

### Dashboard visual-engine overhaul (command-center presentation)

- Deep obsidian background (`#050811`) with an animated ambient
  mesh (cyan/emerald/indigo radial glows, transform/opacity only,
  paused when the tab is hidden); frosted glass panels
  (`rgba(15,23,42,.65)`, `blur(16px)`, specular top/left borders).
  Light mode is re-tokened, not removed; default stays dark (no
  theme-migration bump). All new motion sits inside the existing
  prefers-reduced-motion guard.
- Overview hero: the static shield SVG is replaced by a vanilla
  `<canvas>` wireframe globe with two orbital rings and satellite
  dots — pulsing emerald while connected, crimson when under attack
  or at Stage 2+, dim grey while disconnected; rAF pauses when
  hidden or under reduced-motion. KPI cards and hero panels get a
  pointer-only 3D tilt (max ~6deg) plus a cursor spotlight, and
  numbers count up smoothly (380ms ease-out) instead of jumping.
  Switching views replays a staggered fade-up entrance
  (`cubic-bezier(0.16,1,0.3,1)`).
- Toggle switches (visible pill controls syncing both ways with
  the underlying `<select>`s, which are kept in the DOM): a
  Sun/Moon theme switch in the top bar; an Under-Attack master
  switch with a confirmation pulse; Maintenance Override expanding
  its duration/message fields only when ON; the stage selector as
  an animated segmented pill with a sliding indicator; and
  Adaptive PoW, WAF inspect-body, and Dry-run switches in
  Settings. No per-rule enabled toggle exists — firewall rules
  carry expression/action/schedule only, so none was invented.
- IP Lists: Allow and Block render side-by-side in a 2-column
  glass grid (emerald border for Allow, crimson for Block); "Add
  an Entry" now lives in an `+ Add IP / CIDR` drawer with the
  existing form moved verbatim.
- Stage: the three status cards carry animated 3D status rings
  (ok/warn/bad/off) driven by the live stage API; the Stage
  Reference Matrix is a collapsible drawer. Logs: Passed Requests
  and Live Tail now share one real-time terminal console
  (`#030508`, JetBrains Mono, syntax-highlighted fields, blinking
  cursor) with a Live Stream toggle driving the existing SSE tail;
  Search Structured Logs sits above it in a collapsible filter
  bar. Service-worker shell bumped to v12.

### Dashboard: forced obsidian default + real WebGL 3D core (19 Nov)

- Theme-default fix: the page was still opening Light for
  returning browsers because a saved `"light"` choice already
  existed with migration version `"3"`, so the one-time reset
  never fired again — and `applyTheme` fell back to `"light"`
  on any invalid value while `<body>` never received
  `data-theme` at all. Fixed by bumping the migration `"3"`→
  `"4"` (every returning browser resets to dark exactly once),
  making the invalid-value fallback `"dark"`, and setting
  `data-theme` on both `<html>` and `<body>` in the bootstrap,
  in `applyTheme`, and as markup defaults. An explicit Sun/Moon
  toggle afterwards is still respected and persisted.
- Real WebGL 3D core: the Overview hero is now a rotating
  wireframe icosahedron (Three.js) with two counter-rotating
  tilted orbital rings and glowing node particles on a 260x180
  transparent canvas, mouse-parallax tilt, emerald `#10b981`
  when safe/Stage 1 and crimson `#ef4444` under attack. Three.js
  r128 is VENDORED (`core/dashboard/vendor/three-r128.min.js`,
  MIT, REVISION verified as `"128"`), embedded via `go:embed`
  and served as a protected shell asset — the requested CDN
  script tag was deliberately not used (supply-chain risk, and
  it would break the dashboard's offline property). If THREE is
  missing or WebGL fails, the existing 2D canvas globe draws
  instead — never a blank box.
- Forced obsidian: canvas `#04070f` with an animated mesh
  aurora (emerald `#10b981`, cyan `#06b6d4`, indigo `#3b82f6`
  orbs); every card is a frosted glass slab exactly per spec
  (`rgba(13,19,34,.72)`, `blur(20px)`, `1px rgba(255,255,255,.08)`
  border, `1px rgba(255,255,255,.18)` top border, deep drop +
  inner top highlight). Light mode stays fully functional.
- Tilt reconciled to `perspective(900px) ... translateZ(8px)`
  and extended to the domain inspector and the Allow/Block IP
  panels (re-bound after the IP lists render); `transform-style:
  preserve-3d` on tilt elements. View/sub-tab switches now
  replay the staggered `fadeSlideUp` entrance (18px rise +
  `.98` scale, 0.4s, `cubic-bezier(.16,1,.3,1)`). Toggle
  switches get spring transitions
  (`cubic-bezier(.34,1.56,.64,1)`) with a breathing neon glow
  when active; the active sidebar item carries a glowing
  vertical neon bar (`box-shadow: 0 0 12px #3b82f6`).
  Service-worker shell bumped to v13 (+603,445 bytes of
  vendored Three.js in the binary).

### Dashboard: colourful 3D + animation everywhere (19 Nov)

- Globe diagnosis: the user's screenshot showed the hero globe as
  clean lat/long ellipses with two rings — that is the 2D canvas
  fallback drawing, not the WebGL icosahedron (80 triangular
  faces) plus dense halo mesh. The fallback was completely silent:
  any failure (THREE not loaded, no WebGL context, renderer
  exception, reduced-motion) fell back with no log and no visible
  marker. `startGlobe()` now logs
  `console.info("[SonuShield] globe renderer: three-webgl")` or
  `canvas-2d-fallback (reason)` and sets
  `data-globe-renderer` on `#heroShield`, so a running browser
  inspection can confirm which renderer is active. The 2D fallback
  is also upgraded (pulsing glow disc, brighter lines, cyan second
  ring, glowing 5px satellite dots, faster rotation) so it never
  reads as a dead static drawing.
- WebGL core upgraded: canvas 260x180 → 320x220, brighter core
  (opacity 1), second counter-rotating inner icosahedron, glow
  sprite behind the core (canvas-generated radial texture, no
  external asset), thicker orbital rings (tube 0.02), 90 + 30 node
  particles at two depths, faster rotation — the core now reads as
  layered 3D depth in a still screenshot. A breathing glow disc
  sits behind the hero shield in CSS too.
- Aurora fixed: the old orbs (0.12–0.22 opacity, blur 90px) were
  invisible in screenshots, and the opaque top bar/sidebar hid
  them. Orbs are now 0.30–0.38 opacity with a fourth violet orb,
  blur 60px, 36s drift; the top bar and sidebar are translucent
  frosted glass in dark mode so the glow shows through on every
  view. Light mode stays fully functional.
- Colourful 3D glass everywhere: every card family carries its own
  accent — emerald for requests/traffic, cyan for CPU/RAM/server,
  amber for Stage, violet/indigo for security/grade, red only for
  attack/block — as a gradient top edge plus a soft outer glow.
  Sidebar icons are coloured per section with a glowing active
  item; the 900px tilt/spotlight now covers KPI, Domain,
  Allow/Block IP, Stage, Reports KPI, Insights grade/telemetry,
  Settings and About panels. Charts get glowing gradient lines
  (emerald traffic, cyan CPU/RAM), a visible grid, and breathing
  empty states — zero traffic still shows zero, nothing is
  invented. The Connected dot pulses harder; count-up and
  staggered entrances are unchanged. Service-worker shell bumped
  to v14.

## Known limitations (carried forward)

- Live GeoIP, Turnstile/hCaptcha, and ACME flows are unverifiable without
  operator keys and a real domain; Docker builds are unvalidated (no Docker
  in the build environment).
- WordPress/panel plugins, the Cloudflare import, and real-IdP SSO are
  mock-tested or untested in real environments.
- Community rule packs: none bundled; the operator supplies their own.
- gofilter rejects quoted IP literals in rule expressions (bare literals
  only) — documented in [Firewall Rules](docs/firewall-rules.md).
- Batch 3 residuals: real Redis + two live nodes unverified; HTTP/3
  UDP delivery and browser interop untested; no live Cloudflare API
  call made; the anomaly detector's constants come from synthetic
  harness traffic only and are expected to be miscalibrated on real
  traffic (log-only, off by default).
- No server is 100% DDoS-proof; see
  [Architecture](docs/architecture.md#honest-limits).
