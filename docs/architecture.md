# Architecture

SonuShield is a single Go binary with two modes: the **proxy** (default),
which terminates TLS, classifies visitors, and reverse-proxies to origin
backends; and the **control plane** (`sonushield control`), a separate
management service that never touches visitor traffic. There is no database,
no separate worker process, and no required external service: all runtime
state lives in memory, and all configuration lives in `config.json`.

![Request pipeline schematic](assets/architecture.svg)

## Components

### Proxy mode

| Component | Package | What it does |
|---|---|---|
| Listeners + TLS | `core/server` | HTTPS on :443 with per-domain certificates selected by SNI; HTTP on :80 redirects to HTTPS (Cloudflare mode listens on one port). PQ TLS (X25519MLKEM768) when enabled. |
| Middleware pipeline | `core/server` | One handler per request: client-IP extraction, fingerprinting, rule evaluation, stage machine, challenge serving, cache lookup, and the reverse proxy. |
| Fingerprinting | `core/firewall` | Legacy TLS fingerprint, JA4 (approximated from what Go's TLS stack exposes), sh1 HTTP fingerprint, HTTP/2 fingerprint, passive OS signals, behaviour beacon. Fingerprints are clustering signals, never verdicts on their own. |
| Rule engines | `core/firewall` | General rules (gofilter expressions over `ip.*` / `http.*` / `proxy.*` fields) plus the compiled edge-rule fast path. Both apply the same action semantics: plain integers set the suspicion level and stop; `+N`/`-N` adjust and continue. |
| Stage machine | `core/server`, `core/firewall` | Suspicion levels 0–4 map to stages: 0 passthrough, 1 cookie redirect, 2 proof-of-work, 3 captcha/passkey, 4 block. Thresholds are per-domain; stages switch automatically on request rate unless locked. |
| Challenge pages | `core/server` | Stage-1 redirect + HMAC cookie, Stage-2 proof-of-work (balooPow solver, Argon2id variant, memory variant), Stage-3 built-in captcha, Turnstile/hCaptcha, or passkey. Pages are served from the proxy; no visitor-facing branding unless the operator configures it. |
| Reverse proxy | `core/server`, `core/domains` | Per-domain backend pools with health checks, failover, origin connection pooling, stampede guard, WebSocket pass-through, and optional origin locking. Backend TLS verification is opt-in per domain. |
| Edge cache | `core/domains` | In-memory, per-domain, GET-only, explicit-freshness-only cache with tag/prefix/path purge and a stale-grace fallback when all backends are down. |
| WAF-lite + API protection | `core/firewall`, `core/server` | Request inspection rules, JWT/API-key/GraphQL/OpenAPI validation, DLP scanning, signed URLs, hotlink protection. |
| Control API + dashboard | `core/api`, `core/dashboard` | API v1 (secret in POST body) and v2 (header auth, `results` envelope) for stages, domains, rules, logs, reloads, backups, and reporting. The dashboard is one shared UI served locally, from the control host, or not at all (`dashboardMode`). |
| Monitor / terminal HUD | `core/server` | Live log tail, request counters, and the terminal command loop (`stage`, `reload`, `help`). Terminal-only commands are mirrored by API actions; nothing requires the terminal. |
| Background jobs | `core/server`, `core/*` | Cache sweeps (2-minute tick), certificate expiry checks, reputation-feed refresh, BGP monitoring, synthetic checks, latency/SLA sampling, on-call rotation. |
| Configuration | `core/config`, `core/domains` | `config.json` loaded at startup; `SafeReload` validates before applying (the raw reload path panics on bad input and is never API-wired). Rollback snapshots, GitOps sync, templates, and bulk import/export. |

### Control-plane mode

| Component | Package | What it does |
|---|---|---|
| Accounts + sessions | `core/controlplane` | bcrypt-hashed accounts in a local file, setup-token bootstrap, signed cookie sessions, CSRF tokens, per-IP login limiting, optional SSO. |
| Node proxying | `core/controlplane` | Forwards dashboard API calls to configured proxy nodes over HTTPS with per-node secrets, CA bundles, and Host-header routing. The control host holds node API secrets — its config file is as sensitive as the nodes'. |
| Audit log | `core/controlplane` | Append-only local record of who did what, on which node. |
| Dashboard serving | `core/dashboard` | The same UI as the on-domain dashboard, plus the node switcher and Accounts view. Login exists only here, never on a protected domain. |

## Request lifecycle

1. **TLS handshake.** The listener picks the domain's certificate by SNI
   (unknown SNI is rejected). Fingerprint inputs are captured from the
   handshake: cipher suites, curves, signature schemes, ALPN, TLS version.
2. **IP and identity.** The client IP comes from the peer address (or the
   Cloudflare connecting-IP header in Cloudflare mode). Challenge cookies,
   if present, are verified (HMAC, bound to IP + fingerprint + user-agent +
   hour) and the cached fingerprint is restored.
3. **Fingerprinting.** The legacy fingerprint, JA4, sh1, and HTTP/2
   fingerprints are computed or restored. Geo/ASN lookup, reputation lists,
   and the risk score run here.
4. **Rule evaluation.** Edge rules first, then general firewall rules, then
   WAF-lite. Each match adjusts the suspicion level; a plain-integer action
   stops evaluation.
5. **Stage decision.** The suspicion level selects the stage. A valid cookie
   for the current stage passes through; otherwise the visitor gets the
   stage's challenge page (or the block page at stage 4).
6. **Cache / backend.** Passing requests check the edge cache, then the
   backend pool (healthy backend selection, failover on error, stale-cache
   fallback when every backend is down). Responses flow back through header
   handling, security headers, and logging.
7. **Logging and metering.** Structured JSON logs, per-domain counters,
   attack reports, and tenant metering are updated. Privacy mode masks IPs
   in outputs at this point — raw values never reach logs when it is on.

## Challenge flow

```
Visitor ──► Stage 1: redirect + HMAC cookie (invisible, one round trip)
              │ fail / suspicious
              ▼
         Stage 2: proof-of-work in the browser (balooPow / Argon2id / memory)
              │ fail / suspicious
              ▼
         Stage 3: captcha (built-in / Turnstile / hCaptcha) or passkey
              │ fail / suspicious
              ▼
         Stage 4: block (or tarpit delay, when configured)
```

Stages are per-domain and automatic: rising request rates push the stage up,
and it falls back when traffic normalises. Operators can lock a stage via
the API or terminal. Challenges are the last resort, not the default — a
legitimate visitor with a valid cookie and a clean fingerprint never sees
one. The invisibility rule is a design constraint, not a slogan: quiet mode
suppresses even the challenge-page branding.

## Control plane

The control plane is a separate process on a separate host. It holds no
visitor state and forwards no visitor traffic: it authenticates operators,
serves the dashboard, and proxies management API calls to nodes. Nodes
decide authorization themselves — the control plane forwards the operator's
role and tenant, and each node enforces its own role/tenant scoping — so a
compromised control host cannot widen what a node allows beyond the node
secrets it holds. Node API secrets, the account file (password hashes), and
the session secret are the control host's crown jewels: restrict filesystem
access and put the host behind network allow-listing (see
[Security Audit](security-audit.md)).

## Data stores

Everything is in memory except the files below. A restart or reload loses
runtime state (caches, counters, stage locks, IP lists learned at runtime)
but never configuration.

| Store | Location | Contents |
|---|---|---|
| `config.json` | Proxy working directory | Domains, rules, secrets, feature flags. The single source of truth. |
| Fingerprint lists | `global/fingerprints/` | Operator-populated JA4/sh1/HTTP2 allow/block lists (JSON). Empty by default; no values are invented. |
| GeoIP database | Operator-supplied file | MaxMind-format database for country/ASN lookups. |
| Control-plane config | Control host | Node URLs/secrets, session secret, SSO settings. |
| Account file | Control host | Usernames, bcrypt hashes, roles, tenants. |
| Audit log | Control host | Management actions, append-only. |
| Backups | Operator-chosen location | Versioned JSON envelopes, redacted by default or encrypted with a passphrase. Never contain certificates, GeoIP databases, or template files. |

There is no shared state between proxy nodes: each node keeps its own
caches, counters, and learned lists. Multi-server state sharing (Redis) is
Batch 3 work and is not implemented — see
[Roadmap](roadmap.md). Deploying two nodes behind a load balancer today
means each node challenges independently.

## Trust boundaries

| Boundary | Trust assumption |
|---|---|
| Visitor → proxy | Nothing. Every header, cookie, body, and TLS signal is attacker-controlled until verified. All parsing is bounded; all outputs are escaped or sandboxed. |
| Proxy → backend | Semi-trusted. Backend responses are proxied, not executed — except the 5xx error page, which escapes the body and sandboxes the iframe. Backend TLS verification is opt-in; on untrusted networks, turn it on. |
| Operator → config file | Full control. Anyone who can write `config.json` (or the control-plane config) owns the proxy: secrets, rules, webhooks, and outbound URLs all flow from it. Protect the file, not just the API. |
| Control plane → nodes | Node API secrets. A node trusts any caller presenting its secret; the control host must be guarded accordingly. |
| Proxy → outbound services | Operator-configured URLs (webhooks, JWKS, threat-sharing peers, feeds). Config-file-only by design; the SSRF guard covers only URLs an API caller can influence or that name a fixed public service. See [Security Audit](security-audit.md). |

## Honest limits

These are properties of the design, not bugs to be fixed in a later batch:

- **Single-server volumetric ceiling.** SonuShield runs on one server (or
  several independent ones). A flood large enough to saturate the server's
  link or CPU cannot be absorbed no matter how good the filtering is —
  packets the link cannot carry never reach the proxy. Volumetric defence
  needs upstream capacity (provider mitigation, anycast, scrubbing). What
  SonuShield does well is application-layer filtering: telling real visitors
  from bots once traffic reaches it.
- **Layer 7 only.** No L3/L4 mitigation, no SYN-cookie tuning, no BGP
  blackholing of its own. BGP monitoring watches announcements; it does not
  change routing.
- **Fingerprint approximations.** Go's TLS stack does not expose the raw
  ClientHello, so JA4 extension lists are approximated and will not match
  external JA4 databases. HTTP/2 frame-level signals (SETTINGS order,
  PRIORITY) are not exposed to handlers at all. Both fingerprints are
  clustering signals within SonuShield, not forensic identifiers.
- **No machine learning.** Risk scoring is fixed documented weights, not a
  trained model. It ranks; it does not learn, and it never proves a request
  malicious or safe.
- **Proof-of-work is economics, not proof.** PoW raises the cost of
  automated requests; it cannot distinguish a determined attacker with
  cheap compute from a legitimate visitor on a slow device. Difficulty
  adapts, but the trade-off between bot cost and visitor experience is
  inherent.
- **Challenge pages depend on third-party scripts (Stage 2).** The solver
  loads from a CDN today; a compromised CDN could ship malicious script to
  challenged visitors. Vendoring is evaluated in the
  [Roadmap](roadmap.md).
- **No server is 100% DDoS-proof.** Any claim otherwise is marketing.
  SonuShield raises the cost and shrinks the surface; it does not make an
  origin unreachable-by-attack.

## Further reading

- [How It Works](how-it-works.md) — the stage model in operator terms.
- [Configuration](configuration.md) — every config key.
- [Control Plane](control-plane.md) — setup and security notes.
- [Security Audit](security-audit.md) — findings, fixes, residual risks.
- [Benchmarks](benchmarks.md) — measured numbers and how to reproduce them.
- [Roadmap](roadmap.md) — what is planned and what is deliberately not.
