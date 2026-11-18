# Security Audit

Two manual security reviews of the SonuShield codebase, both read-only code
review plus targeted live probes against throwaway proxies on localhost. No
production system was probed. This page records what was found, what was
fixed, and what remains as an accepted, documented limitation. It is not a
penetration-test report and makes no claim that the code is free of issues
outside the reviewed scope.

## First audit — 18 November 2026 (code through `bc2588c`)

Scope: all packages, plus two live probes (Stage-1 redirect behaviour and
`GET_IP_CACHE` output). Findings: 2 High, 6 Medium, 5 Low, 0 Critical. All
findings were fixed in commit `289d70c`, except where noted as a documented
limitation below. Each fix was verified live or by a focused test proving the
hole is closed and legitimate flows still work.

| ID | Finding | Fix |
|----|---------|-----|
| H-1 | `GET_IP_CACHE` returned live challenge cookies + full visitor fingerprints to any viewer-role caller (live-confirmed). | Admin-only; returns an entry count only, never keys or values. |
| H-2 | API v1 read request bodies unbounded (OOM by any authenticated caller) and fell through after a body-read error, writing a second response. | Body capped at 1 MiB; the error branch returns. |
| M-1 | Open redirect on the Stage-1 challenge and the challenge / memory-PoW / passkey redirects: `//evil.com/x` redirected off-site (live-confirmed). | Shared `safeRedirectTarget` helper: targets collapse to same-origin relative paths. |
| M-2 | Backend TLS verification disabled on every origin transport, with no way to enable it. | Opt-in per-domain `backendVerifyTLS` (requests, health probes, WebSocket dials). Default stays skip-verify, documented honestly — see below. |
| M-3 | Backend 5xx bodies embedded unescaped in a `srcdoc` iframe (HTML injection in the protected domain's origin). | Body and status HTML-escaped; iframe carries `sandbox=""`. |
| M-4 | Server-set challenge cookies lacked `HttpOnly`. | Added to the Stage-1 cookie (`_1__bProxy_v`), which no script touches. The shared `__bProxy_v` cookie deliberately stays script-writable — see below. |
| M-5 | `IMPORT_RULE_PACK` (operator role) read arbitrary local files and fetched arbitrary internal URLs. | File sources confined to the operator-configured `rulePacksDirectory` (unset refuses file sources); URL fetches refuse non-public destinations. |
| M-6 | A tenant-scoped approver could approve proxy-wide two-person approvals. | Tenant approvers may only approve actions on their own tenant's domains. |
| L-1 | API secret comparison was not constant-time. | `hmac.Equal` for the admin secret and every role secret. |
| L-2 | Challenge-cookie hardening gaps; CDN scripts without integrity checks. | Cookie part fixed via M-4. CDN scripts: see residual risks below. |
| L-3 | Operator outbound URLs had no SSRF guard. | Shared guard in `core/fetch`, enforced where a URL can come from a less-trusted source (pack URLs) or names a fixed public service (RIPEstat). Other operator URLs are deliberately unguarded — see below. |
| L-4 | `CacheIps` entries never expired except under memory pressure. | Hourly TTL sweep on the existing cleanup tick, independent of memory pressure. |
| L-5 | Control-plane login limiter is per-IP only. | No code change. Documented: put the control host behind network allow-listing (see [Control Plane](control-plane.md#security-notes)). |

Checked and found clean in the first audit: role enforcement on all API
actions; tenant scoping in domain actions and approval listing; SSO (PKCE,
state, nonce, claims, JWKS); HMAC verification (waiting room, signed URLs,
webhooks, threat sharing, form guard); passkey/PoW verification; challenge-skip
paths; secret leakage (API responses, audit logs, backups, metrics, dashboard);
no shell execution anywhere; input validation bounds; visitor-side TLS; request
smuggling; config persistence atomicity; `SafeReload` (raw reload never wired to
the API); backend proxying and retry safety; BGP/Stripe/webhook handling; and
the wizard, origin lock, DLP, RUM, and privacy-mode behaviours.

## Follow-up pass — 18 November 2026 (commits `4153e63..783b944` and `9bc6083..644c331`)

The first audit stopped at `bc2588c` (platform model 3/7). This pass reviewed
the remaining platform-model commits (dashboard on the control host, shared UI,
dashboard-mode gating, log-tail proxying, node Host routing, response-key
alignment) and the animation-refresh commits the same way: auth, tenant
scoping, secret leakage, SSRF, injection, and session handling.

**No new findings.** What was checked:

- `core/controlplane/tail.go`: session auth + CSRF required; tenant filtering
  fails closed (unparseable, domain-less, and unknown-domain entries dropped
  for scoped callers); bounded scanner; stream body closed when the client
  disconnects.
- `core/server/dashboardmode.go`: unknown modes fail safe to `off`; the
  control-plane redirect target must be an absolute http(s) URL with a host
  (operator config, validated anyway); the disabled mode answers a bare 404
  with no branding leak.
- Control-plane handlers/nodes/server changes: response-key renames only; node
  Host routing from operator config; PWA shell assets served behind the
  session via exact-match map lookup (no path traversal).
- `core/dashboard/dashboard.go`: the control-plane bootstrap is a hardcoded
  JSON literal injected into a script block; the function documents that
  callers must pass `encoding/json` output, which escapes `<`, `>`, and `&`.
- Dashboard additions (node switcher, accounts view): DOM built with
  `createElement`/`textContent`, and the accounts table escapes every
  account-controlled value (including inside attributes) with the existing
  `esc()` helper, which covers `& < > " '`.
- Animation refresh: CSS-only changes to challenge pages, the dashboard, and
  the docs diagrams. No JavaScript behaviour changed; `prefers-reduced-motion`
  is honored.

## Accepted limitations and residual risks

These are known, deliberate, or not fixable without breaking legitimate use.
Each is recorded here so no one mistakes silence for safety.

- **Backend TLS verification is off by default (M-2).** Historical behaviour,
  kept so private origins with self-signed certificates keep working.
  Operators with origins on untrusted networks should set `backendVerifyTLS`.
  The default is stated plainly in [Configuration](configuration.md#load-balancing-and-failover).
- **The shared `__bProxy_v` cookie is not `HttpOnly` (M-4).** The proof-of-work
  page sets this cookie from JavaScript, and a script cannot overwrite an
  `HttpOnly` cookie — flagging the server-set copies would trap visitors who
  move between challenge types. The Stage-1 cookie, which no script touches,
  does carry `HttpOnly`. The XSS path that could read `__bProxy_v` is narrowed
  by the M-3 escaping + sandbox fix, and the cookie value is bound to
  IP + fingerprint + user-agent + hour.
- **Challenge-page CDN scripts have no subresource integrity (L-2).** The
  Stage-2 page loads the solver from the 41Baloo CDN and `crypto-js` from
  cdnjs. A compromised CDN could ship malicious script to challenged
  visitors. Vendoring the solver is evaluated in the
  [Roadmap](roadmap.md); until then, this risk stands.
- **`/_bProxy/stats` and `/_bProxy/fingerprint` need no secret.** Any visitor
  who passed the challenge can read proxy statistics and their own
  fingerprint. Minor information disclosure, kept by design.
- **Some operator URLs are deliberately not SSRF-guarded (L-3).** Webhooks,
  JWKS/OIDC endpoints, threat-sharing peers, the Cloudflare API base, the
  reputation feed, and custom BGP sources may legitimately live on private
  networks, and all of them are config-file-only — exploitation would require
  control of the config file, which already equals full proxy control.
  Guarding them would break real deployments (internal alert receivers,
  private identity providers, peer proxies, internal mirrors) without
  closing an attacker-reachable hole. The guard is enforced where a URL can
  come from an API caller (rule-pack URLs) or names a fixed public service
  (RIPEstat).
- **Control-plane login guessing (L-5).** Per-IP limiting only; no CAPTCHA or
  second factor. Network allow-listing is the expected control.
- **Pre-existing issues fixed separately.** The monitor's stdin-EOF CPU spin,
  the `:80` redirect dropping the query string, and IPv6 clients showing as
  `[` were fixed alongside this work; see the
  [changelog](../CHANGELOG.md).

## Reporting a vulnerability

This is a public GPL project. Please report security issues through the
repository's issue tracker with a minimal reproduction against a throwaway
config — never against a production proxy — and allow time for a fix before
disclosing details publicly.
