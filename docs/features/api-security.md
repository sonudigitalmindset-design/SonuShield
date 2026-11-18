# API & Origin Security

Guards for API routes, origins, and the traffic between proxy and backend.

> [← Feature index](../features.md)

Every diagram on this page is an animated schematic: it shows the mechanism in motion, not a screenshot. Diagrams use SMIL animation only, so they animate on GitHub.

<a id="api-protection"></a>

## API Protection (JWT, Keys, GraphQL)

![API Protection (JWT, Keys, GraphQL) schematic](../assets/features/api-protection.svg)

### How it works

API routes get their own guard layer, evaluated per route. **JWT verification** supports HS256 (shared secret) and RS256/ES256 via a JWKS endpoint, using only the standard library; `alg: none` is rejected outright and expired or wrong-audience tokens are refused. **API keys** carry per-key rate limits independent of per-IP limits, so one abusive integration cannot exhaust a shared budget. **GraphQL** requests are measured for query depth and field count as an approximation — documented as not a full parser — so deeply nested queries can be rejected before they reach the origin. Rejections are plain status codes with a short message, logged as block events (`api_jwt` / `api_key` / `api_graphql`); token and key values are never logged.

### Configuration

Flat per-domain keys (no wrapper object): `jwtSecret`, `jwtJWKSURL`, `jwtProtectedPaths`; `apiKeys` array of `{"key", "name", "limitPerMinute"}`, `apiKeyHeader`, `apiKeyPaths`; `graphqlPath`, `graphqlMaxDepth`, `graphqlMaxFields`. Secrets are config-file-only.

### Limits

- GraphQL measurement is an approximation over the query text, not a full parse: exotic queries (fragments, directives) may be measured imprecisely.
- JWT verification checks signature and standard claims only; application-level authorization stays the origin's job.

See also: [Configuration](../configuration.md#api-protection)

---

<a id="mobile-attestation"></a>

## Mobile App Attestation

![Mobile App Attestation schematic](../assets/features/mobile-attestation.svg)

### How it works

API requests from mobile apps can carry an attestation token proving the app is genuine and unmodified. The proxy verifies the JWT's signature (HS256 or via JWKS), issuer, audience, expiry, and the verdict claim. In block mode (the default) a failed verification refuses the request and it never reaches the backend; in log mode the failure is logged and the request passes. Only the JWT form is supported; Apple App Attest's CBOR format is not parsed. Attestation applies to the API routes the operator marks.

### Configuration

Per domain: `attestation` object — `enabled`, `jwksUrl` or `secret`, `issuer`, `audience`, `header`, `paths`, `mode`, `verdictClaim`, `verdictValues`.

### Limits

- JWT form only — Apple App Attest CBOR is not parsed.
- Verified against test tokens only; real devices and production attestation providers were never tested.

See also: [Configuration](../configuration.md#mobile-app-attestation)

---

<a id="openapi-validation"></a>

## OpenAPI Request Validation

![OpenAPI Request Validation schematic](../assets/features/openapi-validation.svg)

### How it works

Per-route request validation against an operator-supplied OpenAPI (JSON 3.x) specification: paths, parameters, and request bodies are checked against the spec, and mismatches are logged or blocked per route. An invalid or unparseable spec fails safe — validation is disabled for that route with a warning, rather than blocking everything. The supported schema subset is documented: `allOf`/`oneOf`/`anyOf`, discriminators, and `format` assertions are not evaluated.

### Configuration

Per domain: `openApi` object — `specFile`, `prefixes`, `mode` (`log` / `block`), and per-route `routes` of `{"prefix", "mode"}`.

### Limits

- Schema subset only: no `allOf`/`oneOf`/`anyOf`, no discriminators, no `format` checks. A spec relying on those will validate loosely.
- Validation measures shape, not semantics: a well-formed but malicious payload still needs origin-side handling.

See also: [Configuration](../configuration.md#openapi-validation)

---

<a id="dlp-scanning"></a>

## DLP Scanning

![DLP Scanning schematic](../assets/features/dlp-scanning.svg)

### How it works

Data-loss-prevention scanning applies operator-supplied regular expressions to backend responses on the way out — running in the response hook before the edge-cache store, so cached copies carry redacted bytes. Only 2xx responses with text-ish content types and no Content-Encoding are scanned, up to `maxScanBytes`. No patterns are bundled — the operator writes every one. The default action is `redact`: each match is replaced with `[redacted]` and ETag/Content-MD5 dropped, since the bytes changed. `block` mode answers the whole response with a generic 403. On a match, only the pattern name and match count are logged: matched content is never logged, stored, or returned. Oversized or encoded bodies pass unscanned (fail-open). DLP deliberately ignores `Cache-Control: no-transform` — redaction is the operator's explicit security policy, not an optimization.

### Configuration

Per domain: `dlp` object — `patterns` (array of `{"name", "regex"}` RE2 patterns), `action` (`redact` default / `block`), `maxScanBytes` (default 1 MiB, clamped 64 KiB–8 MiB). Status via `GET_DLP_STATUS` (counts only).

### Limits

- Regex scanning is pattern matching, not understanding: novel formats and heavy obfuscation evade it.
- Only responses are scanned — request bodies are not. Bodies over the scan cap and encoded bodies pass unscanned.

See also: [Configuration](../configuration.md#dlp-scanning)

---

<a id="csp-reports"></a>

## CSP Report Collector

![CSP Report Collector schematic](../assets/features/csp-reports.svg)

### How it works

The proxy collects Content Security Policy violation reports at `POST /_bProxy/csp-report`, accepting both the kebab-case legacy format and the camelCase Reporting API format. Reports are stored per domain in a bounded store (200 reports per domain; overflow is dropped, oldest first) and are viewable through the API and dashboard. Collection is passive: the proxy never injects CSP headers into origin responses (see Security Headers for the headers the proxy does set).

### Configuration

No configuration keys: the endpoint is always available. Browsers send reports only when the origin's CSP directs them to it.

### Limits

- The store holds 200 reports per domain — a violation flood rotates them quickly. Export reports you need to keep.
- Reports describe what the browser blocked; they are evidence, not enforcement.

See also: [Configuration](../configuration.md#csp-report-collector)

---

<a id="origin-lock"></a>

## Origin Lock

![Origin Lock schematic](../assets/features/origin-lock.svg)

### How it works

Origin lock stops attackers from bypassing the proxy by hitting the origin directly. The proxy adds a shared secret header to every proxied request; the origin is configured to refuse requests without it. The secret is config-file-only — it is never accepted or returned by any API action — so it cannot leak through the dashboard or a config export. Locking only works when the origin actually enforces the check: the proxy side alone proves nothing.

### Configuration

Per domain: `originLockSecret` (config-file-only). The origin-side check is the operator's configuration (web server or application).

### Limits

- The proxy cannot verify the origin enforces the lock — test it by requesting the origin directly without the header.
- If the secret leaks, rotate it in both places at once; there is no grace period for two secrets.

See also: [Configuration](../configuration.md#origin-lock)

---

<a id="security-headers"></a>

## Security Headers & CORS

![Security Headers & CORS schematic](../assets/features/security-headers.svg)

### How it works

The proxy adds security response headers (HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, and friends) and CORS headers on the way out, per domain. Origin-set headers win on conflict: the proxy never overwrites a header the origin already set, so application-specific policies survive. Header injection is wired through the response hook on initial load (a Batch 5 fix corrected the wiring so headers apply from the first request, not only after a reload). CORS is configured per domain with explicit origins — no wildcard-by-default.

### Configuration

Per domain: `securityHeaders` (map of header name → value; an empty map disables the feature), `cors` object — `allowedOrigins`, `allowedMethods`, `allowedHeaders`, `exposedHeaders`, `allowCredentials`, `maxAge`. An absent or invalid CORS config disables CORS for the domain with a warning.

### Limits

- Headers harden the browser's handling of responses; they do not fix origin vulnerabilities.
- HSTS is a commitment: enabling it with a long max-age before HTTPS is solid everywhere can strand visitors.

See also: [Configuration](../configuration.md#security-headers-and-cors)

---

<a id="form-spam-guard"></a>

## Form Spam Guard

![Form Spam Guard schematic](../assets/features/form-spam-guard.svg)

### How it works

Guards form submissions on operator-listed path prefixes with three tripwires: a honeypot field the operator adds to their forms (default name `website`) that humans never fill, a minimum sane fill time (default 3 seconds — submissions faster than that are bots), and a per-IP per-path POST rate cap (default 30 per minute). Mode is `log` by default; `block` mode refuses tripped submissions with a generic response. The guard reads only the named honeypot field and the submission timing — no other form content is inspected or logged.

### Configuration

Per domain: `formGuard` object — `paths` (prefixes), `honeypotField` (default `website`), `minSeconds` (default `3`), `maxPerMinute` (default `30`), `mode` (`log` default / `block`).

### Limits

- The honeypot field only works if the operator adds it to their forms and keeps it hidden from humans.
- Autofill and password managers can submit fast; the 3-second default is a starting point, not a law.

See also: [Configuration](../configuration.md#form-spam-guard)

---

<a id="threat-sharing"></a>

## Threat Sharing Network

![Threat Sharing Network schematic](../assets/features/threat-sharing.svg)

### How it works

SonuShield instances can exchange threat indicators directly, peer to peer, with no central server and no feeds: indicators are HMAC-signed, exchanged over `GET/POST /_bProxy/threat-sharing/indicators`, and carry no PII — only indicator values (IPs, fingerprints, hashes) and their reason. A received indicator adds +1 suspicion to matching requests, never a block. Exchange is fail-open: an unreachable or misbehaving peer changes nothing. Operators choose what to push, including whether canary trips are shared (`pushOnCanary`).

### Configuration

`proxy.threatSharing` object — `enabled`, `peers` (array of `{"name", "url", "sharedSecret"}`), `pullIntervalSeconds` (default `300`, minimum `60`), `pushOnCanary` (bool). Secrets are config-file-only.

### Limits

- A shared indicator is another operator's opinion: +1 suspicion is the deliberate ceiling for foreign data.
- There is no reputation for peers and no revocation list — remove a peer from config to stop trusting it.

See also: [Configuration](../configuration.md#threat-sharing-network)

---

---

[← All features](../features.md)
