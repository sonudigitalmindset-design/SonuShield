# Configuration

`config.json` has two top-level fields: `proxy` (general settings) and `domains` (one entry per protected domain). Firewall rules are configured per domain, under each domain's `firewallRules` — see [Firewall Rules](firewall-rules.md).

## Example Configuration

```json
{
  "proxy": {
    "cloudflare": false,
    "adminsecret": "CHANGE_ME",
    "apisecret": "CHANGE_ME",
    "secrets": {
      "cookie": "CHANGE_ME1",
      "javascript": "CHANGE_ME2",
      "captcha": "CHANGE_ME3"
    },
    "timeout": {
      "idle": 5,
      "read": 5,
      "write": 7,
      "read_header": 5
    },
    "ratelimit_time": 120,
    "ratelimits": {
      "requests": 500,
      "unknownFingerprint": 150,
      "challengeFailures": 40,
      "noRequestsSent": 10
    },
    "colors": ["0", "31"]
  },
  "domains": [
    {
      "name": "example.com",
      "backend": "1.1.1.1",
      "scheme": "http",
      "certificate": "assets/server/server.crt",
      "key": "assets/server/server.key",
      "webhook": {
        "url": "",
        "name": "SonuShield",
        "avatar": "",
        "attack_start_msg": "Attack detected on {{domain.name}}",
        "attack_stop_msg": "Attack on {{domain.name}} has stopped"
      },
      "firewallRules": [],
      "bypassStage1": 75,
      "bypassStage2": 250,
      "stage2Difficulty": 5,
      "disableBypassStage3": 100,
      "disableRawStage3": 250,
      "disableBypassStage2": 50,
      "disableRawStage2": 75
    }
  ]
}
```

A fuller multi-domain example is available in [`examples/config.json`](../examples/config.json). Remember to replace every `CHANGE_ME` secret before starting — SonuShield refuses to start if any secret still contains `CHANGE_ME`.

## Proxy Settings

| Field | Type | Description |
|-------|------|-------------|
| `cloudflare` | Bool | Set to `true` to run behind Cloudflare. See [Cloudflare Mode](how-it-works.md#cloudflare-mode). |
| `adminsecret` | String | Secret used in the v1 API path and in the dashboard URL. Must not contain `CHANGE_ME`. |
| `apisecret` | String | Secret sent in the `proxy-secret` / `Proxy-Secret` API header. Must not contain `CHANGE_ME`. |
| `secrets` | Map[String]String | Challenge secrets with keys `cookie`, `javascript`, and `captcha`. Must not contain `CHANGE_ME`. Generate secure random values, for example with `openssl rand -hex 20` or [random.org](https://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&unique=on&format=html&rnd=new). |
| `timeout` | Object | Connection timeouts in seconds: `idle` (default 5), `read` (default 5), `write` (default 7), `read_header` (default 5). A value of `0` keeps the default. |
| `ratelimit_time` | Int | Window in seconds over which the rate limits below are counted. Values below 10 are raised to 10; defaults to 10 when unset. |
| `ratelimits` | Map[String]Int | Rate limit thresholds (see below). |
| `colors` | Array[String] | ANSI color codes for the terminal HUD, for example `["0", "31"]`. |
| `geoipCountryDatabase` | String | Path to a MaxMind DB (`.mmdb`) Country database for `ip.country` rules. Empty disables country lookups. See [Geo and ASN Rules](#geo-and-asn-rules). |
| `geoipASNDatabase` | String | Path to a MaxMind DB (`.mmdb`) ASN database for `ip.asn` rules. Empty disables ASN lookups. See [Geo and ASN Rules](#geo-and-asn-rules). |
| `reputationBlocklist` | Array[String] | Local IP reputation list: exact IPs and CIDRs, one per entry. See [IP Reputation](#ip-reputation). |
| `reputationFeedURL` | String | URL of an optional plain-text reputation feed, fetched in the background. Empty disables the feed. See [IP Reputation](#ip-reputation). |
| `reputationFeedInterval` | Int | Feed refresh interval in minutes (default `60`, minimum `5`). |
| `reputationSusLv` | Int | Suspicion-level bump applied to listed IPs (default `1`). |
| `autoSSL` | Bool | `true` enables automatic Let's Encrypt certificates for domains with empty `certificate`/`key` fields. Default `false`. See [Automatic SSL](#automatic-ssl). |
| `autoSSLCacheDir` | String | Directory where obtained certificates are cached (default `autocert-cache`). |
| `autoSSLEmail` | String | Optional contact email sent to Let's Encrypt for expiry notices. Empty sends none. |
| `quietMode` | Bool | `true` removes product-identifying strings from visitor-facing output. Default `false`. See [Quiet Mode](#quiet-mode). |
| `metricsEnabled` | Bool | `true` exposes the Prometheus metrics endpoint on the admin-secret path. Default `false` (disabled). See [Prometheus Metrics](#prometheus-metrics). |
| `reportDirectory` | String | Directory that receives one JSON + CSV attack report per finished attack. Empty (default) disables directory export. See [Attack Reports](#attack-reports). |
| `logFormat` | String | `"json"` enables structured JSON logging to `logFile`; `"text"` (default) keeps the existing output. See [Structured Logs](#structured-logs). |
| `logFile` | String | Path of the JSON log file. Required when `logFormat` is `"json"`; without it, JSON logging stays disabled with a startup warning. |
| `logMaxBytes` | Int | Maximum size of the current log file in bytes before rotation (default `10485760`, 10 MiB; values below 64 KiB use the default). |
| `logMaxFiles` | Int | Total log files kept including the current one (default `5`; clamped to `1`–`100`). |
| `apiRoles` | Map[String]String | Additional API secrets mapped to roles (`viewer`, `operator`, `admin`). The main `apisecret` is always admin. See [API Roles and Audit Log](#api-roles-and-audit-log). |
| `configBackups` | Int | Number of rotating `config.json` backups kept (default `5`; clamped to `1`–`20`). See [Configuration Backups and Rollback](#configuration-backups-and-rollback). |

Rate limits (`ratelimits`), counted within the `ratelimit_time` window:

| Key | Description |
|-----|-------------|
| `requests` | Requests a single IP may send before it is blocked. |
| `unknownFingerprint` | Requests a single unknown TLS fingerprint may send before it is blocked. Only applied to clients whose browser could not be identified. |
| `challengeFailures` | Failed challenge attempts from a single IP before it is blocked. |
| `noRequestsSent` | TCP connections opened by a single IP without sending an HTTP request before it is blocked. |

## Domain Settings

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | The domain name, for example `example.com`. Requests are matched by the `Host` header. |
| `scheme` | String | Scheme used to talk to your backend: `http` or `https`. `http` is generally faster and less CPU-intensive. Note: `https` backends are contacted with TLS certificate verification disabled. |
| `backend` | String | Your backend's IP or hostname. You can specify a port, for example `1.1.1.1:8888`. |
| `certificate` | String | Path to the domain's TLS certificate, for example `assets/server/server.crt`. Not loaded in Cloudflare mode. |
| `key` | String | Path to the domain's TLS private key, for example `assets/server/server.key`. Not loaded in Cloudflare mode. |
| `webhook` | Object | Discord alert settings. See [Webhook](#webhook). |
| `telegram` | Object | Telegram alert settings. See [Telegram and Email Alerts](#telegram-and-email-alerts). |
| `email` | Object | Email (SMTP) alert settings. See [Telegram and Email Alerts](#telegram-and-email-alerts). |
| `firewallRules` | Array | Custom firewall rules. See [Firewall Rules](firewall-rules.md). |
| `bypassStage1` | Int | Bypassing requests per second that activate Stage 2. |
| `bypassStage2` | Int | Bypassing requests per second that activate Stage 3. |
| `stage2Difficulty` | Int | Proof-of-work difficulty for Stage 2 (default `5` when `0`). |
| `adaptivePow` | Bool | `true` scales the Stage 2 difficulty with load between `powDifficultyMin` and `powDifficultyMax`. Default `false` (fixed `stage2Difficulty`). |
| `powDifficultyMin` | Int | Adaptive PoW floor. `0` (default) means the base `stage2Difficulty`. Clamped to `1`–`16`. |
| `powDifficultyMax` | Int | Adaptive PoW ceiling. `0` (default) means base difficulty `+3`. Clamped to `1`–`16`. |
| `challengeProvider` | String | `turnstile` or `hcaptcha` to serve that provider's challenge instead of the Stage 2 proof-of-work page. Empty (default) keeps proof-of-work. See [Challenge Providers](#challenge-providers). |
| `challengeSiteKey` | String | The provider site key for this domain. Required when `challengeProvider` is set. |
| `challengeSecretKey` | String | The provider secret key for this domain. Required when `challengeProvider` is set. Never shared or logged. |
| `wafMode` | String | WAF-lite mode: `log` (default, log-only), `block` (generic 403 on match), or `off` (disabled). Unknown values fall back to `log`, never to blocking. See [WAF-Lite](#waf-lite). |
| `wafInspectBody` | Bool | `true` also inspects small POST/PUT/PATCH request bodies (up to 1 MB). Default `false`. |
| `wafWpLoginLimit` | Int | Allowed POSTs per IP per minute to `/wp-login.php` and `/xmlrpc.php` (default `20` when `0`). |
| `disableBypassStage3` | Int | Bypassing requests per second low enough to disable Stage 3. |
| `disableRawStage3` | Int | Total requests per second low enough to disable Stage 3 (bypassing requests must also be low enough). |
| `disableBypassStage2` | Int | Bypassing requests per second low enough to disable Stage 2. |
| `disableRawStage2` | Int | Total requests per second low enough to disable Stage 2 (bypassing requests must also be low enough). |
| `honeypotPaths` | Array[String] | Decoy paths that legitimate visitors never request (exact, case-sensitive match). Hitting one raises suspicion. Empty (default) disables the honeypot. See [Honeypot Endpoints](#honeypot-endpoints). |
| `honeypotSusLv` | Int | Suspicion-level bump for honeypot hits (default `2`). |
| `fakeBotCheck` | Bool | `true` verifies claimed Googlebot/Bingbot user-agents by reverse+forward DNS. Default `false`. See [Fake Search-Bot Verification](#fake-search-bot-verification). |
| `fakeBotSusLv` | Int | Suspicion-level bump for failed search-bot verification (default `3`). |
| `tarpitDelayMs` | Int | Delay in milliseconds applied to confirmed-bad (blocked) requests. `0` (default) disables the tarpit. See [Tarpit](#tarpit). |
| `tarpitSusLv` | Int | Minimum suspicion level the tarpit applies to (default `4`, i.e. blocked requests only). |
| `tarpitMaxConns` | Int | Maximum simultaneous tarpitted connections (default `64`, clamped to `1`–`1024`). |
| `edgeCache` | Bool | `true` enables the in-memory edge cache for safe GET responses. Default `false`. See [Edge Caching](#edge-caching). |
| `edgeCacheTTL` | Int | Maximum cache lifetime in seconds (default `60`). Responses are also bound by their own `Cache-Control`/`Expires` headers. |
| `edgeCacheMaxMB` | Int | Maximum cache size in megabytes (default `64`). |
| `waitingRoom` | Bool | `true` enables the waiting room when bypassed traffic crosses the threshold. Default `false`. See [Waiting Room](#waiting-room). |
| `waitingRoomThreshold` | Int | Bypassed requests per second above which excess visitors are queued (default `0`, i.e. never queues unless set). |
| `waitingRoomAdmit` | Int | Visitors admitted from the queue per second (default `20`). |
| `backends` | Array[String] | Additional backend addresses for load balancing. Empty (default) uses the single `backend`. See [Load Balancing and Failover](#load-balancing-and-failover). |
| `lbPolicy` | String | `round-robin` (default) or `least-connections`. Unknown values warn at startup and use round-robin. |
| `healthCheckEnabled` | Bool | `true` probes backends on an interval and excludes failing ones. Default `false`. See [Load Balancing and Failover](#load-balancing-and-failover). |
| `healthCheckPath` | String | Path probed by health checks (default `/`). |
| `healthCheckInterval` | Int | Seconds between health-check probes per backend (default `10`, minimum `5`). |
| `websocketIdleTimeout` | Int | Idle timeout in seconds for WebSocket connections on the dedicated upgrade path. `0` (default) keeps Go's built-in reverse-proxy upgrade handling. See [WebSocket Support](#websocket-support). |
| `jwtSecret` | String | Shared secret for HS256 JWT validation on protected routes. Empty (default) disables HS256. See [API Protection](#api-protection). |
| `jwtJWKSURL` | String | JWKS endpoint URL for RS256/ES256 JWT validation. Empty (default) disables JWKS. |
| `jwtProtectedPaths` | Array[String] | Route prefixes that require a valid JWT bearer token. Empty (default) disables JWT checks. |
| `apiKeys` | Array[Object] | API keys with per-key rate limits: `{"key": "…", "name": "…", "limitPerMinute": 60}`. Empty (default) disables API-key checks. |
| `apiKeyHeader` | String | Header carrying the API key (default `X-API-Key`). |
| `apiKeyPaths` | Array[String] | Route prefixes that require a valid API key. Empty (default) disables API-key checks. |
| `graphqlPath` | String | Exact path of the GraphQL endpoint (e.g. `/graphql`). Empty (default) disables GraphQL limits. |
| `graphqlMaxDepth` | Int | Maximum GraphQL query nesting depth (`0` = no limit). |
| `graphqlMaxFields` | Int | Maximum GraphQL field count (`0` = no limit). |
| `rulesDryRun` | Bool | `true` logs rule matches without enforcing them. Default `false`. See [Firewall Rules](firewall-rules.md#testing-rules-before-enforcing-them). |

## Geo and ASN Rules

Firewall rules can match on `ip.country` (ISO country code, e.g. `US`) and `ip.asn` (autonomous system number) when MaxMind DB (`.mmdb`) files are configured. No database is bundled: download the free GeoLite2 Country and ASN databases with your own [MaxMind account and license key](https://www.maxmind.com/en/geolite2/signup), then point the two paths at the downloaded files:

```json
"geoipCountryDatabase": "GeoLite2-Country.mmdb",
"geoipASNDatabase": "GeoLite2-ASN.mmdb"
```

The two paths are independent — configure either, both, or neither. When a database is missing, cannot be opened, or has no record for an IP, lookups fail open (`""` / `0`) and rules simply do not match on that field. In Cloudflare mode, the `CF-IPCountry` header supplies the country instead of the database; the ASN still comes from the database. Database files are never committed (see `.gitignore`).

## IP Reputation

A local blocklist plus an optional external feed. Listed IPs get their suspicion level bumped by `reputationSusLv` after firewall rules run, and rules can match on the `ip.reputation` field (`"listed"` or `""`). No list is bundled and no feed is contacted unless configured.

```json
"reputationBlocklist": ["203.0.113.10", "198.51.100.0/24"],
"reputationFeedURL": "https://example.com/blocklist.txt",
"reputationFeedInterval": 60,
"reputationSusLv": 1
```

The feed is plain text, one IP or CIDR per line, with `#` comments (only the first field of each line is read), capped at 10 MB. It is fetched in the background at startup and every `reputationFeedInterval` minutes; startup never blocks on it. On any fetch or parse failure the last good data is kept and a warning is logged — feed errors never block anyone (fail-open). Feed status is visible via the `GET_PROXY_FEATURES` [API action](api.md#proxy-actions), and `REFRESH_REPUTATION_FEED` triggers a refresh on demand.

## Automatic SSL

With `autoSSL: true`, domains whose `certificate` and `key` fields are both empty get certificates automatically from Let's Encrypt (ACME HTTP-01), cached on disk and renewed automatically. Domains with explicit certificate/key files keep using those files, so mixed setups work. The option is ignored in Cloudflare mode, where there is no TLS listener.

Requirements, all on the operator's side:

- Each cert-less domain must resolve in public DNS to this server.
- TCP port 80 must be reachable from the internet: the HTTP-01 challenge is answered on port 80 before the HTTPS redirect.
- [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/) apply (currently 50 certificates per registered domain per week — check the current limits before a large rollout).

Obtained certificates and keys live only in `autoSSLCacheDir` (default `autocert-cache`, git-ignored). Never commit them. A domain with only one of `certificate`/`key` set still fails to load, exactly as without auto SSL.

## Challenge Providers

Instead of the Stage 2 proof-of-work page, a domain can serve a Cloudflare Turnstile or hCaptcha challenge. This needs the operator's own keys from their own provider account — no keys are bundled, and the feature is inert without them. See the [Turnstile documentation](https://developers.cloudflare.com/turnstile/) and the [hCaptcha documentation](https://docs.hcaptcha.com/) for how to obtain a site key and secret key.

```json
"challengeProvider": "turnstile",
"challengeSiteKey": "your-site-key",
"challengeSecretKey": "your-secret-key"
```

The challenge page uses the provider's invisible-mode widget with automatic execution, so legitimate visitors see only a brief "verifying" page and are not asked to solve anything unless the provider decides otherwise. (Whether the widget stays fully invisible also depends on the site key's settings in the provider's dashboard.) Verification happens server-side against the provider's `siteverify` API; a failed or missing token fails closed with a generic error. If the provider is misconfigured (unknown provider name or missing keys), a startup warning is logged and the domain falls back to the proof-of-work challenge. Provider keys are never returned by the API and cannot be set through it — `config.json` only.

## WAF-Lite

A conservative request-inspection layer: 15 patterns covering common SQL injection, cross-site scripting, and path-traversal shapes, plus WordPress login-flood counting (POSTs to `/wp-login.php` and `/xmlrpc.php` per IP per minute). Inspection covers the URL path and query (raw and URL-decoded); `wafInspectBody` adds small request bodies (POST/PUT/PATCH up to 1 MB; chunked or larger bodies are skipped, never buffered, and inspected bodies are restored before proxying).

The default mode is log-only: matches are logged with the rule name, IP, method, and a truncated path — never the request body — and the request continues, so legitimate visitors notice nothing. Set `wafMode: "block"` per domain to answer matches with a generic unbranded 403, or `"off"` to disable inspection. Patterns are deliberately narrow, but no pattern set is false-positive free, which is why blocking is opt-in per domain.

## Honeypot Endpoints

`honeypotPaths` lists decoy paths that legitimate visitors never request — for example, an old admin URL or a path only scanners probe. Matching is exact and case-sensitive (no prefix matching), so a decoy can never catch a real page that merely shares a prefix. A request that hits a decoy path has its suspicion level raised by `honeypotSusLv` (default `2`) and is logged as a `honeypot` event in the structured log. With no paths configured, the honeypot is fully disabled and costs nothing. Choose paths that appear in no link, sitemap, or redirect on your site; a path real users can reach will raise suspicion on real users.

```json
"honeypotPaths": ["/wp-admin/install.php", "/.env.bak"],
"honeypotSusLv": 2
```

## Fake Search-Bot Verification

With `fakeBotCheck: true`, requests whose user-agent claims to be Googlebot or Bingbot are verified by reverse DNS (the IP must resolve to a hostname under `googlebot.com`, `google.com`, or `search.msn.com`) followed by forward DNS (that hostname must resolve back to the same IP). A failed verification raises suspicion by `fakeBotSusLv` (default `3`), is logged as a `fakebot` event, and sets the `ip.searchbot` rule field to `"fake"`; a verified bot sets it to `"verified"`. DNS failures and timeouts fail open: the field becomes `"unchecked"`, nothing is bumped, and nobody is flagged on a DNS error alone. Results are cached (1 hour for verified/fake, 5 minutes for unchecked). The check is off by default and only runs for user-agents that claim to be a search bot.

## Tarpit

With `tarpitDelayMs` set, requests that reach the block decision (suspicion level at or above `tarpitSusLv`, default `4`) wait for the configured delay before the block response is sent, wasting the attacker's time and connection slots. The delay is capped at 30 seconds, and at most `tarpitMaxConns` (default `64`) connections are tarpitted at once — when the slots are full, further blocked requests answer immediately instead of queuing, so tarpitting can never exhaust the proxy. The tarpit never applies to allowed or challenged requests, only to requests already decided as blocks. `0` (default) disables it entirely.

## Edge Caching

With `edgeCache: true`, safe GET responses are cached in memory per domain and served to later identical requests without touching the backend. Only responses that are safe to share are stored: status `200`, `203`, `301`, or `308`, with an explicit positive `s-maxage`/`max-age` or a future `Expires`, and without `Cache-Control: no-store`/`no-cache`/`private`, `Set-Cookie`, `Vary`, or `Content-Encoding`. Requests with an `Authorization` header are never served from or stored in the cache, and upgrade (WebSocket) requests bypass it. Entries are capped at 1 MB each, the whole cache at `edgeCacheMaxMB` (default `64`), and lifetimes at `edgeCacheTTL` (default `60` seconds, further bound by the response's own headers); expired entries are evicted first, then the oldest. Served cache hits carry the standard `Age` header. The cache is per-process memory: a reload or restart empties it.

The [`PURGE_CACHE`](api.md#domain-actions) API action (and the dashboard's domain panel) clears the whole cache or one path. When every backend is down and the cache holds a stale copy of a GET response, the stale copy is served with a `Warning: 110 - "Response is stale"` header instead of the backend error page — see [Load Balancing and Failover](#load-balancing-and-failover).

## Waiting Room

With `waitingRoom: true`, when a domain's bypassed requests per second cross `waitingRoomThreshold`, excess visitors are queued fairly (first-come, first-served) instead of being dropped. Queued visitors see a plain waiting page showing their position, refreshing every few seconds, and are admitted at `waitingRoomAdmit` (default `20`) per second via signed, IP-bound queue cookies. The queue holds 5,000 entries; beyond that, excess visitors get a `503` with `Retry-After`. Reserved paths (`/_bProxy/...`) and cached responses are never queued. Off by default, and with the threshold unset it never activates — normal traffic is never queued. The waiting room is per-process memory: a reload or restart clears the queue.

## Load Balancing and Failover

A domain can list several backends in `backends` (same `scheme` for all). Requests are distributed by `lbPolicy`: `round-robin` (default) or `least-connections` (fewest in-flight backend requests). With `backends` empty, the single `backend` is used exactly as before — single-backend configs behave identically, with no extra probing.

Failover works two ways. First, transport failures mark a backend down after 2 consecutive failures for a 30-second cooldown, whether or not health checks are enabled; a request that fails is retried on another backend when its body can be replayed (GET/HEAD, or any request with a replayable body) — requests whose bodies cannot be replayed are never retried, so an operation is never duplicated. Second, with `healthCheckEnabled: true`, each backend is probed with a `GET` to `healthCheckPath` (default `/`) every `healthCheckInterval` seconds (default `10`, minimum `5`); a `2xx`/`3xx` answer marks it up, anything else marks it down until a probe passes. Probes send the domain name as the `Host` header, follow no redirects, and skip TLS verification for `https` backends, like the proxy itself.

When every backend is down, plain GET requests without `Authorization` are answered from the edge cache's stale copy when one exists (marked with the `Warning: 110` stale header and `Cache-Control: no-store`); otherwise the usual backend error page is shown. Stale fallback needs `edgeCache` enabled and a previously cached response — without it, there is nothing stale to serve.

```json
"backends": ["10.0.0.1:8080", "10.0.0.2:8080"],
"lbPolicy": "round-robin",
"healthCheckEnabled": true,
"healthCheckPath": "/healthz",
"healthCheckInterval": 10
```

## WebSocket Support

WebSocket upgrades proxy through the normal reverse-proxy path by default. Setting `websocketIdleTimeout` (seconds) switches upgrades for that domain to a dedicated path that dials the backend through the domain's backend pool (so load balancing and failover apply) and closes the connection after the configured idle time, instead of letting silent connections linger. The timeout is capped at 1 hour. HTTP/2 connections cannot be hijacked, so upgrades arriving over HTTP/2 keep using the normal reverse-proxy path. WebSocket over HTTP/2 (RFC 8441 extended CONNECT) is not supported.

## API Protection

Three optional, independent guards for API routes. All are inert unless configured, and all run after the normal challenge flow — API clients must still pass rate limits, WAF-lite, and firewall rules. Rejections are plain status codes, logged as `block` events with actions `api_jwt`, `api_key`, or `api_graphql`, and counted under the `api` metrics reason. Tokens and keys are never logged.

**JWT validation.** `jwtProtectedPaths` lists route prefixes that require a valid `Authorization: Bearer` token. Tokens are validated against `jwtSecret` (HS256) or the keys fetched from `jwtJWKSURL` (RS256/ES256). `exp` is required and must be in the future; `nbf` is honored when present; `alg: none` and algorithm confusion between the two modes are rejected. JWKS keys are fetched at startup and refreshed at most hourly; a failed refresh keeps the previous keys, and a failed initial fetch fails closed for protected routes with a startup warning. If protected paths are configured with neither a secret nor a JWKS URL, protected routes reject all requests (fail closed) with a startup warning. Missing or invalid tokens get `401`.

**API keys.** `apiKeyPaths` lists route prefixes that require a key in the `apiKeyHeader` header (default `X-API-Key`). `apiKeys` maps keys to per-key per-minute budgets; a limit of `0` means unlimited. Keys are compared in constant time. Unknown or missing keys get `401`; a known key over its budget gets `429` with `Retry-After: 60`. If key paths are configured with no keys, those routes reject all requests (fail closed) with a startup warning.

**GraphQL limits.** `graphqlPath` is the exact GraphQL endpoint path. JSON `POST` requests there have their `query` measured for brace-nesting depth and field count (an approximation: strings and comments are stripped first, then nesting and identifiers are counted — not a full GraphQL parser). Queries over `graphqlMaxDepth` or `graphqlMaxFields` (either `0` means no limit on that axis) get `400`. Non-JSON bodies, bodies without a `query` string, and bodies over 1 MB pass through untouched for the backend to handle.

```json
"jwtProtectedPaths": ["/api/private/"],
"jwtSecret": "your-hs256-secret",
"apiKeys": [{"key": "key-for-service-a", "name": "service-a", "limitPerMinute": 120}],
"apiKeyPaths": ["/api/keys/"],
"graphqlPath": "/graphql",
"graphqlMaxDepth": 8,
"graphqlMaxFields": 200
```

## Adaptive Proof-of-Work

With `adaptivePow: true`, the Stage 2 difficulty scales linearly with the domain's bypassed requests per second between `bypassStage1` (minimum applies) and `bypassStage2` (maximum applies). Under normal load visitors get the minimum difficulty; as an attack that bypasses Stage 1 grows, the puzzle gets progressively harder. Bounds default to the base difficulty and base `+3`, and the result is always clamped to `1`–`16` (each `+1` multiplies client work roughly 16×). Disabled by default; the fixed `stage2Difficulty` behavior is unchanged when off. The bounds and the toggle can also be adjusted at runtime via the `SET_DOMAIN_FEATURES` [API action](api.md#domain-actions) (runtime-only, not persisted to `config.json`).

## Quiet Mode

With `quietMode: true`, visitor-facing output carries no product identification: the `SonuShield` response header is not set, block messages lose the `Blocked by SonuShield.` prefix, captcha error pages lose the product name, and the unknown-host message on port 80 becomes a generic "`<host>` does not exist." Default output (quiet mode off) is unchanged.

Quiet mode affects only what site visitors see. It never affects authorship attribution: the `/_bProxy/credits` endpoint, the `LICENSE` file, README/docs credits, and code-level credits are always present and unchanged.

## Prometheus Metrics

With `metricsEnabled: true`, the proxy serves Prometheus exposition format (text 0.0.4) at:

```text
/_bProxy/<adminsecret>/metrics
```

Access control is the same secret-gated pattern as the dashboard and the v1 API: the path contains the `adminsecret`, and the endpoint is disabled entirely unless `metricsEnabled` is set. It is never exposed openly. Scrapes are handled before any challenge or rate limiting, so they are neither challenged nor counted in the request statistics. When disabled, the path falls through to normal request handling exactly as if the endpoint did not exist.

Exported series (all per domain, except the info and aggregate gauges):

| Series | Description |
|--------|-------------|
| `sonushield_info{version}` | Proxy version. Always `1`. |
| `sonushield_requests_total{domain}` | Total requests seen. |
| `sonushield_requests_bypassed_total{domain}` | Requests that passed the challenges. |
| `sonushield_requests_per_second{domain}` | Current total requests per second. |
| `sonushield_requests_bypassed_per_second{domain}` | Current bypassed requests per second. |
| `sonushield_peak_requests_per_second{domain}` | Peak total requests per second in the current attack window. |
| `sonushield_peak_requests_bypassed_per_second{domain}` | Peak bypassed requests per second in the current attack window. |
| `sonushield_stage{domain}` | Current challenge stage (1–3). |
| `sonushield_stage_locked{domain}` | `1` when the stage is manually locked, else `0`. |
| `sonushield_attack_raw{domain}` / `sonushield_attack_bypass{domain}` | `1` while the respective attack state is active. |
| `sonushield_blocks_total{domain,reason}` | Blocks by reason: `ratelimit`, `fingerprint`, `waf`, `suspect`, `api`. |
| `sonushield_challenges_total{domain,stage}` | Challenges served, by stage. |
| `sonushield_waf_matches_total{domain,rule}` | WAF-lite matches, by rule name. |
| `sonushield_backend_requests_total{domain,result}` | Backend round trips: `ok` or `error`. |
| `sonushield_backend_latency_seconds{domain}` | Backend latency histogram (buckets 5 ms–10 s, plus `+Inf`, with `_sum` and `_count`). |
| `sonushield_cpu_usage_percent` / `sonushield_ram_usage_percent` | Proxy process CPU/RAM, when measurable. |
| `sonushield_unknown_fingerprints` / `sonushield_ips_tracked` | Aggregate counts only. No IP address or fingerprint value is ever used as a label, so cardinality stays bounded.

Example scrape configuration (replace the host and secret):

```yaml
scrape_configs:
  - job_name: sonushield
    scheme: https
    metrics_path: /_bProxy/CHANGE_ME/metrics
    static_configs:
      - targets: ['example.com:443']
```

## Attack Reports

The [`GET_ATTACK_REPORT`](api.md#domain-actions) API action returns a summary for one domain: the attack window (from the per-second request logger), totals, current and peak request rates, stage and attack flags, and the actions taken (blocks by reason, challenges by stage, WAF matches by rule, backend results and average latency). It also lists the top IPs and unknown fingerprints with request counts, enriched with country/ASN when a GeoIP database is configured.

The per-IP and per-fingerprint tallies are **proxy-wide**, not per-domain: the firewall tracks them globally, and reports label them as such. Country aggregates are computed over the listed top IPs only. Reports contain metadata only — no request bodies, cookies, headers, or secrets.

With `reportDirectory` set, the proxy additionally writes one JSON file and one CSV file per finished attack into that directory (created if needed), named `<domain>_<window start>_<window end>.json` / `.csv`. A numeric suffix is added if a file with that name already exists, so earlier reports are never overwritten. Export failures are logged and never affect traffic. The CSV form is a single flat table with the header `section,key,value,detail`, covering the summary fields, action counts, top IPs (with `country=` / `asn=` detail), fingerprints, and countries.

## Structured Logs

With `logFormat: "json"` and `logFile` set, the proxy appends one JSON object per line to the log file for these events: `allow` (request passed the challenges), `block` (ratelimit, fingerprint, WAF, suspect, or API-protection block), `challenge` (stage 1/2/3 served), `waf` (WAF-lite match in log-only mode), `honeypot` (decoy path hit), `fakebot` (failed search-bot verification), `dryrun` (firewall-rule match in dry-run mode, with `would_be_sus_level`), `audit` (control-plane API action; see below), and `attack_start` / `attack_end`. Every entry carries `ts`, `level`, `event`, and `domain`; request entries add `ip`, `action`, `rule` and/or matched firewall-rule `rules`, fingerprints (`fingerprint`, `ja4`, `http_fingerprint`), `stage`, `sus_level`, `method`, `path`, truncated `user_agent`, and fail-open `country` / `asn` when a GeoIP database is loaded.

Privacy rules, enforced in the logger itself:

- Request bodies, cookies, and headers are never logged.
- The path is stripped of its query string, so tokens in URLs cannot leak.
- The admin secret embedded in API/dashboard/metrics paths is redacted to `/_bProxy/[redacted]/...`.
- The user-agent is truncated to 200 characters.

JSON is written only to the file, never to stdout (the terminal HUD redraws there). `logFormat` values other than `json` keep the existing text output; `json` without `logFile` logs a startup warning and stays disabled. A `reload` applies new log settings without a restart.

Retention is size-based rotation: when the current file would pass `logMaxBytes` (default 10 MiB), it is renamed to `<file>.1`, older files shift up, and the oldest is deleted, keeping `logMaxFiles` files in total (default 5, so disk use stays near `logMaxBytes × logMaxFiles`). If the log file cannot be opened, written, or rotated, logging disables itself with one warning instead of filling the disk or affecting traffic. The log directory must already exist — it is not created automatically.

## JA4 Local Overrides

SonuShield computes a JA4 fingerprint for every TLS connection alongside the legacy fingerprint (see [How It Works](how-it-works.md#tls-fingerprinting)). The built-in JA4 lists start empty, and you can teach the proxy JA4 values you have observed yourself with an optional `ja4_fingerprints.json` file next to `config.json`:

```json
{
  "known": {"t13d...": "Chromium"},
  "bot": {"t13d...": "SomeBot"},
  "malicious": {"t13d...": "Flood tool"}
}
```

(Replace the `t13d...` placeholders with full JA4 values observed on your own proxy.)

Local entries merge over the fetched lists and win on key conflicts. A missing file is a silent no-op; a file that fails to parse logs a warning and keeps the fetched lists. Only JA4 values observed on your own proxy (see `/_bProxy/fingerprint`) belong here: SonuShield JA4 values are computed from the fields Go's TLS stack exposes and are not comparable with values from external JA4 databases. See [`global/fingerprints/SOURCES.md`](../global/fingerprints/SOURCES.md) for list provenance.

## Webhook

Each domain can send Discord DDoS alerts through a webhook. Create a webhook in your Discord server (Server Settings → Integrations → Webhooks) and see [Discord's introduction to webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) for details. Leave `url` empty to disable alerts for a domain.

| Field | Type | Description |
|-------|------|-------------|
| `url` | String | The Discord webhook URL alerts are sent to. |
| `name` | String | The name shown above the alert in Discord. |
| `avatar` | String | URL of the profile picture shown with the alert in Discord. |
| `attack_start_msg` | String | Message sent when your domain first comes under attack. |
| `attack_stop_msg` | String | Message sent when the attack has ended. |

Both messages support placeholders: `{{domain.name}}`, `{{attack.start}}`, `{{attack.end}}`, `{{proxy.cpu}}`, and `{{proxy.ram}}`.

Alerts are only sent when the stage is **not** locked, when the first stage starts being bypassed, and when the attack ends. See [DDoS Alerts](features.md#ddos-alerts).

## Telegram and Email Alerts

Alongside Discord, each domain can send the same attack start/stop alerts over Telegram and email. Each channel is independent: configure any combination, and a channel with missing settings stays silent. All credentials come from `config.json` only — none are bundled, invented, or logged, and a failed send prints only a generic failure line.

Telegram needs a bot token and a chat ID from your own bot (create one with [@BotFather](https://t.me/BotFather), then message the bot and read the chat ID from the `getUpdates` API response):

```json
"telegram": {
  "botToken": "123456:your-bot-token",
  "chatId": "000000000",
  "attack_start_msg": "Attack detected on {{domain.name}}",
  "attack_stop_msg": "Attack on {{domain.name}} has stopped"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `botToken` | String | Your Telegram bot's token. |
| `chatId` | String | The chat (user, group, or channel) the bot sends alerts to. |
| `attack_start_msg` | String | Message sent when the domain first comes under attack. Empty uses a built-in default. |
| `attack_stop_msg` | String | Message sent when the attack has ended. Empty uses a built-in default. |

Messages are plain text and support the same placeholders as the Discord webhook (`{{domain.name}}`, `{{attack.start}}`, `{{attack.end}}`, `{{proxy.cpu}}`, `{{proxy.ram}}`).

Email needs an SMTP server you control or have an account on:

```json
"email": {
  "smtpHost": "smtp.example.com",
  "smtpPort": 587,
  "username": "alerts@example.com",
  "password": "your-smtp-password",
  "from": "alerts@example.com",
  "to": "owner@example.com",
  "useTLS": false,
  "attack_start_msg": "",
  "attack_stop_msg": ""
}
```

| Field | Type | Description |
|-------|------|-------------|
| `smtpHost` | String | SMTP server hostname. Empty disables email alerts. |
| `smtpPort` | Int | SMTP port (`0` defaults to `587`; use `465` with `useTLS`). |
| `username` | String | SMTP username. Empty sends without authentication. |
| `password` | String | SMTP password (or app password). Never logged. |
| `from` | String | Sender address. Empty uses the username. |
| `to` | String | Recipient address. Empty disables email alerts. |
| `useTLS` | Bool | `true` connects with implicit TLS (port 465 style). `false` (default) uses plain TCP and upgrades with STARTTLS when the server offers it. |
| `attack_start_msg` / `attack_stop_msg` | String | Message body, same placeholders as above. Empty uses a built-in default. |

Credentials are sent only to the configured SMTP server, and only over an encrypted connection or to a local server. Subjects are `SonuShield DDoS alert: <domain> — attack started/stopped`.

## Stage Thresholds

The automatic stage system watches two numbers per domain: total requests per second and bypassing requests per second (requests that passed the current challenge). When bypassing requests exceed `bypassStage1`, Stage 2 activates; when they exceed `bypassStage2`, Stage 3 activates. Stages step back down when both the bypassing and total request rates fall below the matching `disable*` thresholds. Locking a stage with the [`stage`](how-it-works.md#commands) command disables automatic switching until you unlock it with `stage 0`.

## API Roles and Audit Log

The main `apisecret` always authenticates as **admin**. `apiRoles` adds further API secrets mapped to roles, so read-only or limited operators get their own secret instead of sharing the admin one:

```json
"apiRoles": {
  "a-long-random-viewer-secret": "viewer",
  "a-long-random-operator-secret": "operator"
}
```

| Role | May run |
|------|---------|
| `viewer` | Read-only actions: all `GET_*`, `GET_DOMAINS`, `GET_PROXY_FEATURES`, `GET_ATTACK_REPORT`, `LIST_CONFIG_BACKUPS`, `SIMULATE_RULE`, `EXPORT_RULES`. |
| `operator` | Everything a viewer can, plus `SET_STAGE`, `ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE`, `CLEAR_LOGS`, `REFRESH_REPUTATION_FEED`, `PURGE_CACHE`, `IMPORT_RULES`. |
| `admin` | Everything, including `SET_DOMAIN_CONFIG`, `SET_DOMAIN_FEATURES`, `RELOAD`, `RESTORE_CONFIG_BACKUP`, and `FILL_IP_CACHE`. |

Unknown role names are ignored with a startup warning; empty secrets never match. A role calling an action above its level gets `ERR_FORBIDDEN`; unknown actions still get `ERR_ACTION_NOT_FOUND` for every role. Role changes take effect on reload (unlike `apisecret` itself, which needs a restart).

Every control-plane API call is written to the audit log: role, action, domain, scrubbed parameters, peer IP, and the result. When structured JSON logging is configured, audit entries go to the log file with `event: "audit"`; otherwise a compact line is printed to stdout (operators using the dashboard heavily should configure `logFile` to keep stdout clean). Parameters whose names look secret-like (`secret`, `token`, `password`, `key`) are dropped and values are truncated, and presented secrets are never logged — including for rejected calls, which are audited as role `unauthenticated`. See the [API Reference](api.md#roles-and-audit-log).

## Configuration Backups and Rollback

Every write to `config.json` (dashboard/API edits) rotates the backup set first: the previous file becomes `config.json.bak`, the older backups shift to `config.json.bak.1`, `.bak.2`, and so on, up to `configBackups` (default `5`). The [`LIST_CONFIG_BACKUPS` / `RESTORE_CONFIG_BACKUP`](api.md#proxy-actions) API actions (and the dashboard's Settings view) list and restore them. A restore validates the backup with the same checks as a reload, backs up the current file, swaps the backup in atomically, and reloads; if the reload fails, the previous file is written back and reloaded again, so a restore can never leave the running proxy disagreeing with the file. Backup names are validated strictly, so no path outside the backup set can be restored. Restoring is an admin-only action.

## Applying Changes

After editing `config.json` by hand, apply it with the Reload config button in the [dashboard](dashboard.md) or the `reload` terminal command (or restart the proxy). The dashboard/API reload validates the file first: secrets present and without `CHANGE_ME` placeholders, at least one named domain, every firewall rule compiling with a usable action, and every certificate pair loading. An invalid file is rejected and the running proxy is untouched. A successful reload resets request counters and stage locks, like the terminal reload; admin/API secret changes still need a restart. The `add` terminal command can add a domain interactively and reloads the configuration for you.

Some settings can also be changed from the dashboard without editing the file, via the authenticated API actions, and are written back to `config.json` immediately (atomically, with the previous file kept in the [rotating backup set](#configuration-backups-and-rollback)): firewall rules ([`ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE`](api.md#domain-actions)) and the domain settings in [`SET_DOMAIN_FEATURES`](api.md#domain-actions) plus stage thresholds ([`SET_DOMAIN_CONFIG`](api.md#domain-actions)). Keys the proxy does not know about are preserved in the file; only the edited keys change, and the file is re-indented.

Two settings can also be adjusted at runtime without editing the file or persisting, via [`SET_DOMAIN_FEATURES`](api.md#domain-actions): the adaptive proof-of-work toggle and bounds, and the WAF-lite mode, body inspection, and WordPress login limit. Runtime changes are not written back to `config.json` — a reload or restart restores the file's values. Stage changes ([`SET_STAGE`](api.md#domain-actions)) are likewise runtime-only.

## Next Steps

- [Firewall Rules](firewall-rules.md) — custom rules per domain.
- [API](api.md) — read stats, rules, and logs over HTTP.
- [Troubleshooting](troubleshooting.md) — if the proxy refuses to start.
