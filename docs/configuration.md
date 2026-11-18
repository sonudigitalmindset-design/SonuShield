# Configuration

`config.json` has two top-level fields: `proxy` (general settings) and `domains` (one entry per protected domain). Firewall rules are configured per domain, under each domain's `firewallRules` — see [Firewall Rules](firewall-rules.md).

> [← README](../README.md)

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
| `apisecret` | String | Secret sent in the `X-SonuShield-Secret` API header (the legacy `Proxy-Secret` spelling is still accepted for non-browser clients). Must not contain `CHANGE_ME`. |
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
| `rulePacksDirectory` | String | Directory that `IMPORT_RULE_PACK` may read pack files from. Empty (default) refuses file sources. See [Community Rule Packs](#community-rule-packs). |
| `logFormat` | String | `"json"` enables structured JSON logging to `logFile`; `"text"` (default) keeps the existing output. See [Structured Logs](#structured-logs). |
| `logFile` | String | Path of the JSON log file. Required when `logFormat` is `"json"`; without it, JSON logging stays disabled with a startup warning. |
| `logMaxBytes` | Int | Maximum size of the current log file in bytes before rotation (default `10485760`, 10 MiB; values below 64 KiB use the default). |
| `logMaxFiles` | Int | Total log files kept including the current one (default `5`; clamped to `1`–`100`). |
| `apiRoles` | Map[String]String | Additional API secrets mapped to roles (`viewer`, `operator`, `admin`). The main `apisecret` is always admin. See [API Roles and Audit Log](#api-roles-and-audit-log). |
| `configBackups` | Int | Number of rotating `config.json` backups kept (default `5`; clamped to `1`–`20`). See [Configuration Backups and Rollback](#configuration-backups-and-rollback). |
| `maxConnsPerIP` | Int | Maximum simultaneous connections per client IP (`0`, default, disables the cap). See [Slowloris and Request-Smuggling Guards](#slowloris-and-request-smuggling-guards). |
| `maxRequestBody` | Int | Global maximum request-body size in bytes (default `33554432`, 32 MiB; a negative value means unlimited). See [Payload Limits](#payload-limits). |
| `statusPage` | Bool | `true` enables the public `/_bProxy/status` and `/_bProxy/health` endpoints. Default `false`. See [Status Page](#status-page). |
| `gitops` | Object | Config-as-code sync from a local directory. Disabled by default. See [GitOps](#gitops). |
| `sso` | Object | OIDC login for the dashboard. Disabled by default. See [SSO for the Dashboard](#sso-for-the-dashboard). |
| `tlsDisablePostQuantum` | Bool | `true` restricts the TLS listener to classic key exchange (X25519, P-256/384/521) and disables the post-quantum hybrid. Default `false` (hybrid enabled). See [Post-Quantum TLS](#post-quantum-tls). |
| `branding` | Object | Operator branding for the dashboard and built-in challenge pages. Absent (default) keeps SonuShield's own presentation. See [White-Label Branding](#white-label-branding). |
| `stripe` | Object | Stripe usage-based billing hooks for tenant metering. Disabled without a secret key. See [Stripe Billing](#stripe-billing). |
| `publicApiKeys` | Array[Object] | API keys for the versioned public API, one per key: `{"key", "tenant", "name", "requestsPerMinute"}`. Empty (default) disables the public API. See [Public API](#public-api). |
| `eventWebhooks` | Array[Object] | Signed event webhook endpoints for attack/audit events, in JSON, syslog, or CEF format. Empty (default) sends nothing. See [Event Webhooks and SIEM Export](#event-webhooks-and-siem-export). |
| `osSignatures` | Array[Object] | Operator-supplied passive OS signatures: `{"label", "sndMss", "rcvMss", "wscale", "timestamps", "sack"}`. Empty (default) means every client reports `ip.os` as `unknown`. See [Passive OS Fingerprinting](#passive-os-fingerprinting). |
| `certAlerts` | Bool | `true` enables certificate-expiry alerts on the existing alert channels. Default `false`. See [Certificate and Subdomain Alerts](#certificate-and-subdomain-alerts). |
| `certAlertDays` | Int | Days before expiry at which the first alert fires (default `14` when `0` or negative). |
| `subdomainMonitor` | Object | Subdomain DNS monitoring: `{"enabled", "domains", "intervalMinutes", "failureThreshold"}`. Disabled by default. See [Certificate and Subdomain Alerts](#certificate-and-subdomain-alerts). |
| `privacyMode` | Bool | `true` minimizes stored PII: masked IPs and no user-agents in logs and reports, shortened log retention. Default `false`. See [Privacy Mode](#privacy-mode). |
| `twoPersonApproval` | Bool | `true` requires a second distinct approver for sensitive control actions. Default `false`. See [Two-Person Approval](#two-person-approval). |
| `approvalExpirySeconds` | Int | Seconds a pending approval waits before expiring (default `300` when `0` or negative). |
| `controlPlaneSecret` | String | Shared secret under which a trusted control plane proves caller identities for two-person approval. Empty (default) disables the mechanism. See [Control Plane](control-plane.md#two-person-approval). |
| `dashboardMode` | String | On-domain dashboard mode: `"local"` (default, served as before), `"control-plane"` (redirect to `controlPlaneUrl`, else bare 404), or `"off"` (bare 404). Unknown values fail safe to `"off"`. See [Control Plane](control-plane.md#dashboard-modes-and-migration). |
| `controlPlaneUrl` | String | Control-plane dashboard URL that on-domain dashboard requests redirect to when `dashboardMode` is `"control-plane"`. Must be an absolute `http(s)` URL; anything else falls back to a bare 404. |
| `redis` | Object | Optional Redis-backed shared rate-limit counts and challenge-result cache for multi-server deployments: `{"enabled", "addr", "password", "db", "tls", "keyPrefix", "sharedCache", "timeoutMs"}`. Disabled by default; single-server behavior is unchanged when off. See [Multi-Server](multi-server.md). |
| `http3` | Object | Optional HTTP/3 (QUIC) serving: `{"enabled", "addr"}` (empty `addr` means `:443`). Disabled by default; ignored in Cloudflare mode. See [HTTP/3](http3.md). |
| `anomalyDetection` | Bool | `true` enables the experimental log-only anomaly signal. Default `false`. It never changes suspicion levels, challenges, or blocks. See [ML Evaluation](ml-evaluation.md). |

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
| `backendVerifyTLS` | Bool | `true` verifies the origin TLS certificate against system roots for `https` backends (requests, health probes, WebSocket dials). Default `false` (historical skip-verify behavior). See [Load Balancing and Failover](#load-balancing-and-failover). |
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
| `riskHighRiskCountries` | Array[String] | ISO country codes treated as high-risk in the composite risk score (empty default: geography contributes nothing). Requires a GeoIP country database. See [Risk Score](#risk-score). |
| `riskHighRiskASNs` | Array[Int] | AS numbers treated as high-risk in the composite risk score (empty default). Requires a GeoIP ASN database. See [Risk Score](#risk-score). |
| `shareReputation` | Bool | `true` lets this domain both contribute to and consume the proxy-wide shared reputation store. Default `false`. See [Cross-Domain Reputation Sharing](#cross-domain-reputation-sharing). |
| `sharedReputationSusLv` | Int | Suspicion-level bump for requests whose IP or fingerprint was flagged on another opted-in domain (default `1`). |
| `timingEnforce` | Bool | `true` applies a suspicion bump when inhuman request timing is detected. Default `false` (detection is logged but never enforced). See [Timing and Behavior Detection](#timing-and-behavior-detection). |
| `timingSusLv` | Int | Suspicion-level bump for timing anomalies when `timingEnforce` is set (default `1`). |
| `sessionRatelimit` | Int | Maximum requests per challenge-cookie session per rate-limit window (`0`, default, disables the limit). See [Per-Session Limits](#per-session-limits). |
| `maxBodyBytes` | Int | Maximum request-body size in bytes for this domain (`0` inherits the proxy limit; a negative value means unlimited). See [Payload Limits](#payload-limits). |
| `bodyLimits` | Array[Object] | Per-route body limits: `{"prefix": "/upload", "maxBytes": 104857600}`. The longest matching prefix wins. See [Payload Limits](#payload-limits). |
| `originLockSecret` | String | Shared secret the proxy adds as `X-SonuShield-Origin` on every backend request. Empty (default) disables the header. Config-file-only; never logged or returned by the API. See [Origin Lock](#origin-lock). |
| `securityHeaders` | Map[String]String | Response headers set (overwriting backend values) on every proxied response. Empty (default) changes nothing. See [Security Headers and CORS](#security-headers-and-cors). |
| `cors` | Object | Per-domain CORS policy. Absent (default) disables CORS handling. Invalid policies fail closed. See [Security Headers and CORS](#security-headers-and-cors). |
| `ipAllowlist` | Array[Object] | Allow-list entries: `{"target": "203.0.113.0/24", "expires": 0, "note": ""}`. See [IP Allow and Block Lists](#ip-allow-and-block-lists). |
| `ipBlocklist` | Array[Object] | Block-list entries, same shape as `ipAllowlist`. The block list wins when both match. See [IP Allow and Block Lists](#ip-allow-and-block-lists). |
| `pageTemplates` | Object | Custom challenge-page HTML: `{"pow": "…", "captcha": "…", "waitingRoom": "…"}`. See [Custom Challenge Pages](#custom-challenge-pages). |
| `tenant` | String | Tenant this domain belongs to (default `"default"`). See [Multi-Tenancy and Metering](#multi-tenancy-and-metering). |
| `memoryHardPow` | Bool | `true` serves the Argon2-based Stage 2 puzzle instead of the classic hash puzzle. Default `false`. See [Memory-Hard Proof-of-Work](#memory-hard-proof-of-work). |
| `memoryHardPowBits` | Int | Memory-hard puzzle difficulty: leading zero bits required (default `4`, clamped `1`–`8`). |
| `memoryHardPowMemoryKB` | Int | Memory-hard puzzle memory cost in KiB (default `512`, clamped `256`–`8192`). |
| `memoryHardPowTime` | Int | Memory-hard puzzle time cost, Argon2 iterations (default `1`, clamped `1`–`3`). |
| `challengeRotation` | Array[String] | Ordered challenge types to rotate (`pow`, `memoryPow`, `turnstile`, `hcaptcha`, `captcha`). Empty (default) keeps the fixed challenge chain. See [Challenge Rotation](#challenge-rotation). |
| `challengeRotationMode` | String | `"wave"` (default: rotate at each attack wave) or `"request"` (rotate per served challenge). |
| `brotli` | Bool | `true` enables Brotli compression of eligible responses. Default `false`. See [Brotli and Image Optimization](#brotli-and-image-optimization). |
| `imageOptimize` | Bool | `true` enables on-the-fly image resizing/recompression. Default `false`. See [Brotli and Image Optimization](#brotli-and-image-optimization). |
| `imageOptimizeMaxWidth` | Int | Images wider than this (pixels) are resized down (default `1920`, clamped `16`–`4096`). |
| `imageOptimizeQuality` | Int | Re-encode quality for resized images (default `80`, clamped `40`–`95`). |
| `poolMaxIdleConns` | Int | Origin pool: maximum idle connections kept across all hosts (`0`, default, uses the shared transport). See [Origin Pooling and Stampede Guard](#origin-pooling-and-stampede-guard). |
| `poolMaxIdleConnsPerHost` | Int | Origin pool: maximum idle connections per host (`0` = default). |
| `poolMaxConnsPerHost` | Int | Origin pool: maximum simultaneous connections per host (`0` = default). |
| `poolIdleConnTimeout` | Int | Origin pool: idle-connection timeout in seconds (`0` = default 90, clamped `1`–`3600`). |
| `stampedeGuard` | Bool | `true` collapses simultaneous identical cache misses into one origin fetch. Default `false`. Requires the edge cache. See [Origin Pooling and Stampede Guard](#origin-pooling-and-stampede-guard). |
| `edgeRules` | Array[Object] | Fast-path precompiled rules, same `{"expression", "action"}` shape as `firewallRules`, evaluated before them. Empty (default) disables the fast path. See [Edge Rules](firewall-rules.md#edge-rules). |
| `twilio` | Object | WhatsApp/SMS alerts via a Twilio-compatible API. Inert unless fully configured. See [WhatsApp and SMS Alerts](#whatsapp-and-sms-alerts). |
| `branding` | Object | Per-domain branding override for built-in challenge pages. Absent (default) inherits the proxy branding. See [White-Label Branding](#white-label-branding). |
| `behaviorCheck` | Bool | `true` collects a privacy-respecting mouse/scroll signal on challenge pages only. Default `false`. See [Behavior Check](#behavior-check). |
| `behaviorEnforce` | Bool | `true` applies the suspicion bump for bot-like behavior. Default `false` (log-only signal). |
| `behaviorSusLv` | Int | Suspicion-level bump for bot-like behavior when enforced (default `1`). |
| `canaryPaths` | Array[String] | Decoy paths whose use immediately raises maximum suspicion and fires an alert. Empty (default) disables path canaries. See [Canary Tokens](#canary-tokens). |
| `canaryTokens` | Array[String] | Decoy credentials (fake API keys) whose use immediately raises maximum suspicion and fires an alert. Empty (default) disables token canaries. Token values are never logged or returned. |
| `invisibleMarkers` | Bool | `true` adds honeypot fields and invisible links to challenge pages the proxy serves. Default `false`. Never injected into origin content. See [Invisible Markers](#invisible-markers). |
| `fairQueue` | Bool | `true` shares backend capacity fairly across client IPs under overload. Default `false`. See [Fair Queuing](#fair-queuing). |
| `fairQueueMaxInflight` | Int | Maximum simultaneous backend requests admitted by the fair queue (`0` disables the queue even when `fairQueue` is set). |
| `fairQueueWaitMs` | Int | Maximum milliseconds a request waits in the fair queue before a 503 (default `5000`). |
| `shadowRules` | Array | Rules evaluated in shadow mode: matches are logged, never enforced. Empty (default) disables shadow rules. See [Shadow Mode](#shadow-mode). |
| `shadowWaf` | Bool | `true` also evaluates WAF-lite patterns in shadow mode. Default `false`. |
| `signedURLSecret` | String | HMAC secret for signed URLs on protected paths. Empty (default) disables signed-URL checks. Config-file-only; never logged or returned. See [Signed URLs and Hotlink Protection](#signed-urls-and-hotlink-protection). |
| `signedURLPaths` | Array[String] | Path prefixes that require a valid signed URL. Empty (default) disables the check. |
| `hotlinkProtect` | Bool | `true` enables Referer-based hotlink protection for asset paths. Default `false`. |
| `hotlinkPaths` | Array[String] | Path prefixes protected against hotlinking. Empty (default) protects nothing. |
| `hotlinkAllowlist` | Array[String] | Hosts allowed to hotlink protected assets (case-insensitive, ports ignored). The domain itself is always allowed. |
| `formGuard` | Object | Form spam guard: `{"paths", "honeypotField", "minSeconds", "maxPerMinute", "mode"}`. Absent (default) disables the guard. See [Form Spam Guard](#form-spam-guard). |
| `slaTarget` | Float | SLA target as a percentage (default `99.9`, clamped). Used by the latency/SLA report. See [Latency and SLA](#latency-and-sla). |
| `scheduleTimezone` | String | IANA timezone name used to evaluate rule schedules for this domain (default `UTC`). Invalid names warn and fall back to UTC. See [Scheduled Rules and Maintenance Windows](#scheduled-rules-and-maintenance-windows). |
| `maintenanceWindows` | Array[Object] | Scheduled maintenance windows: `{"start", "end", "message"}` with RFC 3339 timestamps. Empty (default) disables scheduled maintenance. |
| `cloudflareApiToken` | String | Cloudflare API token for rule import. Config-file-only; never logged or returned. Empty (default) disables Cloudflare import. See [Cloudflare Import](#cloudflare-import). |
| `cloudflareZoneId` | String | Cloudflare zone ID for rule import. Required with `cloudflareApiToken`. |
| `cloudflareApiBase` | String | Cloudflare API base URL (default `https://api.cloudflare.com`). Override only for testing against a mock. |

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

Failover works two ways. First, transport failures mark a backend down after 2 consecutive failures for a 30-second cooldown, whether or not health checks are enabled; a request that fails is retried on another backend when its body can be replayed (GET/HEAD, or any request with a replayable body) — requests whose bodies cannot be replayed are never retried, so an operation is never duplicated. Second, with `healthCheckEnabled: true`, each backend is probed with a `GET` to `healthCheckPath` (default `/`) every `healthCheckInterval` seconds (default `10`, minimum `5`); a `2xx`/`3xx` answer marks it up, anything else marks it down until a probe passes. Probes send the domain name as the `Host` header, follow no redirects, and follow the domain's TLS verification setting (below).

**Backend TLS verification.** By default, proxy-to-origin TLS connections do **not** verify the origin certificate — the historical behavior, kept so private origins with self-signed certificates keep working. Anyone able to intercept proxy→origin traffic could present any certificate for an HTTPS origin, so for origins on untrusted networks, set `backendVerifyTLS: true` on the domain: the origin certificate is then verified against the system roots with the backend hostname as the server name, for proxied requests, health probes, and WebSocket dials alike. Verification failures fail the request (or mark the backend down) rather than falling back to unverified. Only enable it when the origin serves a valid certificate for its hostname; IP-literal backends need a certificate with an IP SAN.

When every backend is down, plain GET requests without `Authorization` are answered from the edge cache's stale copy when one exists (marked with the `Warning: 110` stale header and `Cache-Control: no-store`); otherwise the usual backend error page is shown. Stale fallback needs `edgeCache` enabled and a previously cached response — without it, there is nothing stale to serve. Expired entries are retained for this fallback for up to 1 hour past expiry, then dropped.

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

Alerts are only sent when the stage is **not** locked, when the first stage starts being bypassed, and when the attack ends. See the [alert features](features.md#observability-alerts).

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
| `viewer` | Read-only actions: all `GET_*`, `GET_DOMAINS`, `GET_PROXY_FEATURES`, `GET_ATTACK_REPORT`, `LIST_CONFIG_BACKUPS`, `SIMULATE_RULE`, `EXPORT_RULES`, `GET_IP_LISTS`, `SEARCH_LOGS`, `GET_ATTACK_MAP`, `GET_TENANTS`, `GET_TENANT_USAGE`. |
| `operator` | Everything a viewer can, plus `SET_STAGE`, `ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE`, `CLEAR_LOGS`, `REFRESH_REPUTATION_FEED`, `PURGE_CACHE`, `IMPORT_RULES`, `ADD_IP_ENTRY` / `REMOVE_IP_ENTRY`. |
| `admin` | Everything, including `SET_DOMAIN_CONFIG`, `SET_DOMAIN_FEATURES`, `RELOAD`, `RESTORE_CONFIG_BACKUP`, `GET_IP_CACHE`, and `FILL_IP_CACHE`. |

Unknown role names are ignored with a startup warning; empty secrets never match. A role calling an action above its level gets `ERR_FORBIDDEN`; unknown actions still get `ERR_ACTION_NOT_FOUND` for every role. Role changes take effect on reload (unlike `apisecret` itself, which needs a restart).

Every control-plane API call is written to the audit log: role, action, domain, scrubbed parameters, peer IP, and the result. When structured JSON logging is configured, audit entries go to the log file with `event: "audit"`; otherwise a compact line is printed to stdout (operators using the dashboard heavily should configure `logFile` to keep stdout clean). Parameters whose names look secret-like (`secret`, `token`, `password`, `key`) are dropped and values are truncated, and presented secrets are never logged — including for rejected calls, which are audited as role `unauthenticated`. See the [API Reference](api.md#roles-and-audit-log).

## Configuration Backups and Rollback

Every write to `config.json` (dashboard/API edits) rotates the backup set first: the previous file becomes `config.json.bak`, the older backups shift to `config.json.bak.1`, `.bak.2`, and so on, up to `configBackups` (default `5`). The [`LIST_CONFIG_BACKUPS` / `RESTORE_CONFIG_BACKUP`](api.md#proxy-actions) API actions (and the dashboard's Settings view) list and restore them. A restore validates the backup with the same checks as a reload, backs up the current file, swaps the backup in atomically, and reloads; if the reload fails, the previous file is written back and reloaded again, so a restore can never leave the running proxy disagreeing with the file. Backup names are validated strictly, so no path outside the backup set can be restored. Restoring is an admin-only action.

## Risk Score

Every request gets a composite risk score from `0` to `100`, combining the signals known at evaluation time. It is a heuristic for ranking and clustering — **never a guarantee**: a high score never proves a request is malicious, and a low score never proves it is safe. The score is exposed as the `ip.risk` [firewall rule field](firewall-rules.md), as `risk_score` in structured logs, and as average/max/sample-count in [attack reports](#attack-reports).

Weights (fixed; there are no hidden inputs):

| Signal | Contribution |
|--------|--------------|
| Suspicion level at arrival (the domain's stage) | Stage 0 → 0, stage 1 → 10, stage 2 → 30, stage 3 → 50, stage 4+ → 70 |
| Known browser fingerprint | −10 |
| Bot-listed fingerprint | +25 |
| Unknown fingerprint | +15 |
| Listed on the local reputation blocklist or feed | +25 |
| Shared reputation (flagged on another opted-in domain) | +15 |
| Timing anomaly (inhumanly regular or bursty) | +20 |
| Challenge failures in the window | More than 10 → +10, more than 50 → +20 |
| Country in `riskHighRiskCountries` | +15 |
| ASN in `riskHighRiskASNs` | +15 |

The result is clamped to `0`–`100`. Geography contributes nothing unless the operator configures the high-risk lists (and a GeoIP database); an unconfigured database or a missing record is never penalised. In Cloudflare mode there is no TLS fingerprint and the browser is reported as `Cloudflare`, which counts as known (no penalty, no bonus). Same-request honeypot and fake-bot hits are not inputs: they raise the suspicion level directly after the score is computed, so the score is a snapshot of the signals known at evaluation time.

## Cross-Domain Reputation Sharing

Domains on the same proxy can share IP/fingerprint reputation: an attacker blocked on one domain starts with elevated suspicion on the others. Both directions are opt-in per domain — a domain that has not set `shareReputation: true` neither contributes nor consumes — and the store only ever adds suspicion, never blocks. Entries expire after 10 minutes. Sharing fails open: if the store is unavailable, requests are evaluated normally. Only blocks from the WAF and the suspect-block path are recorded; rate-limit and fingerprint-list blocks are already proxy-wide signals and are not recorded again.

## Timing and Behavior Detection

The proxy watches per-IP request timing for inhuman patterns and logs them as `timing` events in the structured log (at most once per IP per minute). Two patterns are detected, with deliberately conservative thresholds so legitimate bursts are not flagged:

- **Regular:** 12 or more requests with a coefficient of variation under `0.08` and a mean interval under 500 ms. Slow exact polling (intervals of 1 second or more) is never flagged.
- **Burst:** 50 or more requests inside a 1-second window.

Detection is log-only by default. Set `timingEnforce: true` to also apply the `timingSusLv` suspicion bump (default `1`) when an anomaly is detected. The timing verdict is also available to firewall rules as the `ip.timing` field (`""`, `"regular"`, or `"burst"`).

## Per-Session Limits

`sessionRatelimit` caps requests per challenge-cookie session within the rate-limit window, in addition to the per-IP limits — so one abusive session behind a shared NAT does not punish every user on that IP. The session key is a hash of the challenge-cookie value; the raw cookie is never stored or logged. Requests without a session cookie are unaffected. Over-limit requests are blocked with code `R4` (`session_ratelimit`). `0` (default) disables the limit.

## Slowloris and Request-Smuggling Guards

What is added here versus what Go's HTTP server already provides:

| Protection | Source |
|------------|--------|
| Slow headers: `timeout.read_header` bounds how long a connection may idle while sending headers | Inherited (pre-existing setting) |
| Ambiguous `Content-Length` / `Transfer-Encoding` framing: Go's server drops `Content-Length` when `Transfer-Encoding: chunked` is present, rejects unsupported transfer encodings with `400`, and the reverse proxy re-frames the body when forwarding, so the origin never sees the ambiguous shape | Inherited from Go; verified live |
| Middleware backstop: a request that somehow arrives with both a transfer encoding and a positive content length is answered `400` | Added (defense in depth; expected never to fire, since Go normalises the framing first) |
| Per-IP concurrent-connection cap (`maxConnsPerIP`): connections over the cap are closed immediately on accept, so one slow client cannot exhaust connection capacity | Added; `0` (default) disables it, and no tracking happens at all when disabled |

The connection cap counts connections from accept until close or WebSocket hijack, keyed by client IP (IPv6 handled correctly). There is no separate slow-body timeout: bodies are bounded by the [payload limits](#payload-limits), and the `read` timeout bounds total read time.

## Payload Limits

Request bodies are limited globally and per route, with a clean `413` response when a declared `Content-Length` exceeds the limit. The default limit is **32 MiB** (`33554432` bytes), which normal uploads stay well under. Resolution for a request, most specific first: the longest matching `bodyLimits` prefix → the domain `maxBodyBytes` → the proxy `maxRequestBody` → the 32 MiB default. At each level, a negative value means unlimited and `0` means inherit. Invalid route entries (empty prefix, non-positive size) are skipped with a warning.

Chunked (unknown-length) bodies are capped with a read limit as a backstop: an over-limit chunked body fails while being proxied and the client sees the generic backend-error page rather than the clean `413` — a documented asymmetry of streaming bodies. The proxy never decompresses request bodies, so there is no request-side decompression-bomb surface.

## Origin Lock

`originLockSecret` makes the proxy add an `X-SonuShield-Origin` header carrying the secret on every backend request, so the origin can reject traffic that bypassed the proxy. Any client-sent header of the same name is stripped first, unconditionally. The secret is config-file-only: it is never logged, never returned by the API (the API reports only whether one is configured), and never accepted through the dashboard.

Origin-side check, Nginx:

```nginx
# Inside the server block that serves the proxied site.
# Replace CHANGE_ME with the same secret as originLockSecret.
if ($http_x_sonushield_origin != "CHANGE_ME") {
    return 403;
}
```

Origin-side check, Apache (requires `mod_rewrite`):

```apache
RewriteEngine On
RewriteCond %{HTTP:X-SonuShield-Origin} !=CHANGE_ME
RewriteRule ^ - [F]
```

Replace `CHANGE_ME` with the real secret in both snippets, and keep the secret out of version control. Firewall the origin to the proxy's IPs as well: the header is a second layer, not the only one.

## Security Headers and CORS

`securityHeaders` sets response headers (overwriting any backend value) on every proxied response, before the edge-cache store, so cached copies carry them too. Example:

```json
"securityHeaders": {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin"
}
```

Header names must be valid tokens and values must not contain CR/LF; invalid entries are skipped with a startup warning. Empty (default) changes nothing.

`cors` configures a per-domain CORS policy:

```json
"cors": {
  "allowedOrigins": ["https://app.example.com"],
  "allowedMethods": ["GET", "POST"],
  "allowedHeaders": ["Authorization", "Content-Type"],
  "exposedHeaders": ["X-Total-Count"],
  "allowCredentials": false,
  "maxAge": 600
}
```

An invalid policy fails closed for that domain with a log line: no origins, an unparseable origin, an origin with a path, or a wildcard origin combined with credentials all disable CORS for the domain. Origins are normalised to `scheme://host`; methods default to `GET, HEAD, POST`; `maxAge` is clamped to `0`–`86400`. CORS headers are applied per request (after the cache store, so cached copies never contain another request's origin, and re-applied when a cached response is served); `Vary: Origin` is always added when CORS is configured and the request carries an `Origin`. Preflight (`OPTIONS` + `Origin` + `Access-Control-Request-Method`) requests are answered directly, without challenge, before rate limiting: a disallowed origin, method, or header set gets `403` with no CORS headers.

## IP Allow and Block Lists

`ipAllowlist` and `ipBlocklist` hold entries of `{"target": "203.0.113.0/24", "expires": 0, "note": ""}`. A target is a bare IP or a CIDR; `expires` is a Unix timestamp (`0` = never). Expired entries are skipped by matching and dropped from listings; invalid entries are warned about and skipped at load. The block list wins when both match an IP. An allow-listed IP starts at suspicion level `0` and bypasses the per-IP rate-limit blocks and the fingerprint block; a block-listed IP is blocked immediately (`IPBL`).

Lists are managed without editing the file via the authenticated [`GET_IP_LISTS` / `ADD_IP_ENTRY` / `REMOVE_IP_ENTRY`](api.md#domain-actions) actions and the dashboard's IP lists view, with the same atomic-write discipline as rule edits. No list is ever bundled: every entry is operator-supplied.

## Custom Challenge Pages

`pageTemplates` replaces the built-in challenge pages with operator-provided HTML:

```json
"pageTemplates": {
  "pow": "<html>…{{publicSalt}}…{{challenge}}…{{difficulty}}…</html>",
  "captcha": "<html>…{{captchaImage}}…{{maskImage}}…{{publicPart}}…</html>",
  "waitingRoom": "<html>…{{position}}…</html>"
}
```

Placeholders are substituted with HTML-escaped values, and `{{message}}` is accepted (optional) on every template. Required placeholders: PoW needs `{{publicSalt}}`, `{{challenge}}`, and `{{difficulty}}`; captcha needs `{{captchaImage}}`, `{{maskImage}}`, and `{{publicPart}}`; the waiting room needs `{{position}}`. A template missing its required placeholders is disabled with a warning and the built-in page is served instead.

Safety rules: `<script>` tags are stripped from templates with a warning — no arbitrary script execution beyond the existing proof-of-work flow, whose fixed solver script is appended to PoW templates automatically. Captcha templates must keep the element IDs the built-in captcha script expects: `captcha`, `mask`, `captcha-slider`, `text`, `successMessage`, `failMessage`, `box`, and `center`. The Turnstile/hCaptcha provider page is not customisable. Terse plain-text block messages (rate-limit and block notices) stay in English.

The built-in PoW, captcha, provider-verifying, and waiting-room pages are also available in Hindi, served when the request's `Accept-Language` starts with `hi`, with English fallback.

## Status Page

`statusPage: true` enables two public, unauthenticated endpoints, answered before any challenge or rate limiting:

- `GET /_bProxy/status` — `{"status": "ok", "uptime_seconds": N, "domains": [{"name": "…", "healthy": true}]}`. Exactly those three top-level keys: no IPs, secrets, config, request counts, rates, or stages. A domain is `healthy` when its backend pool has at least one eligible backend (with health checks on, a backend passing probes; with them off, a backend not in failure cooldown).
- `GET /_bProxy/health` — exactly `{"status": "ok"}`, a bare liveness check for scrubbing providers and load balancers.

Both are off by default; when off, the paths fall through to the normal request flow. See [Scrubbing-Center Integration](scrubbing-integration.md).

## Multi-Tenancy and Metering

Domains are grouped per tenant with the `tenant` key (default `"default"`). Tenant-scoped API roles bind a secret to one tenant: `"apiRoles": {"<secret>": "tenant:acme:viewer"}`. A tenant-scoped caller sees only its own domains (`GET_DOMAINS` is filtered, `GET_DOMAIN_CONFIG` reports the domain's tenant) and may run only `GET_DOMAINS` and `GET_TENANT_USAGE` as proxy actions; asking for another tenant's usage is forbidden. Single-tenant configs behave exactly as before.

Per-tenant usage counters (requests, blocked, bytes in/out) are exposed via [`GET_TENANTS` / `GET_TENANT_USAGE`](api.md#proxy-actions) and the dashboard's Domains view. Bandwidth is an estimate: challenge, block, and error pages and WebSocket traffic are not counted, and headers are excluded. Blocked counts are approximated as total minus bypassed, clamped at zero.

## GitOps

`gitops` watches a local directory (typically a git checkout, synced by an external tool — the proxy never shells out to git) for `config.json` changes and applies them through the validated reload path:

```json
"gitops": {
  "enabled": true,
  "directory": "/srv/sonushield-config",
  "intervalSeconds": 60
}
```

The watcher checks the file at most every `intervalSeconds` (default `60`, minimum `10`). A changed file is parsed and validated with the same checks as an API reload before anything is written; a bad synced config is logged and skipped, and can never take the proxy down. A valid file replaces `config.json` atomically (the previous file is kept as `config.json.bak`) and is applied via the validated safe reload. Sync is one-way: dashboard/API edits survive until the next git change overwrites them, so do not edit the same keys from both sides while GitOps is enabled. Enabling, disabling, or retargeting the watcher takes effect on the next reload without a restart. Disabled by default.

## SSO for the Dashboard

`sso` enables OIDC login for the dashboard, coexisting with the existing secret-path auth — either method grants access when configured, and secret-path auth keeps working alone:

```json
"sso": {
  "enabled": true,
  "issuer": "https://idp.example.com",
  "clientId": "sonushield-dashboard",
  "clientSecret": "CHANGE_ME",
  "redirectUrl": "https://proxy.example.com/_bProxy/sso/callback",
  "scopes": ["openid", "profile"],
  "defaultRole": "viewer",
  "roleClaim": "groups",
  "roleMapping": {"sso-admins": "admin", "sso-ops": "operator"}
}
```

The flow is the standard authorization-code flow with PKCE (S256), state, and nonce. Discovery is fetched without following redirects, the document's issuer must exactly equal the configured issuer, and ID tokens must be RS256/ES256 signed by a provider JWKS key (HS256 and `alg: none` are rejected); issuer, audience, expiry, and nonce are all checked. Sessions are HMAC-signed cookies (`HttpOnly`, `Secure`, `SameSite=Lax`, scoped to `/_bProxy/`, 8-hour lifetime); API calls accept the session cookie only with the `X-SonuShield-CSRF: 1` header the dashboard sends. Roles come from `defaultRole` (default `viewer`) or from the `roleClaim` mapping (a string claim, or the first matching array value; unknown values fall back to the default). Sessions are never tenant-scoped. Tokens, codes, and secrets are never logged; failures log only a failure class.

The client secret is config-file-only. HTTPS is required for the issuer and redirect URL, except `http` on loopback hosts (for local testing against a mock provider). An enabled-but-invalid config warns at startup and disables SSO; it never stops the proxy. These on-domain SSO paths are superseded once the dashboard moves to the control host: the control plane has its own SSO endpoints (`/sso/*`) on its own listener, where the identity provider only authenticates and the account file decides the role — see [Control Plane](control-plane.md#sso). `/_bProxy/sso/status` always answers `{"enabled": bool}` so the dashboard can offer SSO only when configured.

## Control Plane

The `controlPlane` top-level section configures the separate management host (`sonushield control`): the dashboard served from its own official-style host, owner/reseller/tenant accounts, server-side scoping, audit logging, and node management over API v2. It is inert unless the binary is run in `control` mode, and a config file holding only this section (no proxy secrets, no domains) validates as a control-plane config. Full setup, account bootstrap, the reseller/tenant model, migration from the on-domain dashboard, and security notes: [Control Plane](control-plane.md).

The proxy-side settings for the platform model live in the proxy table above: `controlPlaneSecret` (shared caller-identity secret for two-person approval through the control plane), `dashboardMode` (`"local"` / `"control-plane"` / `"off"`), and `controlPlaneUrl` (redirect target for `"control-plane"` mode). Mode changes apply on reload, without a restart.

## Post-Quantum TLS

Go 1.24 enables the X25519MLKEM768 post-quantum hybrid key exchange by default, and SonuShield uses the Go default: clients that offer the hybrid group negotiate it, and clients that do not fall back to classic X25519 or P-256/384/521. No configuration is needed, and no certificate change is involved — this is key exchange only, not post-quantum signatures. The negotiation was verified with real TLS handshakes (an MLKEM-only client succeeds against the default listener and fails when the hybrid is disabled). To restrict the listener to classic key exchange — for example, for a middlebox that mishandles the larger ClientHello — set the proxy-level `tlsDisablePostQuantum: true`.

**ECH is not supported.** Encrypted ClientHello needs server-side support that Go's standard `crypto/tls` does not provide as of Go 1.24, so SonuShield cannot terminate ECH itself and does not claim to. The path forward is a future Go release with ECH support, or a dedicated ECH-capable TLS terminator in front of the proxy. The Server Name Indication (SNI) in the ClientHello remains visible to network observers, as with any TLS server without ECH.

## Memory-Hard Proof-of-Work

With `memoryHardPow: true`, a domain's Stage 2 challenge is an Argon2id puzzle instead of the classic hash puzzle: the visitor's browser runs a pure-JavaScript Argon2id solver (embedded in the binary, no CDN, no WebAssembly) and submits the counter it found; the server verifies with a single Argon2id computation. The puzzle is bound to a single-use nonce tied to the visitor's IP, TLS fingerprint, and user-agent, and expires after 10 minutes. A provider challenge (Turnstile/hCaptcha) still takes precedence when configured; challenge rotation (below) takes precedence over both.

Parameters, all per domain and clamped to the ranges in the table above:

```json
"memoryHardPow": true,
"memoryHardPowBits": 4,
"memoryHardPowMemoryKB": 512,
"memoryHardPowTime": 1
```

**Choose parameters carefully — never combine high values.** The defaults target roughly half a second of solving on a laptop and one to two seconds on a phone (measured: ~31 ms per evaluation at 512 KiB / 1 iteration in a desktop JavaScript engine; 4 bits needs ~16 evaluations on average). Raising memory to 8 MiB with 3 iterations and 8 bits would take minutes on a phone and melt its battery. Start with the defaults and raise one parameter at a time, testing on a real low-end phone. The classic puzzle stays the default; this is an opt-in alternative for operators whose attackers run GPU/ASIC hash solvers.

## Challenge Rotation

With `challengeRotation` set, the served Stage 2 challenge type rotates through the listed types instead of always serving the same one, so an attacker cannot settle on a single solver:

```json
"challengeRotation": ["pow", "captcha"],
"challengeRotationMode": "request"
```

Type names are case-insensitive: `pow` (classic hash puzzle), `memoryPow` (the Argon2 puzzle above, only when `memoryHardPow` is enabled), `turnstile` / `hcaptcha` (only when the domain is configured for that provider, with keys), and `captcha` (the slider captcha). Unknown names are dropped, duplicates collapse, and unavailable types are skipped; if no listed type is available, rotation is inert and the fixed chain runs. The classic puzzle is the ultimate fallback. `challengeRotationMode` is `"wave"` (default: advance at the start of each attack wave) or `"request"` (round-robin per served challenge). Rotation state resets on restart and survives reloads. One limit: each domain has a single provider configuration, so rotating between Turnstile and hCaptcha on the same domain is not possible. Off by default; the current fixed behavior is preserved when the list is empty. The rotation policy is visible read-only via `GET_DOMAIN_FEATURES`; the live current type is not exposed through the API.

## Brotli and Image Optimization

With `brotli: true`, eligible responses are compressed with Brotli (level 5) when the client advertises it via `Accept-Encoding`. Only GET responses are compressed, only for compressible content types, only under 1 MiB, and never for authenticated traffic (`Authorization` present), upgraded connections, or responses marked `Cache-Control: no-transform`. An explicit `br` quality of 0 is honored. ETags are weakened and `Content-MD5` dropped, as compression requires. Fail-open: any error serves the original bytes unchanged.

With `imageOptimize: true`, JPEG and PNG images wider than `imageOptimizeMaxWidth` are resized down and re-encoded in their original format at `imageOptimizeQuality`. Images are capped at 5 MiB and 16 megapixels, at most 4 optimizations run concurrently, and the same GET / authenticated / `no-transform` guards apply. No format conversion happens (no WebP/AVIF output); the `Content-Type` is preserved. Both features are off by default and never alter responses for non-GET or authenticated traffic.

## Origin Pooling and Stampede Guard

By default all domains share one keep-alive transport to origins. Setting any of `poolMaxIdleConns`, `poolMaxIdleConnsPerHost`, `poolMaxConnsPerHost`, or `poolIdleConnTimeout` gives the domain a dedicated transport with those limits (unset values mirror the shared defaults: 10 idle total, 2 idle per host, 10 connections per host, 90-second idle timeout). Pooling never changes single-backend behavior observably — it only bounds connection reuse.

With `stampedeGuard: true` and the edge cache enabled, simultaneous identical cache misses are collapsed: one request fetches from the origin while the others wait (up to 30 seconds) and are then served from the freshly filled cache, so one slow origin response does not fan out into many. Only cacheable requests are guarded. Off by default.

## WhatsApp and SMS Alerts

A domain can send the same attack start/stop alerts over WhatsApp or SMS through the operator's own Twilio-compatible account:

```json
"twilio": {
  "accountSID": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "authToken": "CHANGE_ME",
  "from": "+15005550006",
  "to": "+15005550001",
  "apiBase": "https://api.twilio.com",
  "attack_start_msg": "Attack detected on {{domain.name}}",
  "attack_stop_msg": "Attack on {{domain.name}} has stopped"
}
```

All four of account SID, auth token, `from`, and `to` must be set; otherwise the channel is inert. Whether a message goes as WhatsApp or SMS is decided by the provider from the `from` number: prefix it with `whatsapp:` (for example `"whatsapp:+15005550006"`) for WhatsApp, or use a plain E.164 number for SMS. `apiBase` defaults to Twilio's API and only needs overriding for a compatible provider or a test mock. Message templates support the same `{{domain.name}}` placeholder as the other channels. The token is config-file-only, never returned by the API (only `TWILIO_CONFIGURED`, `TWILIO_FROM`, and `TWILIO_TO` are reported), and message contents are never logged. Live delivery needs the operator's own Twilio account; it was verified against a mock server only.

## White-Label Branding

Resellers can brand the dashboard and the built-in challenge pages with their own display name, logo, and accent color, proxy-wide with per-domain overrides:

```json
"branding": {
  "displayName": "Acme Shield",
  "logoURL": "https://cdn.example.com/logo.png",
  "accentColor": "#123456"
}
```

Per-domain fields override the proxy-wide ones individually; an empty field falls back to the proxy value, and the dashboard always uses the proxy-wide branding. Values are sanitised: the name is trimmed and capped at 64 characters, the logo must be an `http(s)` URL or a same-origin absolute path (no `javascript:` or protocol-relative URLs), and the accent must be a `#rgb` / `#rrggbb` hex color. Invalid values fall back silently and never break serving.

**Hard limit: white-labeling never removes or hides GPL attribution.** The LICENSE file, the `/_bProxy/credits` endpoint, and the README/docs credits always stay, and the dashboard's About footer keeps its attribution line. Branding changes only the dashboard wordmark/title/mark/accent, an optional banner and accent override on the built-in challenge pages, and nothing else. Custom page templates receive no branding injection, and the PWA manifest name and favicon stay SonuShield's (they are static embedded assets). The `SonuShield` response header and alert prefixes are likewise untouched. Branding is config-file-only; there are no API actions or dashboard controls for it.

## Stripe Billing

For multi-tenant operators, usage-based billing hooks report metering counters to Stripe as usage records on metered subscription items:

```json
"stripe": {
  "secretKey": "sk_live_...",
  "apiBase": "https://api.stripe.com",
  "reportIntervalSeconds": 3600,
  "customers": {
    "acme": {
      "customerId": "cus_...",
      "requestsItemId": "si_...",
      "bandwidthItemId": "si_..."
    }
  }
}
```

The secret key is config-file-only (only `sk_test_` / `sk_live_` keys are accepted; publishable keys are rejected) and is never logged or returned. `apiBase` defaults to Stripe's API and only needs overriding for a test mock. Each tenant maps to one Stripe customer with up to two metered subscription items — one for requests, one for bandwidth. **Units are raw**: request counts and bytes, so the operator's metered prices in Stripe must be defined in those units. Reporting is deltas-only with deterministic idempotency keys: the first sight of a tenant baselines its counters and reports nothing (never retro-bills), a failed report retries the same delta with the same key, and a counter reset on reload reports the post-reset value as a fresh delta (pre-reload unreported usage is forgotten, never double-counted). `reportIntervalSeconds` of `0` (default) disables scheduled reporting; otherwise it is clamped to 60–86400 seconds. Reporting can also be triggered on demand with the `REPORT_STRIPE_USAGE` API action, and `GET_STRIPE_STATUS` reports enablement, key mode (test/live), and the last result. Counters are estimate-grade, like the metering counters themselves: challenge, block, and error pages and WebSocket traffic are not counted, and headers are excluded. Unmapped tenants report nothing. The integration creates no customers, subscriptions, or charges — the operator sets those up in Stripe. It was verified against a mock server only; no live Stripe account was used.

## Public API

The versioned public API (`/_bProxy/public/v1/`) is a separate, read-only API for tenants and resellers, distinct from the internal control API. Access is by API key, configured proxy-wide:

```json
"publicApiKeys": [
  {"key": "CHANGE_ME", "tenant": "acme", "name": "acme-read",
   "requestsPerMinute": 100}
]
```

Keys must be at least 16 characters; shorter keys never match. `requestsPerMinute` defaults to 60 when unset (clamped to 1–60000); `tenant` defaults to `"default"`. Keys travel as `Authorization: Bearer <key>` (preferred) or `X-API-Key`, are compared in constant time, and are never logged or returned. Endpoints: `GET v1/ping` (tenant + key name), `GET v1/usage` (tenant aggregate; `?domain=` filters to one of the tenant's domains), and `GET v1/domains` (the tenant's domains with stage and counters). Responses use a `{"ok": true, "data": …}` / `{"ok": false, "error": {"code", "message"}}` envelope with matching HTTP codes. A domain outside the caller's tenant 404s exactly like a nonexistent one. Only GET is accepted (other methods get 405); unknown endpoints and versions get a JSON 404 and are never proxied. Rate limits are per key, fixed-window, with `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset` headers and `Retry-After` on 429. Unauthenticated requests get JSON 401 errors at any stage (the suspect firewall block for very high suspicion levels still applies to every path); the public API is read-only and its calls are not audit-logged. Minimal Go and Python clients live in [`sdk/`](../sdk/README.md) with examples that run against a live proxy.

## Event Webhooks and SIEM Export

Attack start/stop and audit events can be delivered to operator-configured endpoints as signed HTTP webhooks, in JSON, syslog (RFC 5424), or CEF format for SIEM ingestion:

```json
"eventWebhooks": [
  {"url": "https://siem.example.com/collect", "secret": "CHANGE_ME",
   "events": ["attack.start", "attack.stop"], "format": "cef",
   "timeoutSeconds": 10, "maxRetries": 3}
]
```

An endpoint delivers only with an `http(s)` URL and a non-empty secret. `events` filters the event types delivered (empty means all: `attack.start`, `attack.stop`, `audit`, plus `test` from the `TEST_WEBHOOKS` action, which ignores filters). `format` is `json` (default), `syslog`, or `cef`. Delivery is a bounded ordered queue (256 events; overflow drops and counts) with exponential backoff (1s ×2, capped at 60s); transport errors and 5xx responses retry, 3xx/4xx are permanent, and redirects are never followed. At most 16 endpoints are used; extras are ignored and counted. Each delivery carries `X-SonuShield-Timestamp` (Unix seconds) and `X-SonuShield-Signature` (`v1=` + hex HMAC-SHA256 of `"<timestamp>.<body>"` with the endpoint secret) — verify both, and reject stale timestamps, on receipt. Payloads carry operational facts only (event id, type, timestamp, domain, tenant, and scrubbed audit parameters); secrets never appear in payloads. Delivery is HTTP POST only — there is no UDP/TCP syslog sender; SIEMs ingest through an HTTP collector or a relay. `GET_WEBHOOK_STATUS` reports endpoint hosts (never full URLs or secrets), queue depth, and drop counts; `TEST_WEBHOOKS` queues one `test` event per endpoint. Webhook URLs are treated as secrets in exports and backups, since they often embed tokens.

## Passive OS Fingerprinting

SonuShield can classify a client's OS family from passively observable TCP signals, using only what the kernel genuinely exposes through `TCP_INFO` on Linux: the send and receive MSS, the smoothed RTT, and the negotiated options bitmask (timestamps, SACK, window scaling, ECN). Classification is by operator-supplied signatures in `proxy.osSignatures`:

```json
"osSignatures": [
  {"label": "linux", "sndMss": 1460, "wscale": true, "timestamps": true, "sack": true}
]
```

A signature matches when every non-zero/non-nil field matches; the first matching signature wins. With no signatures configured, `ip.os` is always `unknown` — the proxy ships no signature database and invents no values. The result is available to firewall rules as `ip.os` (the label, or `unknown`) and `ip.tcpinfo` (a compact rendering of the raw signals), and is shown on the `/_bProxy/fingerprint` page.

Honesty limits: Go's `net/http` does not expose raw TCP headers, so classic p0f signals are **not** available — TTL, the DF flag, TCP option order, the window-scale *value*, and the initial window size cannot be observed. On non-Linux platforms the collector is a stub and `ip.os` stays `unknown`. No signals are collected in Cloudflare mode (the proxy never sees the client TCP connection).

## Behavior Check

When `behaviorCheck` is set on a domain, challenge pages the proxy serves include a small script that reports only whether the mouse moved, whether the page scrolled, and a coarse elapsed-time bucket — sent once via `sendBeacon` when the page unloads. No coordinates, no keystrokes, no cross-site tracking, and no identifier beyond the existing challenge cookie. The signal is collected only on challenge pages, never on normal pages.

A client is flagged as bot-like only when it shows no mouse or scroll activity *and* completes the challenge in under 1.5 seconds; slower no-interaction clients are inconclusive and never flagged. By default the signal is log-only (and adds a small risk-score contribution); `behaviorEnforce` applies the `behaviorSusLv` suspicion bump. The verdict is available to rules as `ip.behavior` (`human`, `bot`, or empty).

## Canary Tokens

Decoy paths and credentials that no legitimate visitor should ever touch. Configure per domain:

```json
"canaryPaths": ["/admin-old", "/wp-admin-backup"],
"canaryTokens": ["sk-live-decoy-..."]
```

Hitting a canary path (exact, case-sensitive match) or presenting a canary token as a bearer token, API key, or `api_key`/`apikey` parameter immediately answers a generic 403, raises maximum suspicion, and fires an alert on the existing alert channels (rate-limited to one per IP per hour). Token values are never logged, never returned by the API, and never included in alerts. With none configured, canaries are fully inert.

## Invisible Markers

When `invisibleMarkers` is set on a domain, challenge pages the proxy serves gain two traps: a hidden link to a nonce URL (the endpoint always answers 404) and a honeypot form field on the verification forms. Interacting with either marks the client as automated: the IP is blocked with a generic 403 and an alert fires. Markers are added only to pages the proxy itself serves — never to origin content — and are off by default.

## Fair Queuing

When `fairQueue` is set with a positive `fairQueueMaxInflight`, backend capacity is shared fairly across client IPs under overload: each IP gets its own FIFO queue, and admission proceeds round-robin, one request per IP per turn (deficit round-robin with quantum 1 and equal weights — there is no cost or size weighting). At normal load the queue is a fast path with no observable effect. Requests that wait longer than `fairQueueWaitMs` (default 5000) receive a 503 with `Retry-After`. Cache hits, challenges, reserved paths, and WebSocket upgrades bypass the queue.

## Shadow Mode

Shadow mode evaluates a second set of rules — and optionally the WAF-lite patterns — without ever acting on the result, so an operator can see what a new ruleset *would* have done:

```json
"shadowRules": [{"expression": "ip.country eq \"XX\"", "action": "4"}],
"shadowWaf": true
```

Shadow matches are logged as `shadow` entries, and `GET_SHADOW_REPORT` compares shadow outcomes against live outcomes (would-block / would-challenge / would-allow counts, disagreements, per-rule tallies, and the last 50 decisions). Shadow rules support the same `schedule` field as live rules. Shadow mode is distinct from `rulesDryRun`, which disables live enforcement; shadow evaluation runs alongside live enforcement and never affects traffic.

## Signed URLs and Hotlink Protection

Protected paths can require an HMAC-signed URL with an expiry. The operator secret is config-only:

```json
"signedURLSecret": "a-long-random-secret",
"signedURLPaths": ["/downloads/", "/private/"]
```

A signed URL carries `exp` (Unix expiry) and `sig` (hex HMAC-SHA256 of `path + "\n" + exp` with the secret). Verification is strict: absolute expiry, 64-hex signature, constant-time comparison, and no clock-skew allowance. Invalid or expired signatures get a generic 403. The secret is never logged or returned, and is redacted from backups and config exports.

Hotlink protection checks the `Referer` of GET/HEAD requests to `hotlinkPaths`: missing referers are allowed, the domain itself and `hotlinkAllowlist` hosts are allowed (case-insensitive, ports ignored), and everything else gets a generic 403. Both features are off by default.

## Form Spam Guard

An opt-in per-path guard for POST endpoints, configured per domain:

```json
"formGuard": {
  "paths": ["/contact", "/comment"],
  "honeypotField": "website",
  "minSeconds": 3,
  "maxPerMinute": 30,
  "mode": "log"
}
```

Three signals: a honeypot field (bots fill hidden fields humans never see), submission timing (a signed timestamp cookie set on GETs to guarded paths; submissions faster than `minSeconds` are suspicious), and a per-IP rate limit per path. Defaults are generous — `minSeconds` 3, `maxPerMinute` 30 — and a missing, invalid, or stale timing cookie never condemns a request. `mode` is `log` (default, log-only) or `block` (generic 403). The guard only inspects URL-encoded form bodies for the honeypot and timing checks; the rate limit applies to all POSTs to guarded paths.

## Latency and SLA

Every domain's latency is tracked in a ring of the last 512 sampled requests, with no configuration needed: proxy latency (middleware entry to the first backend attempt), TTFB (first attempt to response headers), and total time (first attempt until the body is fully read). Retries inflate TTFB honestly — the clock starts at the first attempt. `GET_LATENCY` reports p50/p95/p99 for TTFB and total, mean proxy latency, the origin success rate over the retained window (labelled as such — it is not wall-clock uptime), the `slaTarget` percentage (default 99.9), and the remaining error budget. Oversized Brotli/image-optimized responses and abandoned bodies are not sampled. The dashboard's Insights view shows the same figures.

## Attack Timeline and Postmortem

Each attack gets a timeline: attack start/end, stage changes, and peaks, recorded from the existing attack lifecycle — no new data collection. `GET_POSTMORTEM` returns the last finished attack (or the current one, with `which=current`) as JSON or readable text, combining the attack-scoped timeline and peaks with the proxy-wide top sources and latency samples. The timeline holds at most 200 events per attack and the last 10 finished attacks per domain.

## Security Grade Scan

`GET_SECURITY_GRADE` grades the current configuration — secret strength (length and placeholder checks only, never values), certificate validity, HSTS, WAF coverage, stage thresholds, CORS, challenge-provider keys, debug exposure, webhook/feed URL schemes, and informational checks for post-quantum TLS, SSO, metrics exposure, and privacy mode. Each check reports a status (pass/warn/fail/info), severity, detail, and fix guidance, and the overall grade (A–F) is computed from the scored checks with caps: any high-severity failure caps the grade at C, any failure caps it at B. The scan is a configuration audit, not a penetration test: it makes no network probes and never phones home.

## Certificate and Subdomain Alerts

Certificate-expiry alerting and subdomain monitoring reuse the existing alert channels (Discord, Telegram, email, Twilio) via the generic notice path:

```json
"certAlerts": true,
"certAlertDays": 14,
"subdomainMonitor": {
  "enabled": true,
  "domains": ["app.example.com", "api.example.com"],
  "intervalMinutes": 60,
  "failureThreshold": 3
}
```

Cert checks run hourly: one alert per certificate per calendar day once the certificate is within `certAlertDays` of expiry. Unreadable certificates are not alerted hourly — they are reported by the grade scan and `GET_CERT_STATUS`. Subdomain checks resolve only the operator-listed names through the system DNS (there is no CT-log lookup): the first successful lookup sets a silent baseline, address changes alert, and failures alert after `failureThreshold` consecutive failures. Checks are fail-open: a DNS failure never affects traffic. `intervalMinutes` below 5 is raised to 5. Both features are off by default; `GET_CERT_STATUS` and `GET_SUBDOMAIN_STATUS` report current state on demand.

## Scheduled Rules and Maintenance Windows

Rules can carry a cron-style `schedule` (5 fields: minute, hour, day of month, month, day of week — `*`, lists, ranges, and steps; day-of-week 7 means Sunday; month/weekday names are not supported). Day-of-month and day-of-week follow Vixie OR semantics: a rule is active when either field matches. Schedules are evaluated in the domain's `scheduleTimezone` (IANA name, default UTC). A rule whose schedule is not currently active is skipped as if it did not exist; edge rules ignore schedules. An invalid schedule in the config file warns at load and the rule stays always-active (fail safe); the API rejects invalid schedules on rule creation. The rule simulator is expression-only and ignores schedules.

Maintenance windows serve a plain 503 page (with `Retry-After: 60`) for ordinary traffic while `/_bProxy/` control-plane paths keep working:

```json
"maintenanceWindows": [
  {"start": "2026-11-20T02:00:00Z", "end": "2026-11-20T04:00:00Z", "message": "Scheduled maintenance"}
]
```

Windows are end-exclusive; invalid windows are dropped with a warning. The dashboard's Stage view (or `SET_MAINTENANCE` / `GET_MAINTENANCE`) can also enable an on-demand override — in-memory, surviving reloads but not restarts — with an optional message (max 500 characters) and duration in minutes (`0` = until disabled).

## Community Rule Packs

Rule packs are operator-supplied JSON documents with pack metadata plus a rules array:

```json
{"name": "bot-pack", "version": "1.0", "source": "https://example.com/pack.json",
 "description": "…", "rules": [{"expression": "…", "action": "4"}]}
```

`IMPORT_RULE_PACK` fetches a pack from a server file path or an http/https URL (1 MB cap, 10-second timeout, at most 3 redirects) and validates every rule exactly like a rule import — all-or-nothing, in `replace` (default) or `append` mode. File paths are restricted to the proxy `rulePacksDirectory` (unset means file sources are refused; absolute paths and directory escapes are rejected), and URL fetches refuse non-public destinations. Pack metadata is recorded in a registry kept in `config.json` under `proxy.rulePacks` (metadata only, no rule contents) and listed by `LIST_RULE_PACKS`. SonuShield ships no bundled packs and claims no community endorsement; packs are operator-chosen. URL fetching is fail-open: a fetch failure aborts the import and changes nothing.

## Cloudflare Import

Firewall rules can be imported from the Cloudflare API using the operator's own token and zone ID (`cloudflareApiToken`, `cloudflareZoneId`, config-only, never logged or returned). `CF_PREVIEW_IMPORT` is read-only: it fetches the zone's firewall rules, translates the documented expression subset (`ip.src`, `http.request.uri.path`, `http.user_agent`, `http.request.method`, `cf.client.bot`; comparison, `contains`/`matches`/`starts_with`/`ends_with`/`in` operators; `and`/`or`/`not` and parentheses) into SonuShield rule equivalents, and reports exactly what would change — translated rules with any caveat notes, skipped rules with reasons, and settings with no SonuShield equivalent that are not imported. `CF_APPLY_IMPORT` re-fetches and re-translates, then applies in `append` (default) or `replace` mode. Action mapping: block → `4`, challenge variants → `2`, allow → `0`; log/skip actions are skipped. `cf.client.bot` translates to a check on the known-bot fingerprint list, which is not the same as Cloudflare Bot Management — the preview notes this caveat on every affected rule. The import reads only; it never writes back to Cloudflare.

## Privacy Mode

When `privacyMode` is set proxy-wide, stored PII is minimized consistently:

- Log entries (JSON logs and the in-memory log list): IP addresses are masked (IPv4 last octet to 0, IPv6 last 64 bits zeroed) and user-agents are dropped. Masking happens after the GeoIP lookup, so country/ASN are still recorded.
- Reports and the `GET_IP_REQUESTS` response: IP tallies are masked, with collisions summed so totals stay correct.
- Log search results: entries are masked on the way out, including entries written before the mode was enabled.
- Audit entries: IPs are masked in the file entry and the stdout fallback.
- Log retention: the number of kept log files is capped at 2.
- Metrics carry no IP labels, with or without privacy mode.

Live enforcement state (rate limiting, connection tracking, IP reputation) necessarily keeps exact IPs to function; it is never written to disk or returned unmasked while privacy mode is on. Fingerprints are retained as pseudonymous signals. The `/_bProxy/fingerprint` page shows a visitor their own data back to them and stores nothing. Privacy mode is off by default and takes effect on load and reload.

## Two-Person Approval

When `twoPersonApproval` is set proxy-wide, sensitive control actions require a second distinct approver before executing: config restore, backup restore, rule import, domain import, rule-pack import, Cloudflare apply, and domain creation from a template. The first call returns a pending response with an approval ID and expiry; a different caller (identified by the hash of the presented secret, or the SSO session for dashboard SSO logins) must approve with `APPROVE_ACTION` before the action executes. The approver must also satisfy the action's role and tenant scoping. `REJECT_ACTION` rejects (or lets the requester cancel their own request), `LIST_APPROVALS` lists pending requests (stored parameters are never returned), and expired requests are pruned and audit-logged. All approval events are written to the audit log. Pending state is in-memory and does not survive a restart. With the feature off, every action executes immediately and single-operator setups are unaffected.

## Mobile App Attestation

`attestation` (per domain) verifies app-integrity tokens — Google Play Integrity / Apple App Attest style JWTs — on operator-configured API paths. Set `enabled`, `paths` (path prefixes), and either `jwksUrl` (public keys fetched and refreshed hourly) or `secret` (HS256, config-only, never returned by the API). `issuer`, `audience`, and `header` (default `X-Attestation-Token`) pin the expected token claims; `verdictClaim` (a dot-path like `deviceIntegrity.deviceRecognitionVerdict`) and `verdictValues` pin the expected verdict. `mode` is `block` (generic 403, the default) or `log` (log only). Verification checks signature, issuer, audience, and expiry; tokens are never logged. When enabled with paths but no verification material, matching requests are rejected and a startup warning is printed — fail-closed by design. Apple App Attest CBOR assertion objects are not parsed: JWT-form assertions only. Real-device attestation was verified against mock tokens only; confirm with a real device before enforcing.

## Passkey Challenge

`passkey` (per domain) offers a WebAuthn assertion challenge as an alternative to the captcha at Stage 3. Set `enabled`, `rpId` (the relying-party domain), `rpName`, `origins` (allowed origins, defaulting to `https://<rpId>`), and `credentialsFile` (a JSON file holding only public-key material: credential ID, JWK public key, user handle, label, sign count — written atomically with `0600` permissions). The passkey page is served only when at least one credential is enrolled; otherwise the captcha is used, so the feature can never strand visitors. Enrollment is out-of-band via the API (`ENROLL_PASSKEY`, admin role) with operator-supplied JWK values — there is no registration ceremony in the proxy. Assertions are verified server-side (type, challenge, origin, RP ID hash, User Present flag, ES256/RS256 signature, monotonic sign counter); challenges are single-use nonces bound to IP/TLS/user-agent with a 10-minute TTL. `LIST_PASSKEYS` (viewer) returns metadata only; `REMOVE_PASSKEY` (operator) removes a credential.

## Credential Stuffing Detection

`credentialStuffing` (per domain) correlates failed-login signals across IPs. `paths` lists the watched login paths (longest-prefix match); `failureStatuses` (default `401, 403`) marks which origin response statuses count as failures; `perIpThreshold` (default 10) and `distributedThreshold` (default 20 distinct IPs) set the velocity trip points within `windowSeconds` (default 300). `mode` is `log` (default, log-only) or `block` (adds +2 suspicion toward the captcha — never an outright block). No bodies or usernames are inspected; only POSTs to watched paths are evaluated. Origin servers can also feed the detector through `POST /_bProxy/origin-signal` (see [Origin Signals](#origin-signals)). Status via `GET_STUFFING_STATUS` (counts only).

## Session Hijack Detection

`sessionHijack` (per domain) flags an established session cookie that suddenly appears with different signals. Set `cookie` (the session cookie name; empty means off) and `mode` (`log` default, or `block` for a +2 suspicion bump). A binding of IP + TLS fingerprint + HTTP fingerprint + country is recorded per cookie value (keyed by SHA-256 hash — raw values are never stored); a request is flagged only when two or more bound signals differ, so a single change (a new IP, a browser update) is never acted on. Flagged requests never rebind the session. Status via `GET_HIJACK_STATUS` (counts only).

## OpenAPI Validation

`openApi` (per domain) validates API requests against an operator-supplied OpenAPI 3.x spec file (JSON only; convert YAML with `yq` first). Set `specFile` and `prefixes` (path prefixes to validate; empty means off), `mode` (`log` default, or `block` for a generic 400), and per-route `routes` overrides (longest-prefix wins). Validated: path templates with `{param}`, required query/header/path parameters with type and enum checks, and JSON body schemas (types, required fields, nested properties, array items, enums, numeric bounds, string length/pattern, boolean `additionalProperties: false`). Local `#/components/schemas/...` references are resolved; `allOf`/`oneOf`/`anyOf`, discriminators, and `format` are not evaluated. An invalid, unreadable, or non-3.x spec disables validation with a warning (fail safe). Violation log entries name the rule and field only, never body content. Status via `GET_OPENAPI_STATUS`.

## DLP Scanning

`dlp` (per domain) scans outbound response bodies for operator-configured secret patterns. `patterns` is a list of `{name, regex}` pairs (config-only — no patterns are bundled, so nothing matches until the operator writes one); `action` is `redact` (default, matches replaced with `[redacted]`) or `block` (generic 403); `maxScanBytes` caps the scanned body (default 1 MiB). Only 2xx responses with text-ish content types and no Content-Encoding are scanned; oversized or encoded bodies pass through unscanned (fail open, documented). Scanning runs before the edge-cache store, so cached copies carry redacted bytes. Matched content is never logged, stored, or returned — log entries and `GET_DLP_STATUS` carry pattern names and counts only.

## CSP Report Collector

Browsers send Content Security Policy violation reports to `POST /_bProxy/csp-report` when the site's `report-uri` / `report-to` directive points there. Both wire shapes are accepted (legacy `application/csp-report` and Reporting API `application/reports+json`); bodies are capped at 64 KiB. Only a small subset of fields is stored (document/blocked URIs with query strings stripped, directives, source file/position, status, disposition); referrer, original policy, and script samples are dropped. Storage is a bounded per-domain ring (200 reports); reports never influence enforcement. The endpoint is unauthenticated by design (browsers cannot authenticate report delivery), so a malicious client can only pollute the bounded list. View reports in the dashboard Logs view or via `GET_CSP_REPORTS`.

## Threat Sharing Network

`threatSharing` (proxy-wide) exchanges threat indicators — bad IPs and fingerprints with a reason and an expiry — between SonuShield instances the operator explicitly peers with. There is no central server and no bundled feed. Set `enabled` and `peers` (`name`, `url`, `sharedSecret` — config-only, never logged or returned); `pullIntervalSeconds` defaults to 300 (minimum 60). Exchanges use `GET`/`POST /_bProxy/threat-sharing/indicators`, authenticated with an HMAC-SHA256 signature header (timestamp skew ±300 seconds). Received indicators raise suspicion by one level on matching requests — never a block on their own — and expire (default 1 hour, clamped to 24 hours). Peer errors fail open: previously received indicators are kept until they expire. `pushOnCanary` shares a canary-tripper's IP with peers. Manage via `GET_SHARING_STATUS`, `ADD_INDICATOR`, `REMOVE_INDICATOR`, `PULL_INDICATORS`, `PUSH_INDICATORS`.

## BGP Alerts

`bgpMonitor` (proxy-wide) watches route announcements for the operator's own prefixes and alerts on unexpected origins. Set `enabled`, `prefixes`, and `expectedOrigins` (the ASNs that should originate them). `source` is `ripestat` (the default: the free, public RIPEstat prefix-overview API, no credentials) or `custom` (an operator API base URL in `apiBase`, with an optional Bearer `apiToken`, returning `{"announced": true, "origins": [12345]}`). `checkIntervalSeconds` defaults to 3600 (minimum 300). The first successful check per prefix is a silent baseline; later checks alert once per transition to an unexpected origin set (or to no announcement) and once on recovery. Fetch errors fail open and raise no alert. RIPEstat aggregates collector data in multi-hour intervals, so this is a coarse-grained early warning, not real-time hijack detection. Status via `GET_BGP_STATUS`.

## Live Log Tail

The dashboard Logs view streams new log entries live over `GET /_bProxy/<adminsecret>/log-tail` (server-sent events), authenticated like the rest of the control plane (an `X-SonuShield-Secret` header or an SSO session plus the CSRF header). Entries are the same sanitized records the JSON logger writes — no bodies, cookies, query strings, or secrets — and audit entries are never streamed. The tail works even when file logging is disabled. Delivery is best-effort and bounded (16 subscribers, 100-entry buffers; a full buffer drops entries rather than blocking requests). Tenant-scoped callers see only their own tenant's domains.

## Synthetic Checks

`synthetic` (proxy-wide) schedules self-checks that request the operator's domains through the proxy like ordinary visitors. Set `enabled` and `checks` (`name`, `url`, optional `method` GET/HEAD, `expectStatus` default 200, `expectBodyContains`); `intervalSeconds` defaults to 300 (minimum 60), and `latencyThresholdMs` (when positive) alerts on slow checks. Checks carry the user-agent `SonuShield-Synthetic-Check/1.0`, verify TLS, and alert once per transition (failure, recovery, latency breach, latency recovery) over the existing notice channels. Checks are normal requests — they pass challenges, appear in request totals, and never touch attack statistics. Status via `GET_SYNTHETIC_STATUS`.

## RUM Beacon

Real-user timing is collected from the snippet served at `GET /_bProxy/rum.js`, which the operator embeds on origin pages (`<script src="/_bProxy/rum.js" async></script>`). The snippet reads `PerformanceNavigationTiming` once per page load and posts one beacon to `POST /_bProxy/rum`. Only navigation-timing buckets are collected (DNS, connect, TLS, TTFB, DOM, load — clamped to 0–60000 ms, rounded to 10 ms buckets); no IP or user-agent is stored, and the optional path is stripped of its query string. In privacy mode the per-path breakdown is dropped entirely. The snippet is never injected into origin content and is not added to challenge pages. Aggregates are available via `GET_RUM_STATS` and the dashboard Insights view.

## On-Call Rotation

`oncall` (proxy-wide) routes alert delivery to the responder who is on call. `responders` lists people with per-channel overrides (Telegram, email, Twilio, webhook — same shapes as the domain settings; empty channels are skipped while that responder is on call); `schedule` lists entries (`responder`, `days` as `mon`..`sun`, `start`/`end` as `HH:MM`, `timezone` as an IANA name, UTC when empty/invalid; end earlier than start spans midnight; first match wins). When no entry matches, alerts fall back to the domain's configured channels. `escalationMinutes` (when positive) re-sends an unacknowledged alert to every responder once the delay elapses. Alerts are tracked for acknowledgement via `GET_ONCALL_STATUS` and `ACK_ALERT`; attack-start alerts are tracked under a fixed ID and cleared by the matching attack-end. With the feature off, delivery is exactly as before. Handover is the schedule itself: at a boundary, new alerts go to the next responder.

## Origin Signals

`originSignals` (proxy-wide) holds the shared secret origin servers use to post failure signals to `POST /_bProxy/origin-signal` (header `X-SonuShield-Signal`, body `{domain, type, ip, path}`). The only accepted type is `login_failure`, which feeds the credential-stuffing detector for the domain's watched paths — the signal is recorded under the longest matching watched prefix, exactly like a failure observed in a response; a path matching no watched path is accepted but has no effect. No usernames or credentials are accepted. With no secret configured the endpoint does not exist. The [WordPress plugin](../plugins/wordpress/README.md) forwards `wp_login_failed` events this way, and the [hosting-panel client](../plugins/panels/README.md) provisions domains through the control API.

## Nginx and Apache Import

`PREVIEW_SERVER_IMPORT` (operator) converts pasted nginx server blocks or Apache vhosts into SonuShield domain entries and reports exactly what would change — without changing anything. The documented subset is server names, proxy backends (`proxy_pass` at server level or in `location /`; `ProxyPass` for `/`), and TLS certificate/key paths. Rewrites, redirects, document roots, other location blocks, and unknown directives are reported (as not-imported or warnings), never silently dropped; blocks without a usable name or backend are skipped with the reason. `APPLY_SERVER_IMPORT` (admin) creates the domains through the bulk-import machinery (all-or-nothing, validated, persisted, reloaded). Include directives are never followed. The dashboard Domains view offers the same flow with a preview step and a confirmation.

## Cache Analytics and Purge

The edge cache (see [Edge Caching](#edge-caching)) keeps counters per domain: hits, misses, bytes served, stores, evictions, purges, and stale serves, plus current entries and bytes — counters only, reset on reload. `GET_CACHE_STATS` (viewer) returns them, and the dashboard domain panel shows them. `PURGE_CACHE` accepts exactly one selector: `path` (one URL path, with any query string), `prefix` (every path starting with the prefix), or `tag` (entries recorded with that `Cache-Tag` response-header value, captured at store time). With no selector the whole domain cache is purged.

## Config Validator

`sonushield validate [--config PATH] [--probe-backends]` fully checks a config file without starting the proxy: structure, secrets presence (values never printed), certificate validity and expiry (expired is an error, expiry within 30 days a warning), backend and hostname validity, duplicate domains, rule compilation, rule actions and schedules, DLP regexes, OpenAPI specs, attestation material, and proxy-feature sanity (GeoIP files, feed URLs, SSO, sharing peers, BGP prefixes, on-call responders, synthetic checks). Unknown top-level keys and short secrets are warnings. Errors exit 1; warnings do not fail validation. `--probe-backends` additionally TCP-dials every backend (3-second timeout) and reports unreachable backends as errors. A [CI workflow](../.github/workflows/ci.yml) runs build, vet, and the validator (positive, negative, and probe cases) on every push and pull request to `main`, generating its own throwaway config and certificate — no secrets needed.

## Applying Changes

After editing `config.json` by hand, apply it with the Reload config button in the [dashboard](dashboard.md) or the `reload` terminal command (or restart the proxy). The dashboard/API reload validates the file first: secrets present and without `CHANGE_ME` placeholders, at least one named domain, every firewall rule compiling with a usable action, and every certificate pair loading. An invalid file is rejected and the running proxy is untouched. A successful reload resets request counters and stage locks, like the terminal reload; admin/API secret changes still need a restart. The `add` terminal command can add a domain interactively and reloads the configuration for you.

Some settings can also be changed from the dashboard without editing the file, via the authenticated API actions, and are written back to `config.json` immediately (atomically, with the previous file kept in the [rotating backup set](#configuration-backups-and-rollback)): firewall rules ([`ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE`](api.md#domain-actions)) and the domain settings in [`SET_DOMAIN_FEATURES`](api.md#domain-actions) plus stage thresholds ([`SET_DOMAIN_CONFIG`](api.md#domain-actions)). Keys the proxy does not know about are preserved in the file; only the edited keys change, and the file is re-indented.

Two settings can also be adjusted at runtime without editing the file or persisting, via [`SET_DOMAIN_FEATURES`](api.md#domain-actions): the adaptive proof-of-work toggle and bounds, and the WAF-lite mode, body inspection, and WordPress login limit. Runtime changes are not written back to `config.json` — a reload or restart restores the file's values. Stage changes ([`SET_STAGE`](api.md#domain-actions)) are likewise runtime-only.

## Next Steps

- [Firewall Rules](firewall-rules.md) — custom rules per domain.
- [API](api.md) — read stats, rules, and logs over HTTP.
- [Troubleshooting](troubleshooting.md) — if the proxy refuses to start.
