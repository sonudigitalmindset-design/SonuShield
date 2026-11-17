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
| `sonushield_blocks_total{domain,reason}` | Blocks by reason: `ratelimit`, `fingerprint`, `waf`, `suspect`. |
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

With `logFormat: "json"` and `logFile` set, the proxy appends one JSON object per line to the log file for these events: `allow` (request passed the challenges), `block` (ratelimit, fingerprint, WAF, or suspect block), `challenge` (stage 1/2/3 served), `waf` (WAF-lite match in log-only mode), and `attack_start` / `attack_end`. Every entry carries `ts`, `level`, `event`, and `domain`; request entries add `ip`, `action`, `rule` and/or matched firewall-rule `rules`, fingerprints (`fingerprint`, `ja4`, `http_fingerprint`), `stage`, `sus_level`, `method`, `path`, truncated `user_agent`, and fail-open `country` / `asn` when a GeoIP database is loaded.

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

## Applying Changes

After editing `config.json` by hand, apply it with the Reload config button in the [dashboard](dashboard.md) or the `reload` terminal command (or restart the proxy). The dashboard/API reload validates the file first: secrets present and without `CHANGE_ME` placeholders, at least one named domain, every firewall rule compiling with a usable action, and every certificate pair loading. An invalid file is rejected and the running proxy is untouched. A successful reload resets request counters and stage locks, like the terminal reload; admin/API secret changes still need a restart. The `add` terminal command can add a domain interactively and reloads the configuration for you.

Some settings can also be changed from the dashboard without editing the file, via the authenticated API actions, and are written back to `config.json` immediately (atomically, with the previous file kept as `config.json.bak`): firewall rules ([`ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE`](api.md#domain-actions)) and the domain settings in [`SET_DOMAIN_FEATURES`](api.md#domain-actions) plus stage thresholds ([`SET_DOMAIN_CONFIG`](api.md#domain-actions)). Keys the proxy does not know about are preserved in the file; only the edited keys change, and the file is re-indented.

Two settings can also be adjusted at runtime without editing the file or persisting, via [`SET_DOMAIN_FEATURES`](api.md#domain-actions): the adaptive proof-of-work toggle and bounds, and the WAF-lite mode, body inspection, and WordPress login limit. Runtime changes are not written back to `config.json` — a reload or restart restores the file's values. Stage changes ([`SET_STAGE`](api.md#domain-actions)) are likewise runtime-only.

## Next Steps

- [Firewall Rules](firewall-rules.md) — custom rules per domain.
- [API](api.md) — read stats, rules, and logs over HTTP.
- [Troubleshooting](troubleshooting.md) — if the proxy refuses to start.
