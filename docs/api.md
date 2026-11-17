# API Reference

SonuShield exposes an HTTP API for reading proxy statistics, firewall rules, and logs — and for managing the proxy: stage control, domain configuration, firewall rule editing, log clearing, and configuration reload. Both API versions authenticate with the `apisecret` from your configuration, or with a role-mapped secret (see [Roles and Audit Log](#roles-and-audit-log)). The v1 path additionally contains your `adminsecret`.

![API schematic](assets/api.svg)

> The API documentation previously hosted on SwaggerHub is no longer available. This page is the authoritative API reference for the current code.

## Version 1

Send a `POST` request with a JSON body to:

```text
POST /_bProxy/<adminsecret>/api/v1
Header: proxy-secret: <apisecret>
Body:   {"domain": "<domain name or empty>", "action": "<ACTION>", "params": {"<key>": "<value>"}}
```

With an empty `domain`, proxy-level actions are executed. With a domain name, domain-level actions are executed for that domain. The optional `params` object carries parameters for actions that take them (`SET_DOMAIN_FEATURES`, `GET_ATTACK_REPORT`, `SET_STAGE`, `SET_DOMAIN_CONFIG`, `ADD_RULE`, `UPDATE_RULE`, `DELETE_RULE`, `PURGE_CACHE`, `SIMULATE_RULE`, `IMPORT_RULES`, `RESTORE_CONFIG_BACKUP`); other actions ignore it.

## Version 2

Send a request to one of these paths (any method with a readable body works; the header is what authenticates the call):

```text
/_bProxy/api/v2/<ACTION>
/_bProxy/api/v2/<domain>/<ACTION>
/_bProxy/api/v2/<domain>/SET_DOMAIN_FEATURES?wafMode=block&...
Header: Proxy-Secret: <apisecret>
```

Actions that take parameters read them from the URL query string in v2 (first value wins per key). Prefer `POST` for actions that change settings.

## Response Format

All API responses are JSON:

```json
{"success": true, "results": {"TOTAL_REQUESTS": 12345}}
```

Failures return `"success": false` with an error code in `results.ERROR`:

| Error code | Meaning |
|------------|---------|
| `ERR_DOMAIN_NOT_FOUND` | The requested domain does not exist. |
| `ERR_ACTION_NOT_FOUND` | The requested action does not exist. |
| `ERR_BODY_READ_FAILED` | The request body could not be read. |
| `ERR_JSON_READ_FAILED` | The request body is not valid JSON. |
| `ERR_INVALID_PARAM` | A parameter name or value is invalid, or parameters contradict each other. Nothing was changed. |
| `ERR_PARAMS_REQUIRED` | The action needs parameters, but none were supplied. |
| `ERR_CONFIG_WRITE_FAILED` | A change was valid but could not be written to `config.json`. Nothing was changed; see `results.ERROR_DETAIL` for the reason. |
| `ERR_RELOAD_FAILED` | The configuration could not be reloaded (invalid file or failed validation). The running config is untouched; see `results.ERROR_DETAIL` for the reason. |
| `ERR_FORBIDDEN` | The authenticated role may not run this action. Nothing was changed. |

Actions that validate a rule, a config write, or a reload also return a human-readable `results.ERROR_DETAIL` alongside the error code. Detail messages never contain secret values.

Requests with a missing or wrong API secret are passed through to the normal request handling instead of receiving an API response.

## Roles and Audit Log

The `apisecret` authenticates as **admin**. Additional secrets mapped to roles via the proxy `apiRoles` config key authenticate as **viewer** (read-only) or **operator** (stage, rules, cache, log clearing, feed refresh, rule import). Admin-only actions are `SET_DOMAIN_CONFIG`, `SET_DOMAIN_FEATURES`, `RELOAD`, `RESTORE_CONFIG_BACKUP`, and `FILL_IP_CACHE`; a lower role calling one gets `ERR_FORBIDDEN`. Unknown actions return `ERR_ACTION_NOT_FOUND` for every role. See [API Roles and Audit Log](configuration.md#api-roles-and-audit-log) for the full permission table.

Every API call is audit-logged (role, action, domain, scrubbed parameters, peer IP, result) — to the structured log file when JSON logging is configured, otherwise as a compact stdout line. Secret-like parameters are dropped, values are truncated, and presented secrets are never logged, including for rejected calls (audited as role `unauthenticated`).

## Proxy Actions

| Action | Returns |
|--------|---------|
| `GET_PROXY_STATS` | `CPU_USAGE`, `RAM_USAGE` |
| `GET_PROXY_STATS_CPU_USAGE` | `CPU_USAGE` |
| `GET_PROXY_STATS_RAM_USAGE` | `RAM_USAGE` |
| `GET_IP_REQUESTS` | `TOTAL_IP_REQUESTS`, `CHALLENGE_IP_REQUESTS` |
| `GET_FINGERPRINT_REQUESTS` | `TOTAL_FINGERPRINT_REQUESTS` (unknown fingerprints only) |
| `GET_IP_CACHE` | `IP_CACHE` |
| `FILL_IP_CACHE` | Diagnostic action: fills the IP cache with test entries. |
| `RELOAD` | Validates `config.json` and, only if it is valid, reloads it into the running proxy. Returns `RELOADED`. On an invalid file returns `ERR_RELOAD_FAILED` and the running config is untouched. A successful reload resets request counters and stage locks, like the terminal `reload` command; admin/API secret changes still need a restart. |
| `GET_DOMAINS` | `DOMAINS`: one summary per configured domain (`NAME`, `BACKEND`, `SCHEME`, `STAGE`, `STAGE_LOCKED`, `UNDER_ATTACK`, `TOTAL_RPS`, `BYPASSED_RPS`, `TOTAL_REQUESTS`, `BYPASSED_REQUESTS`, `RULE_COUNT`). |
| `CLEAR_LOGS` | Clears the in-memory recent-request logs for all domains. Returns `LOGS_CLEARED` and `DOMAINS_CLEARED`. |
| `GET_PROXY_FEATURES` | `QUIET_MODE`, `AUTO_SSL`, `AUTO_SSL_ACTIVE`, `GEO_COUNTRY_LOADED`, `GEO_ASN_LOADED`, `REPUTATION_FEED_CONFIGURED`, `REPUTATION_FEED_INTERVAL_MINUTES`, `REPUTATION_LOCAL_IPS`, `REPUTATION_LOCAL_NETWORKS`, `REPUTATION_FEED_IPS`, `REPUTATION_FEED_NETWORKS`, `REPUTATION_BUMP`, `REPUTATION_FEED_LAST_SUCCESS` (unix time, `0` = never), `REPUTATION_FEED_LAST_ERROR` (`""` = none). |
| `REFRESH_REPUTATION_FEED` | Triggers a background reputation-feed refresh. Returns `REFRESH_STARTED` and `FEED_CONFIGURED`. Fail-open like the scheduled refresh; a refresh already running is not duplicated. |
| `LIST_CONFIG_BACKUPS` | `BACKUPS`: one entry per existing config backup, newest first (`NAME`, `SIZE`, `MODIFIED` in UTC/RFC 3339). Viewer role may run it. |
| `RESTORE_CONFIG_BACKUP` | Restores one backup (parameter `backup`, e.g. `config.json.bak.1`). Validates the backup like a reload, backs up the current file, swaps it in atomically, and reloads; on reload failure the previous file is written back. Returns `RESTORED`. Admin role only. |

## Domain Actions

| Action | Returns |
|--------|---------|
| `GET_TOTAL_REQUESTS` | `TOTAL_REQUESTS` |
| `GET_BYPASSED_REQUESTS` | `BYPASSED_REQUESTS` |
| `GET_TOTAL_REQUESTS_PER_SECOND` | `TOTAL_REQUESTS_REQUESTS_PER_SECOND` |
| `GET_BYPASSED_REQUESTS_PER_SECOND` | `BYPASSED_REQUESTS_REQUESTS_PER_SECOND` |
| `GET_FIREWALL_RULES` | `FIREWALL_RULES` |
| `GET_LOGS` | `LOGS` |
| `CLEAR_LOGS` | Clears the in-memory recent-request logs for this domain. Returns `LOGS_CLEARED` and `DOMAIN`. |
| `GET_STAGE` | `STAGE`, `STAGE_LOCKED`, `UNDER_ATTACK`, `RAW_ATTACK`, `BYPASS_ATTACK`, `BUFFER_COOLDOWN`, `STAGE2_DIFFICULTY`. |
| `SET_STAGE` | Sets the stage (see below). Returns the same fields as `GET_STAGE`. Runtime-only: a reload or restart resets it. |
| `GET_DOMAIN_CONFIG` | The domain's non-secret settings (see below). Secrets are never returned. |
| `SET_DOMAIN_CONFIG` | Adjusts and persists domain settings (see below). Returns the same fields as `GET_DOMAIN_CONFIG`. |
| `ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE` | Add, change, or remove one firewall rule (see below). Returns the updated `FIREWALL_RULES` list. Changes persist to `config.json`. |
| `GET_DOMAIN_FEATURES` | `ADAPTIVE_POW`, `POW_DIFFICULTY_MIN`, `POW_DIFFICULTY_MAX`, `CHALLENGE_PROVIDER`, `CHALLENGE_KEYS_CONFIGURED` (bool — keys themselves are never returned), `WAF_MODE`, `WAF_MODE_EFFECTIVE`, `WAF_INSPECT_BODY`, `WAF_WP_LOGIN_LIMIT`. |
| `GET_ATTACK_REPORT` | Attack summary for the domain (see below). Returns `REPORT` (JSON object) or, with `format=csv`, `REPORT_FORMAT` and `REPORT` (CSV string). |
| `SET_DOMAIN_FEATURES` | Adjusts runtime-tunable feature settings (see below). Returns the same fields as `GET_DOMAIN_FEATURES`. |
| `PURGE_CACHE` | Clears the domain's edge cache, or one path with the `path` parameter. Returns `PURGED` (entries removed) and `DOMAIN`. Operator role may run it. Returns `0` purged when the edge cache is disabled. |
| `SIMULATE_RULE` | Evaluates one rule expression against sample request fields without enforcing anything (see below). Returns `MATCH` and `FIELDS_USED`. Viewer role may run it. |
| `EXPORT_RULES` | `RULES` (the domain's rule set as `{"expression", "action"}` objects), `DOMAIN`, `RULE_COUNT`. Viewer role may run it. |
| `IMPORT_RULES` | Replaces or appends the domain's rule set from a JSON array (see below). Returns the updated `FIREWALL_RULES` list and `IMPORTED`. Operator role may run it. |

`SET_DOMAIN_FEATURES` accepts these parameters (v1 `params` object or v2 query string). Only supplied parameters change; unknown parameters are rejected, and validation is all-or-nothing — on any error, nothing changes:

| Parameter | Values |
|-----------|--------|
| `adaptivePow` | `true` / `false`. |
| `powDifficultyMin` | `0` (default = base difficulty) or `1`–`16`. |
| `powDifficultyMax` | `0` (default = base difficulty + 3) or `1`–`16`. Must not be below the minimum when both are set. |
| `wafMode` | `off`, `log`, or `block`. |
| `wafInspectBody` | `true` / `false`. |
| `wafWpLoginLimit` | Integer `>= 0` (`0` = default of 20/minute). |

Changes apply to the running proxy only and are **not** written back to `config.json` — a reload or restart restores the file's values. For the same settings with persistence, use [`SET_DOMAIN_CONFIG`](#domain-actions), which validates, writes `config.json` atomically, and then applies. Challenge provider and keys cannot be set through the API; they live in `config.json` only.

`SET_STAGE` accepts exactly one of these parameters (v1 `params` object or v2 query string). Unknown parameters are rejected, and validation is all-or-nothing:

| Parameter | Values |
|-----------|--------|
| `stage` | Integer `>= 0`. `0` unlocks and returns to automatic switching from Stage 1 (terminal `stage 0` parity); `1`–`3` (or higher) locks that stage. |
| `underAttack` | `true` locks Stage 3 (under-attack mode); `false` unlocks back to automatic switching. |

`GET_DOMAIN_CONFIG` returns the domain's settings without secrets: `NAME`, `BACKEND`, `SCHEME`, `CERTIFICATE` and `KEY` (file paths, read-only), the six stage thresholds, `STAGE2_DIFFICULTY` (live value), the adaptive proof-of-work and WAF-lite fields (same as `GET_DOMAIN_FEATURES`), `RULES_DRY_RUN`, `WEBHOOK_CONFIGURED`, `TELEGRAM_CONFIGURED` and `TELEGRAM_CHAT_ID`, `EMAIL_CONFIGURED` plus SMTP host/port/username/from/to/TLS, and `RULE_COUNT`. Challenge keys, the Telegram bot token, the email password, and webhook URLs (which embed a token) are never returned — only whether each is configured.

`SET_DOMAIN_CONFIG` accepts these parameters (v1 `params` object or v2 query string). Only supplied parameters change; unknown parameters are rejected, and validation is all-or-nothing — on any error, nothing changes:

| Parameter | Values |
|-----------|--------|
| `bypassStage1`, `bypassStage2` | Integer `>= 0`. |
| `disableBypassStage3`, `disableRawStage3`, `disableBypassStage2`, `disableRawStage2` | Integer `>= 0`. |
| `stage2Difficulty` | `0` (default = 5) or `1`–`16`. |
| `adaptivePow` | `true` / `false`. |
| `powDifficultyMin`, `powDifficultyMax` | `0` (default) or `1`–`16`. Must not contradict each other (see `SET_DOMAIN_FEATURES`). |
| `wafMode` | `off`, `log`, or `block`. |
| `wafInspectBody` | `true` / `false`. |
| `wafWpLoginLimit` | Integer `>= 0` (`0` = default of 20/minute). |
| `rulesDryRun` | `true` / `false`. In dry-run mode, rule matches are logged but take no action. |

`SET_DOMAIN_CONFIG` persists to `config.json` before applying: the file is written atomically (temporary file, rotating backup set, then rename — see [Configuration Backups and Rollback](configuration.md#configuration-backups-and-rollback)), unknown keys in the file are preserved, and a failed write leaves the running proxy untouched. Names, backends, schemes, certificate/key paths, webhooks, alert credentials, and challenge keys are deliberately not settable — change them in `config.json` and reload.

Firewall rule actions take these parameters (v1 `params` object or v2 query string). `index` is 0-based, in the evaluation order `GET_FIREWALL_RULES` returns:

| Action | Parameters |
|--------|-----------|
| `ADD_RULE` | `expression`, `action` (both required). |
| `UPDATE_RULE` | `index` (required), plus `expression` and/or `action` (at least one; omitted fields keep their value). |
| `DELETE_RULE` | `index` (required). |

Every rule is validated before anything changes: the expression must compile in the rule engine and use only documented, populated field names (see [Firewall Rules](firewall-rules.md)), and the action must be an integer, `+N`, or `-N`. An invalid rule is rejected with `ERR_INVALID_PARAM` and a human-readable `ERROR_DETAIL`, and neither the running proxy nor `config.json` changes. Valid changes persist to `config.json` (same atomic write and rotating backups as `SET_DOMAIN_CONFIG`) and take effect immediately, without a reload.

`SIMULATE_RULE` takes `expression` (required, 4 KB cap) and `sample` (optional JSON object string, 10 KB cap) and evaluates the expression against the sample without enforcing anything. Every known rule field starts at its zero value; the sample overlays the fields it names, coerced to the request types (`ip.src` an IP string, counters and `proxy.stage` integers, `proxy.*` flags booleans, the rest strings; strings are also accepted for numbers, booleans, and IPs). Unknown sample fields are rejected. The response reports `MATCH` (bool) and `FIELDS_USED` (field names referenced by the expression, in order, deduplicated). The expression goes through the same validation as rule CRUD, so an uncompilable expression or an unknown field is rejected with `ERR_INVALID_PARAM`.

`IMPORT_RULES` takes `rules` (required: a JSON array of `{"expression", "action"}` objects, 1 MB cap) and `mode` (`replace` by default, or `append`). Every imported rule is validated like rule CRUD, and the whole resulting list is compiled before anything is stored — an invalid import is rejected with `ERR_INVALID_PARAM` and nothing changes. A `replace` import with an empty array clears the rule set. Valid imports persist to `config.json` (same atomic write and rotating backups) and take effect immediately, without a reload.

`GET_ATTACK_REPORT` accepts these parameters (v1 `params` object or v2 query string). Unknown parameters are rejected with `ERR_INVALID_PARAM`:

| Parameter | Values |
|-----------|--------|
| `format` | `json` (default) or `csv`. |
| `top` | Integer `1`–`50`: how many top IPs and fingerprints to list (default `10`). |

The JSON report contains: `domain`, `generated_at`, the attack window (`window_start`, `window_end`, `window_seconds`), `stage`, `stage_manually_set`, `raw_attack`, `bypass_attack`, totals and current/peak rates, `blocks_by_reason`, `challenges_by_stage`, `waf_matches_by_rule`, backend results and average latency, and the top verified/unverified IPs, unknown fingerprints, and countries. The IP, fingerprint, and country tallies are proxy-wide (the firewall tracks them globally) and are labelled as such in the field names (`*_proxy_wide`); country aggregates cover the listed top IPs only. The CSV form renders the same data as one flat table with the header `section,key,value,detail`. Reports contain metadata only — no bodies, cookies, headers, or secrets. See [Attack Reports](configuration.md#attack-reports) for the optional directory export.

## Reserved Paths

These paths are handled by the proxy itself and never forwarded to the backend:

| Path | Description |
|------|-------------|
| `/_bProxy/stats` | Plain-text domain statistics: stage, total/bypassed requests, requests per second, and the proxy fingerprint. |
| `/_bProxy/fingerprint` | Plain-text details about the current request: IP, request counts, suspicion level, TLS fingerprint, JA4 and HTTP fingerprints, HTTP/2 fingerprint, and browser/bot identification. |
| `/_bProxy/verified` | Used by the challenge pages to confirm a solved challenge. Returns `verified`. |
| `/_bProxy/challenge-verify` | `POST` only. Receives provider challenge tokens (Turnstile / hCaptcha) from the challenge page and verifies them server-side. Other methods receive a plain 404. |
| `/_bProxy/credits` | Attribution and license information. |
| `/_bProxy/<adminsecret>/dashboard` | Web dashboard and control panel. Served only on the exact admin-secret path. See [Dashboard](dashboard.md). |
| `/_bProxy/<adminsecret>/metrics` | Prometheus metrics. Served only when `metricsEnabled` is set, and only on the exact admin-secret path; scrapes are neither challenged nor counted. See [Configuration](configuration.md#prometheus-metrics). |

The `/_bProxy/` path prefix and the challenge cookie names are kept unchanged from the original project for compatibility with existing integrations.

## Next Steps

- [Dashboard](dashboard.md) — the browser UI built on this API.
- [Configuration](configuration.md) — where `adminsecret` and `apisecret` are set.
