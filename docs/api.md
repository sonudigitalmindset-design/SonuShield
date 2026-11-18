# API Reference

SonuShield exposes an HTTP API for reading proxy statistics, firewall rules, and logs — and for managing the proxy: stage control, domain configuration, firewall rule editing, log clearing, and configuration reload. Both API versions authenticate with the `apisecret` from your configuration, or with a role-mapped secret (see [Roles and Audit Log](#roles-and-audit-log)). The v1 path additionally contains your `adminsecret`.

> [← README](../README.md)

![API schematic](assets/api.svg)

> The API documentation previously hosted on SwaggerHub is no longer available. This page is the authoritative API reference for the current code.

## Version 1

Send a `POST` request with a JSON body to:

```text
POST /_bProxy/<adminsecret>/api/v1
Header: X-SonuShield-Secret: <apisecret>
Body:   {"domain": "<domain name or empty>", "action": "<ACTION>", "params": {"<key>": "<value>"}}
```

With an empty `domain`, proxy-level actions are executed. With a domain name, domain-level actions are executed for that domain. The optional `params` object carries parameters for actions that take them (`SET_DOMAIN_FEATURES`, `GET_ATTACK_REPORT`, `SET_STAGE`, `SET_DOMAIN_CONFIG`, `ADD_RULE`, `UPDATE_RULE`, `DELETE_RULE`, `PURGE_CACHE`, `SIMULATE_RULE`, `IMPORT_RULES`, `RESTORE_CONFIG_BACKUP`); other actions ignore it.

## Version 2

Send a request to one of these paths (any method with a readable body works; the header is what authenticates the call):

```text
/_bProxy/api/v2/<ACTION>
/_bProxy/api/v2/<domain>/<ACTION>
/_bProxy/api/v2/<domain>/SET_DOMAIN_FEATURES?wafMode=block&...
Header: X-SonuShield-Secret: <apisecret>
```

Actions that take parameters read them from the URL query string in v2 (first value wins per key). Prefer `POST` for actions that change settings.

### The secret header

Both versions accept the secret in the `X-SonuShield-Secret` header. The historical `Proxy-Secret` spelling is still accepted for scripts and older clients, but browsers can never send it: the Fetch Standard forbids page script from setting any header whose name starts with `proxy-` or `sec-`, so `fetch()` silently drops it. Browser-based clients (including the dashboard) must use `X-SonuShield-Secret`.

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

The `apisecret` authenticates as **admin**. Additional secrets mapped to roles via the proxy `apiRoles` config key authenticate as **viewer** (read-only) or **operator** (stage, rules, cache, log clearing, feed refresh, rule import, IP-list entries). Admin-only actions are `SET_DOMAIN_CONFIG`, `SET_DOMAIN_FEATURES`, `RELOAD`, `RESTORE_CONFIG_BACKUP`, `GET_IP_CACHE`, `FILL_IP_CACHE`, `CREATE_DOMAIN_FROM_TEMPLATE`, `IMPORT_DOMAINS`, `REPORT_STRIPE_USAGE`, `TEST_WEBHOOKS`, `EXPORT_BACKUP`, `RESTORE_BACKUP`, and `CF_APPLY_IMPORT`; a lower role calling one gets `ERR_FORBIDDEN`. Unknown actions return `ERR_ACTION_NOT_FOUND` for every role. Tenant-scoped secrets (`"tenant:<name>:<role>"`) keep their role but only for that tenant's domains; see [Multi-Tenancy and Metering](configuration.md#multi-tenancy-and-metering). See [API Roles and Audit Log](configuration.md#api-roles-and-audit-log) for the full permission table.

When SSO is configured, a valid SSO session cookie also authenticates API calls — but only when the request also carries the `X-SonuShield-CSRF: 1` header the dashboard sends. A valid cookie without that header is answered `ERR_FORBIDDEN` and never falls through to the backend. SSO sessions carry a role only and are never tenant-scoped; audit entries for them report the role with an `(sso)` suffix.

Every API call is audit-logged (role, action, domain, scrubbed parameters, peer IP, result) — to the structured log file when JSON logging is configured, otherwise as a compact stdout line. Secret-like parameters are dropped, values are truncated, and presented secrets are never logged, including for rejected calls (audited as role `unauthenticated`).

## Proxy Actions

| Action | Returns |
|--------|---------|
| `GET_PROXY_STATS` | `CPU_USAGE`, `RAM_USAGE` |
| `GET_PROXY_STATS_CPU_USAGE` | `CPU_USAGE` |
| `GET_PROXY_STATS_RAM_USAGE` | `RAM_USAGE` |
| `GET_IP_REQUESTS` | `TOTAL_IP_REQUESTS`, `CHALLENGE_IP_REQUESTS` |
| `GET_FINGERPRINT_REQUESTS` | `TOTAL_FINGERPRINT_REQUESTS` (unknown fingerprints only) |
| `GET_IP_CACHE` | `IP_CACHE_COUNT` only (admin-only: the cache holds live challenge cookies, so keys and values are never returned). |
| `FILL_IP_CACHE` | Diagnostic action: fills the IP cache with test entries. |
| `RELOAD` | Validates `config.json` and, only if it is valid, reloads it into the running proxy. Returns `RELOADED`. On an invalid file returns `ERR_RELOAD_FAILED` and the running config is untouched. A successful reload resets request counters and stage locks, like the terminal `reload` command; admin/API secret changes still need a restart. |
| `GET_DOMAINS` | `DOMAINS`: one summary per configured domain (`NAME`, `BACKEND`, `SCHEME`, `STAGE`, `STAGE_LOCKED`, `UNDER_ATTACK`, `TOTAL_RPS`, `BYPASSED_RPS`, `TOTAL_REQUESTS`, `BYPASSED_REQUESTS`, `RULE_COUNT`, `TENANT`). Tenant-scoped callers see only their own tenant's domains. |
| `SEARCH_LOGS` | Searches the structured JSON log (see below). Accepts an optional `domain` parameter. Viewer role may run it. |
| `GET_ATTACK_MAP` | Top countries by blocks + challenges in a recent window (see below). Viewer role may run it. |
| `GET_TENANTS` | `TENANTS`: one entry per tenant (`TENANT`, `DOMAINS`, `DOMAIN_COUNT`). Viewer role may run it. |
| `GET_TENANT_USAGE` | `USAGE`: per-tenant request, blocked, and bandwidth counters (see below). Accepts an optional `tenant` parameter. Viewer role may run it. Tenant-scoped callers are forced to their own tenant. |
| `CLEAR_LOGS` | Clears the in-memory recent-request logs for all domains. Returns `LOGS_CLEARED` and `DOMAINS_CLEARED`. |
| `GET_PROXY_FEATURES` | `QUIET_MODE`, `AUTO_SSL`, `AUTO_SSL_ACTIVE`, `GEO_COUNTRY_LOADED`, `GEO_ASN_LOADED`, `REPUTATION_FEED_CONFIGURED`, `REPUTATION_FEED_INTERVAL_MINUTES`, `REPUTATION_LOCAL_IPS`, `REPUTATION_LOCAL_NETWORKS`, `REPUTATION_FEED_IPS`, `REPUTATION_FEED_NETWORKS`, `REPUTATION_BUMP`, `REPUTATION_FEED_LAST_SUCCESS` (unix time, `0` = never), `REPUTATION_FEED_LAST_ERROR` (`""` = none). |
| `REFRESH_REPUTATION_FEED` | Triggers a background reputation-feed refresh. Returns `REFRESH_STARTED` and `FEED_CONFIGURED`. Fail-open like the scheduled refresh; a refresh already running is not duplicated. |
| `LIST_CONFIG_BACKUPS` | `BACKUPS`: one entry per existing config backup, newest first (`NAME`, `SIZE`, `MODIFIED` in UTC/RFC 3339). Viewer role may run it. |
| `RESTORE_CONFIG_BACKUP` | Restores one backup (parameter `backup`, e.g. `config.json.bak.1`). Validates the backup like a reload, backs up the current file, swaps it in atomically, and reloads; on reload failure the previous file is written back. Returns `RESTORED`. Admin role only. |
| `GET_DOMAIN_TEMPLATES` | `TEMPLATES`: the built-in domain templates (`NAME`, `TITLE`, `DESCRIPTION`, `PRESET`). Viewer role may run it. |
| `CREATE_DOMAIN_FROM_TEMPLATE` | Creates one domain from a template (see below). Validates, persists, and reloads; on reload failure the file is rolled back. Admin role only. |
| `IMPORT_DOMAINS` | Bulk-imports domains from JSON or CSV (see below). All-or-nothing: an invalid entry rejects the whole import. Admin role only. |
| `GET_STRIPE_STATUS` | `ENABLED`, `INTERVAL`, `KEY_MODE` (`test` / `live` / `""`), `LAST_REPORT`. The secret key is never returned. Viewer role may run it. |
| `REPORT_STRIPE_USAGE` | Runs one usage-reporting pass immediately (deltas only, idempotent). Returns `RESULTS` per tenant. Admin role only. |
| `GET_WEBHOOK_STATUS` | `ENDPOINTS` (hosts only, never full URLs or secrets), `QUEUE`, `DROPPED`. Viewer role may run it. |
| `TEST_WEBHOOKS` | Queues one `test` event per configured endpoint, ignoring event filters. Returns `QUEUED`. Admin role only. |
| `EXPORT_BACKUP` | Returns a backup envelope (`BACKUP`) holding the full config document. Secrets are redacted by default; with `include_secrets=true` and a `passphrase` parameter they are included encrypted. Admin role only. See below. |
| `RESTORE_BACKUP` | Restores a backup envelope (parameters `backup`, `passphrase`). Validates before applying; a bad backup changes nothing. Admin role only. Distinct from `RESTORE_CONFIG_BACKUP`. See below. |
| `GET_SECURITY_GRADE` | Configuration audit: `GRADE` (A–F), `SCORE` (0–100), `CHECKS` (id, title, severity, status, detail, guidance), `DISCLAIMER`. No secret values are ever included. Viewer role may run it. See below. |
| `GET_CERT_STATUS` | `ENABLED`, `ALERT_DAYS`, `DOMAINS` (per domain: `DOMAIN`, `STATUS`, `EXPIRES`, `DAYS_REMAINING`, `LAST_ALERT`). Viewer role may run it. |
| `GET_SUBDOMAIN_STATUS` | `ENABLED`, `INTERVAL_MINUTES`, `FAILURE_THRESHOLD`, `DOMAINS` (per listed name: `NAME`, `ADDRESSES`, `BASELINE_SET`, `LAST_CHECKED`, `CONSECUTIVE_FAILURES`, `LAST_ERROR`). Viewer role may run it. |
| `LIST_RULE_PACKS` | `PACKS` (imported-pack registry records: name, version, source, description, domain, rule count, mode, import time), `COUNT`. Viewer role may run it. |
| `APPROVE_ACTION` / `REJECT_ACTION` | Approve (and execute) or reject a pending two-person approval (parameter `APPROVAL_ID`). Operator role may run them. See below. |
| `LIST_APPROVALS` | `ENABLED`, `APPROVALS` (pending requests: id, action, domain, requester role, tenant, created/expiry times — stored parameters are never returned), `COUNT`. Viewer role may run it. |
| `GET_SHARING_STATUS` | `ENABLED`, `PEERS` (per peer: `NAME`, `URL`, `LAST_SUCCESS`, `LAST_ERROR` — secrets are never returned), `LOCAL` and `RECEIVED` indicator counts. Viewer role may run it. |
| `ADD_INDICATOR` / `REMOVE_INDICATOR` | Add or remove one local threat indicator (`type` `ip`/`fingerprint`, `value`, optional `reason`, optional `ttl` in seconds, default 3600; remove takes `type` + `value`). Returns `ADDED` / `REMOVED`. Operator role may run them. |
| `PULL_INDICATORS` / `PUSH_INDICATORS` | Trigger an immediate pull from / push to all peers in the background. Returns `PULL_STARTED` / `PUSH_STARTED`. Operator role may run them. |
| `GET_BGP_STATUS` | `ENABLED`, `PREFIXES` (per prefix: `PREFIX`, `EXPECTED`, `LAST_ORIGINS`, `ANNOUNCED`, `ALERTING`, `LAST_CHECK`, `LAST_ERROR`). Viewer role may run it. |
| `GET_SYNTHETIC_STATUS` | `ENABLED`, `CHECKS` (per check: `NAME`, `URL`, `LAST_RUN`, `OK`, `LATENCY_MS`, `LAST_ERROR`, `CONSECUTIVE_FAILURES`, `LATENCY_BREACHING`). Viewer role may run it. |
| `GET_ONCALL_STATUS` | `ENABLED`, `CURRENT` (the responder on call now, or `\"\"`), `ESCALATION_MINUTES`, `RESPONDERS` (names only — channel settings are never returned), `OPEN_ALERTS` (`ID`, `TITLE`, `DOMAIN`, `CREATED_AT`, `AGE_SECONDS`, `ESCALATED`). Viewer role may run it. |
| `ACK_ALERT` | Acknowledges one tracked alert (parameter `id`), silencing its escalation. Returns `ACKNOWLEDGED`. Operator role may run it. |
| `PREVIEW_SERVER_IMPORT` | Dry-run conversion of nginx/Apache config text (`format` `nginx`/`apache`, `data`) into domain entries. Read-only; returns `DOMAINS`, `SKIPPED`, `WARNINGS`, `NOT_IMPORTED`. Operator role may run it. See below. |
| `APPLY_SERVER_IMPORT` | Creates the converted domains (same parameters as the preview, plus optional `template`). All-or-nothing, validated, persisted, reloaded. Admin role only. See below. |

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
| `GET_DOMAIN_CONFIG` | The domain's non-secret settings (see below). Secrets are never returned. `ORIGIN_LOCK_CONFIGURED` reports whether an origin-lock secret is set; `TENANT` reports the domain's tenant. |
| `GET_IP_LISTS` | `ALLOWLIST` and `BLOCKLIST`: the domain's live (unexpired) IP-list entries. Viewer role may run it. |
| `ADD_IP_ENTRY` / `REMOVE_IP_ENTRY` | Add or remove one IP-list entry (see below). Changes persist to `config.json`. Operator role may run them. |
| `SEARCH_LOGS` | Searches the structured JSON log for this domain only (see below). Viewer role may run it. |
| `SET_DOMAIN_CONFIG` | Adjusts and persists domain settings (see below). Returns the same fields as `GET_DOMAIN_CONFIG`. |
| `ADD_RULE` / `UPDATE_RULE` / `DELETE_RULE` | Add, change, or remove one firewall rule (see below). Returns the updated `FIREWALL_RULES` list. Changes persist to `config.json`. |
| `GET_DOMAIN_FEATURES` | `ADAPTIVE_POW`, `POW_DIFFICULTY_MIN`, `POW_DIFFICULTY_MAX`, `CHALLENGE_PROVIDER`, `CHALLENGE_KEYS_CONFIGURED` (bool — keys themselves are never returned), `WAF_MODE`, `WAF_MODE_EFFECTIVE`, `WAF_INSPECT_BODY`, `WAF_WP_LOGIN_LIMIT`, `MEMORY_HARD_POW`, `MEMORY_HARD_POW_BITS`, `MEMORY_HARD_POW_MEMORY_KB`, `MEMORY_HARD_POW_TIME`, `CHALLENGE_ROTATION`, `CHALLENGE_ROTATION_MODE`, `BEHAVIOR_CHECK`, `BEHAVIOR_ENFORCE`, `INVISIBLE_MARKERS`, `SIGNED_URL_CONFIGURED` (bool — the secret is never returned), `HOTLINK_PROTECT`, `CANARY_CONFIGURED` (bool — paths and token values are never returned), `ATTESTATION_CONFIGURED` (bool — the secret or JWKS URL is never returned), `PASSKEY_CONFIGURED` (bool — no credential material is returned). The memory-hard, rotation, behavior, marker, signed-URL, hotlink, and canary fields are read-only reports of the config-file policy; they cannot be set through the API. |
| `GET_ATTACK_REPORT` | Attack summary for the domain (see below). Returns `REPORT` (JSON object) or, with `format=csv`, `REPORT_FORMAT` and `REPORT` (CSV string). |
| `SET_DOMAIN_FEATURES` | Adjusts runtime-tunable feature settings (see below). Returns the same fields as `GET_DOMAIN_FEATURES`. |
| `PURGE_CACHE` | Clears the domain's edge cache, or one subset with exactly one selector parameter: `path` (one URL path, with any query string), `prefix` (every path starting with the prefix), or `tag` (entries recorded with that `Cache-Tag` value). Returns `PURGED` (entries removed) and `DOMAIN`. Operator role may run it. Returns `0` purged when the edge cache is disabled. |
| `SIMULATE_RULE` | Evaluates one rule expression against sample request fields without enforcing anything (see below). Returns `MATCH` and `FIELDS_USED`. Viewer role may run it. |
| `EXPORT_RULES` | `RULES` (the domain's rule set as `{"expression", "action"}` objects), `DOMAIN`, `RULE_COUNT`. Viewer role may run it. |
| `IMPORT_RULES` | Replaces or appends the domain's rule set from a JSON array (see below). Returns the updated `FIREWALL_RULES` list and `IMPORTED`. Operator role may run it. |
| `GET_SHADOW_REPORT` | Shadow evaluation report (see below). Viewer role may run it. |
| `GET_LATENCY` | Latency and SLA figures (see below). Viewer role may run it. |
| `GET_POSTMORTEM` | Attack timeline and postmortem report (see below). Viewer role may run it. |
| `SET_MAINTENANCE` / `GET_MAINTENANCE` | Enable/disable the maintenance override and report maintenance state (see below). Operator role may run them. |
| `IMPORT_RULE_PACK` | Imports a rule pack from a file path or URL (see below). Returns `PACK_NAME`, `PACK_VERSION`, `IMPORTED`, and possibly `REGISTRY_WARNING`. Operator role may run it. |
| `CF_PREVIEW_IMPORT` | Read-only Cloudflare import preview (see below). Operator role may run it. |
| `CF_APPLY_IMPORT` | Applies a Cloudflare import (see below). Returns `APPLIED`, `SKIPPED_COUNT`, `SKIPPED`, `MODE`, and the updated `FIREWALL_RULES`. Admin role only. |
| `ENROLL_PASSKEY` | Enrolls one passkey credential (parameters `credentialId`, `kty`, `crv`/`x`/`y` for EC or `n`/`e` for RSA, `userHandle`, `label`). Public-key material only; never a secret. Returns `ENROLLED` and `CREDENTIALS`. Admin role only. |
| `LIST_PASSKEYS` | `CREDENTIALS`: enrolled credential metadata (`CREDENTIAL_ID`, `LABEL`, `USER_HANDLE`, `SIGN_COUNT`, `KEY_TYPE`, `CURVE`), plus `CONFIGURED`. No key material is returned. Viewer role may run it. |
| `REMOVE_PASSKEY` | Removes one enrolled credential (parameter `credentialId`). Returns `REMOVED` and `CREDENTIALS`. Operator role may run it. |
| `GET_STUFFING_STATUS` | `ENABLED`, `MODE`, `PER_IP_THRESHOLD`, `DISTRIBUTED_THRESHOLD`, `WINDOW_SECONDS`, `PATHS` (per watched path: `PATH`, `FAILURES`, `DISTINCT_IP`, `FLAGGED`, `KIND`). Counts only. Viewer role may run it. |
| `GET_HIJACK_STATUS` | `ENABLED`, `MODE`, `BINDINGS`, `FLAGGED_RECENT`. Counts only — no cookie values or fingerprints. Viewer role may run it. |
| `GET_OPENAPI_STATUS` | `LOADED` (whether a valid spec is in force), `PATHS` (validated prefixes), `CHECKED`, `VIOLATIONS`. Viewer role may run it. |
| `GET_DLP_STATUS` | `ENABLED`, `MODE` (`redact`/`block`), `SCANNED`, `REDACTED`, `BLOCKED`, `PATTERNS` (names and `MATCHES` only). Pattern names and counts only — never matched content. Viewer role may run it. |
| `GET_CSP_REPORTS` | Stored CSP violation reports, newest first (`limit` parameter, 1–200, default 50), plus `TOTAL`. Viewer role may run it. |
| `GET_RUM_STATS` | `COUNT` (beacons), `METRICS` (per metric: `SAMPLES`, `AVERAGE`, `P50`, `P95`), `PATHS` (top paths: `PATH`, `COUNT`, `AVG_TTFB`, `AVG_LOAD`). Viewer role may run it. |
| `GET_CACHE_STATS` | Edge-cache counters: `HITS`, `MISSES`, `BYTES_SERVED`, `STORES`, `EVICTIONS`, `PURGES`, `STALE_SERVES`, `ENTRIES`, `BYTES`. Viewer role may run it. |

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

`GET_DOMAIN_CONFIG` returns the domain's settings without secrets: `NAME`, `BACKEND`, `SCHEME`, `CERTIFICATE` and `KEY` (file paths, read-only), the six stage thresholds, `STAGE2_DIFFICULTY` (live value), the adaptive proof-of-work and WAF-lite fields (same as `GET_DOMAIN_FEATURES`), `RULES_DRY_RUN`, `WEBHOOK_CONFIGURED`, `TELEGRAM_CONFIGURED` and `TELEGRAM_CHAT_ID`, `EMAIL_CONFIGURED` plus SMTP host/port/username/from/to/TLS, `TWILIO_CONFIGURED` plus `TWILIO_FROM` and `TWILIO_TO`, and `RULE_COUNT`. Challenge keys, the Telegram bot token, the email password, the Twilio auth token, and webhook URLs (which embed a token) are never returned — only whether each is configured.

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
| `ADD_RULE` | `expression`, `action` (both required), `schedule` (optional cron expression; empty means always active). |
| `UPDATE_RULE` | `index` (required), plus `expression`, `action`, and/or `schedule` (at least one; omitted fields keep their value; an empty `schedule` clears the schedule). |
| `DELETE_RULE` | `index` (required). |

Every rule is validated before anything changes: the expression must compile in the rule engine and use only documented, populated field names (see [Firewall Rules](firewall-rules.md)), and the action must be an integer, `+N`, or `-N`. An invalid rule is rejected with `ERR_INVALID_PARAM` and a human-readable `ERROR_DETAIL`, and neither the running proxy nor `config.json` changes. Valid changes persist to `config.json` (same atomic write and rotating backups as `SET_DOMAIN_CONFIG`) and take effect immediately, without a reload.

`SIMULATE_RULE` takes `expression` (required, 4 KB cap) and `sample` (optional JSON object string, 10 KB cap) and evaluates the expression against the sample without enforcing anything. Every known rule field starts at its zero value; the sample overlays the fields it names, coerced to the request types (`ip.src` an IP string, counters and `proxy.stage` integers, `proxy.*` flags booleans, the rest strings; strings are also accepted for numbers, booleans, and IPs). Unknown sample fields are rejected. The response reports `MATCH` (bool) and `FIELDS_USED` (field names referenced by the expression, in order, deduplicated). The expression goes through the same validation as rule CRUD, so an uncompilable expression or an unknown field is rejected with `ERR_INVALID_PARAM`.

`IMPORT_RULES` takes `rules` (required: a JSON array of `{"expression", "action"}` objects, 1 MB cap) and `mode` (`replace` by default, or `append`). Every imported rule is validated like rule CRUD, and the whole resulting list is compiled before anything is stored — an invalid import is rejected with `ERR_INVALID_PARAM` and nothing changes. A `replace` import with an empty array clears the rule set. Valid imports persist to `config.json` (same atomic write and rotating backups) and take effect immediately, without a reload.

`ADD_IP_ENTRY` takes `list` (`allowlist` or `blocklist`, required), `target` (bare IP or CIDR, required), `expires` (optional Unix timestamp, `0` = never; a past timestamp is rejected), and `note` (optional, 200 characters max). Adding an entry whose target string already exists on that list updates it in place. `REMOVE_IP_ENTRY` takes `list` and `target`; removing a missing entry is rejected with `ERR_INVALID_PARAM`. Both validate all parameters before changing anything, persist to `config.json` (same atomic write and rotating backups as rule edits), rebuild the compiled prefix sets, and apply immediately. Expired entries are never returned by `GET_IP_LISTS`.

`SEARCH_LOGS` searches the structured JSON log files (current plus rotated, newest first). It requires JSON logging (`logFormat: "json"` plus `logFile`); without it, the action fails with `ERR_JSON_LOGS_NOT_CONFIGURED`. As a proxy action it searches all domains, or one domain with the `domain` parameter; as a domain action it is scoped to that domain. Filters (all optional): `ip`, `action`, and `event` (exact match), `from` and `to` (Unix timestamps). Pagination: `page` (default `1`) and `perPage` (default `50`, max `200`). The scan is bounded: at most 200,000 lines scanned and 5,000 matches kept. The response reports `ENTRIES` (newest first), `TOTAL`, `PAGE`, `PER_PAGE`, `SCANNED`, `FILES`, `TRUNCATED`, and `LOGS_CONFIGURED`.

`GET_ATTACK_MAP` counts `block` and `challenge` log events by country over a recent window. Parameters (both optional): `top` (default `10`, clamped `1`–`50`) and `window` in seconds (default `3600`, clamped `60`–`86400`). The response reports `COUNTRIES` (`COUNTRY`, `BLOCKS`, `CHALLENGES`, `TOTAL`, most-attacked first), `GEO_CONFIGURED`, `LOGS_CONFIGURED`, `SCANNED`, and `TRUNCATED`. Without a GeoIP database it returns an empty list with `GEO_CONFIGURED: false` (not an error); without JSON logs, an empty list with `LOGS_CONFIGURED: false`. Unknown parameters are ignored.

`GET_TENANT_USAGE` reports `USAGE`, one entry per tenant: `TENANT`, `DOMAINS`, `REQUESTS`, `BLOCKED` (approximated as total minus bypassed, clamped at zero), `BYTES_IN`, `BYTES_OUT`, and `BYTES_TOTAL`. With no `tenant` parameter it reports all tenants (or, for a tenant-scoped caller, only its own); with a `tenant` parameter it reports that tenant, and a tenant-scoped caller asking for another tenant gets `ERR_FORBIDDEN`. Bandwidth is an estimate: challenge, block, and error pages and WebSocket traffic are not counted, and headers are excluded.

`GET_ATTACK_REPORT` accepts these parameters (v1 `params` object or v2 query string). Unknown parameters are rejected with `ERR_INVALID_PARAM`:

| Parameter | Values |
|-----------|--------|
| `format` | `json` (default) or `csv`. |
| `top` | Integer `1`–`50`: how many top IPs and fingerprints to list (default `10`). |

The JSON report contains: `domain`, `generated_at`, the attack window (`window_start`, `window_end`, `window_seconds`), `stage`, `stage_manually_set`, `raw_attack`, `bypass_attack`, totals and current/peak rates, the risk-score summary (`risk_avg`, `risk_max`, `risk_samples`), `blocks_by_reason`, `challenges_by_stage`, `waf_matches_by_rule`, backend results and average latency, and the top verified/unverified IPs, unknown fingerprints, and countries. The IP, fingerprint, and country tallies are proxy-wide (the firewall tracks them globally) and are labelled as such in the field names (`*_proxy_wide`); country aggregates cover the listed top IPs only. The CSV form renders the same data as one flat table with the header `section,key,value,detail`. Reports contain metadata only — no bodies, cookies, headers, or secrets. See [Attack Reports](configuration.md#attack-reports) for the optional directory export.

`CREATE_DOMAIN_FROM_TEMPLATE` takes `name`, `backend`, `scheme`, `template` (one of `plain`, `wordpress`, `static`, `api`, `ecommerce`), `certificate`, and `key`. The template supplies starting-point presets (see below); no template ships firewall rules. The resulting domain is validated like a hand-written config entry, appended to `config.json` (unknown keys preserved), and applied via the validated reload; on reload failure the file is rolled back and nothing changes. Tenant-scoped callers are forbidden, and template creation cannot assign a tenant — set tenants in `config.json`.

`IMPORT_DOMAINS` takes `format` (`json` or `csv`) and `data` (the document string, 1 MB cap). JSON entries and CSV rows carry the same fields as `CREATE_DOMAIN_FROM_TEMPLATE` (CSV columns: `name,backend,scheme,template,certificate,key`). Every entry is validated and the full resulting configuration is compiled before anything is stored — an invalid entry rejects the whole import and nothing changes. Tenant assignment is not supported in import entries.

Domain templates are starting points, documented as such:

| Template | Preset |
|----------|--------|
| `plain` | Standard defaults: WAF log-only, no caching, no presets. |
| `wordpress` | WAF log-only with body inspection, a tighter login-flood limit (10/minute), and honeypot paths for `/wp-config.php` and `/.env`. |
| `static` | Edge caching (5-minute TTL, 256 MB) with stampede guard, Brotli, and image optimization. |
| `api` | WAF log-only with body inspection and Brotli. No caching: API responses must not be shared between callers. |
| `ecommerce` | WAF log-only with body inspection and Brotli, plus a honeypot path for `/.env`. No caching: carts and checkouts are personal. |

`EXPORT_BACKUP` takes `include_secrets` (`true`/`false`, default `false`) and `passphrase`. With secrets excluded (default), every secret-bearing field in the returned envelope is replaced by the `REDACTED` placeholder and the envelope's `secrets` mode is `redacted`. With `include_secrets=true`, a passphrase is required and the secrets are included encrypted (scrypt + AES-256-GCM, bound to the config document); the mode is `encrypted`. The passphrase is never a URL parameter in the dashboard flow and never appears in audit logs.

`RESTORE_BACKUP` takes `backup` (the envelope JSON string, 1 MB cap) and `passphrase` (required for encrypted envelopes; ignored otherwise). The envelope is validated (format, version, config present), secrets are resolved (redacted envelopes take their values from the current config file — so a redacted restore onto a fresh instance fails; encrypted envelopes decrypt with the passphrase), and any remaining placeholder at a secret path refuses the restore. The resulting config is then validated like a reload before it is written; on reload failure the previous file is written back. Returns `RESTORED`, `DOMAINS`, `SECRETS_MODE`, and `RELOADED`. The backup holds the config document only — TLS certificate/key files, GeoIP databases, and custom challenge-template files live outside it and must be copied separately when migrating, keeping their paths valid. The same envelope format is produced by the `backup` / `restore` CLI subcommands (see [Installation](installation.md#command-line-interface)).

`GET_SHADOW_REPORT` takes no parameters and reports `SHADOW_ENABLED`, `SHADOW_RULES` (count), `SHADOW_WAF`, `EVALUATED`, `WOULD_BLOCK`, `WOULD_CHALLENGE`, `WOULD_ALLOW`, `DISAGREEMENTS` (shadow vs live outcomes), `RULE_MATCHES` (tallies per shadow rule), and `RECENT` (the last 50 decisions: time, IP — masked when privacy mode is on — method, path, live and shadow outcomes and suspicion levels, matched rules, WAF rule).

`GET_LATENCY` takes no parameters and reports `SAMPLES`, `ERRORS`, `STATUS_5XX`, `TTFB_P50_MS` / `TTFB_P95_MS` / `TTFB_P99_MS`, `TOTAL_P50_MS` / `TOTAL_P95_MS` / `TOTAL_P99_MS`, `PROXY_MEAN_MS`, `UPTIME_PCT` (origin success rate over the retained window, not wall-clock uptime), `SLA_TARGET_PCT`, `ERROR_BUDGET_REMAINING_PCT`, and `WINDOW_START` / `WINDOW_END`. See [Latency and SLA](configuration.md#latency-and-sla) for the measurement points.

`GET_POSTMORTEM` accepts `which` (`last`, default, or `current` — `last` falls back to the current attack when no finished attack exists), `format` (`json`, default, or `text`), and `top` (`1`–`50`, default `10`). With no recorded attack it returns `FOUND: false` and a `NOTE`. Otherwise it returns the attack timeline (`TIMELINE`: time, kind, detail, stage, RPS, allowed RPS), `START`/`END`/`DURATION`, `PEAK_RPS`, `PEAK_RPS_ALLOWED`, `MAX_STAGE`, `FINISHED`, the proxy-wide top sources and tallies (labelled as such), and `LATENCY_SAMPLES`. With `format=text` the same report is returned as readable text in `REPORT_TEXT`.

`GET_SECURITY_GRADE` takes no parameters. Checks cover secret strength (length/placeholder only, never values), secret distinctness, role-secret hygiene, certificate validity, HSTS, WAF coverage, stage-threshold sanity, CORS, challenge-provider keys, debug-domain exposure, webhook/feed URL schemes, and informational checks for post-quantum TLS, SSO, metrics exposure, and privacy mode. Scoring: pass = 1, warn = 0.5, fail = 0; informational checks are excluded; any high-severity failure caps the grade at C and any failure caps it at B. The response carries a disclaimer: a configuration audit, not a penetration test.

`SET_MAINTENANCE` takes `ENABLED` (`true`/`false`, required), `MESSAGE` (optional, 500 characters max), and `DURATION_MINUTES` (optional, `0` = until disabled). It sets the in-memory maintenance override for the domain and returns `ENABLED` and `MESSAGE`. `GET_MAINTENANCE` takes no parameters and returns `DOMAIN`, `OVERRIDE_ENABLED`, `OVERRIDE_MESSAGE`, `OVERRIDE_ACTIVE`, `SCHEDULED_WINDOWS`, `SCHEDULED_ACTIVE`, `EFFECTIVE_ACTIVE`, and `EFFECTIVE_MESSAGE`.

`IMPORT_RULE_PACK` takes `SOURCE` (required: a file path on the server or an http/https URL) and `MODE` (`replace`, default, or `append`). URL fetches are bounded (1 MB cap, 10-second timeout, at most 3 redirects). The pack document (name, version, source, description, rules) is validated like a rule import — all-or-nothing — and pack metadata is recorded in the `proxy.rulePacks` registry in `config.json`. If the registry write fails after the rules are applied, the response still succeeds and carries `REGISTRY_WARNING`, since the rules are live and the registry is advisory.

`CF_PREVIEW_IMPORT` takes no parameters and is read-only: it fetches the domain's Cloudflare firewall rules (token and zone ID from `config.json`), translates them, and returns `TRANSLATED` (Cloudflare expression/action/description, SonuShield expression/action, caveat notes), `SKIPPED` (with reasons), `TRANSLATED_COUNT`, `SKIPPED_COUNT`, `NOT_IMPORTED_SETTINGS`, and a `NOTE`. `CF_APPLY_IMPORT` takes `MODE` (`append`, default, or `replace`), re-fetches and re-translates, and applies the translated rules. Both fail with `ERR_FETCH_FAILED` when the Cloudflare API cannot be reached; the token is never logged or included in error details.

When two-person approval is enabled (`proxy.twoPersonApproval`), a gated action's first call does not execute: it returns `success: false` with `ERR_APPROVAL_REQUIRED`, an `APPROVAL_ID`, and `EXPIRES_AT`. `APPROVE_ACTION` (parameter `APPROVAL_ID`) executes the stored action only when called by a different caller who also satisfies the action's role and tenant scoping; `REJECT_ACTION` rejects it (the requester may cancel their own request). Failed approval/rejection checks leave the request pending. Gated actions: `RESTORE_CONFIG_BACKUP`, `RESTORE_BACKUP`, `IMPORT_RULES`, `IMPORT_DOMAINS`, `IMPORT_RULE_PACK`, `CF_APPLY_IMPORT`, and `CREATE_DOMAIN_FROM_TEMPLATE`. When the feature is off, all of these execute immediately. Pending state is in-memory with lazy expiry; every approval event is audit-logged.

`PREVIEW_SERVER_IMPORT` takes `format` (`nginx` or `apache`, required) and `data` (the config text, required, 1 MB cap). It returns `DOMAINS` (the converted domain entries, in the same shape as `IMPORT_DOMAINS` accepts), `COUNT`, `SKIPPED` (blocks with reasons), `WARNINGS` (certificate/key pairing drops, wildcard names, malformed backends), and `NOT_IMPORTED` (directives outside the documented subset). `APPLY_SERVER_IMPORT` takes the same parameters plus an optional `template` name (default `standard`) applied to every created domain, and creates the domains through the bulk-import machinery: all-or-nothing, validated against the existing domain rules, persisted to `config.json`, and reloaded. On reload failure the file is rolled back.

`ENROLL_PASSKEY` takes `credentialId` (base64url, required), the public key as flat JWK fields (`kty`, plus `crv`/`x`/`y` for EC P-256 or `n`/`e` for RSA — all base64url, required), `userHandle` (base64url, required), and `label` (optional). The credential is appended to the domain's `credentialsFile` atomically. `LIST_PASSKEYS` returns metadata only — no public key material. `REMOVE_PASSKEY` takes `credentialId`.

`GET_CSP_REPORTS` takes `limit` (`1`–`200`, default `50`) and returns the stored reports newest first, each with the retained fields only (document/blocked URIs query-stripped, directives, source file/position, status, disposition, received time).

`GET_RUM_STATS` returns `COUNT` (total beacons), `METRICS` keyed by timing name (`dns`, `connect`, `tls`, `ttfb`, `dom`, `load`) with `SAMPLES`, `AVERAGE`, `P50`, and `P95` (10 ms buckets), and `PATHS` (top 10 paths with `COUNT`, `AVG_TTFB`, `AVG_LOAD`). With no samples it returns zeroed figures. In privacy mode the per-path breakdown is empty.

## Public API

A versioned, read-only API for tenants and resellers, separate from the control API above. Base path `/_bProxy/public/v1/`, authenticated by API key (see [Public API](configuration.md#public-api)). All responses use the envelope `{"ok": true, "data": …}` on success and `{"ok": false, "error": {"code", "message"}}` on failure, with matching HTTP status codes. Only `GET` is accepted; other methods get `405`, unknown endpoints and versions get a JSON `404` and are never proxied. Unauthenticated requests get JSON `401` errors at any stage (the suspect firewall block for very high suspicion levels still applies to every path).

| Endpoint | Returns |
|----------|---------|
| `GET v1/ping` | `tenant`, `key_name`: proves the key authenticates and shows its scope. |
| `GET v1/usage` | Tenant aggregate: `tenant`, `requests`, `blocked`, `bytes_in`, `bytes_out`, `bytes_total`, `domains`. With `?domain=`, only that domain — a domain outside the caller's tenant 404s exactly like a nonexistent one. Counters are the metering estimates (challenge/block/error pages, WebSocket traffic, and headers excluded). |
| `GET v1/domains` | `domains`: the tenant's domains with `name`, `stage`, `stage_name`, `stage_locked`, `under_attack`, `requests`, `blocked`, `bytes_total`. |

Rate limits are per key (fixed window, default 60/minute), with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers and `Retry-After` on `429`. Minimal Go and Python clients with examples live in [`sdk/`](../sdk/README.md).

## Reserved Paths

These paths are handled by the proxy itself and never forwarded to the backend:

| Path | Description |
|------|-------------|
| `/_bProxy/stats` | Plain-text domain statistics: stage, total/bypassed requests, requests per second, and the proxy fingerprint. |
| `/_bProxy/fingerprint` | Plain-text details about the current request: IP, request counts, suspicion level, TLS fingerprint, JA4 and HTTP fingerprints, HTTP/2 fingerprint, and browser/bot identification. |
| `/_bProxy/verified` | Used by the challenge pages to confirm a solved challenge. Returns `verified`. |
| `/_bProxy/challenge-verify` | `POST` only. Receives provider challenge tokens (Turnstile / hCaptcha) from the challenge page and verifies them server-side. Other methods receive a plain 404. |
| `/_bProxy/pow-verify` | `POST` only. Receives memory-hard puzzle solutions (single-use nonce + counter) and sets the verification cookie on success. Failures get a generic 403/404. Only meaningful when `memoryHardPow` is enabled for a domain. |
| `/_bProxy/public/v1/…` | Versioned public API for tenants/resellers (API-key auth, read-only). See [Public API](#public-api). |
| `/_bProxy/credits` | Attribution and license information. |
| `/_bProxy/passkey-verify` | `POST` only. Receives WebAuthn assertion responses from the passkey challenge page and verifies them server-side, setting the verification cookie on success. Other methods receive a plain 404. Only meaningful when passkey is configured with enrolled credentials; otherwise the captcha is served. |
| `/_bProxy/csp-report` | `POST` only. Receives CSP violation reports (legacy and Reporting API formats), storing a bounded, trimmed subset. Always answers `204` for a parseable report. Non-POST requests receive a plain 404. |
| `/_bProxy/threat-sharing/indicators` | `GET`/`POST` for the opt-in threat-sharing network. HMAC-signed; bad signatures get `401`. When sharing is disabled the path is not handled. |
| `/_bProxy/rum` | `POST` only. Receives real-user timing beacons; always answers `204`. |
| `/_bProxy/rum.js` | `GET` only. The RUM snippet the operator embeds on origin pages. Never injected into origin content. |
| `/_bProxy/origin-signal` | `POST` only. Origin-side failure signals (login failures) authenticated by a shared-secret header; feeds the credential-stuffing detector. When no secret is configured the path is not handled. |
| `/_bProxy/<adminsecret>/log-tail` | Authenticated server-sent-events stream of live log entries for the dashboard. Served only on the exact admin-secret path. |
| `/_bProxy/<adminsecret>/dashboard` | Web dashboard and control panel. Served only on the exact admin-secret path. See [Dashboard](dashboard.md). |
| `/_bProxy/<adminsecret>/metrics` | Prometheus metrics. Served only when `metricsEnabled` is set, and only on the exact admin-secret path; scrapes are neither challenged nor counted. See [Configuration](configuration.md#prometheus-metrics). |
| `/_bProxy/status` | Public status page (opt-in via `statusPage`): uptime and per-domain health, no sensitive data. Answered before challenge/rate limiting. See [Configuration](configuration.md#status-page). |
| `/_bProxy/health` | Bare liveness check (same `statusPage` opt-in): exactly `{"status":"ok"}`. For scrubbing providers and load balancers. |
| `/_bProxy/sso/login`, `/_bProxy/sso/callback`, `/_bProxy/sso/logout`, `/_bProxy/sso/status` | OIDC login flow for the dashboard (only when SSO is configured; `status` always answers `{"enabled": bool}`). Temporary paths until the platform-host work moves the dashboard off protected domains. See [Configuration](configuration.md#sso-for-the-dashboard). |

The `/_bProxy/` path prefix and the challenge cookie names are kept unchanged from the original project for compatibility with existing integrations.

## Next Steps

- [Dashboard](dashboard.md) — the browser UI built on this API.
- [Configuration](configuration.md) — where `adminsecret` and `apisecret` are set.
