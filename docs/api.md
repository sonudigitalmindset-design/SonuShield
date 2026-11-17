# API Reference

SonuShield exposes an HTTP API for reading proxy statistics, firewall rules, and logs. Both API versions authenticate with the `apisecret` from your configuration. The v1 path additionally contains your `adminsecret`.

![API schematic](assets/api.svg)

> The API documentation previously hosted on SwaggerHub is no longer available. This page is the authoritative API reference for the current code.

## Version 1

Send a `POST` request with a JSON body to:

```text
POST /_bProxy/<adminsecret>/api/v1
Header: proxy-secret: <apisecret>
Body:   {"domain": "<domain name or empty>", "action": "<ACTION>", "params": {"<key>": "<value>"}}
```

With an empty `domain`, proxy-level actions are executed. With a domain name, domain-level actions are executed for that domain. The optional `params` object carries parameters for actions that take them (currently only `SET_DOMAIN_FEATURES`); other actions ignore it.

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

Requests with a missing or wrong API secret are passed through to the normal request handling instead of receiving an API response.

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
| `RELOAD` | Accepted, but currently a no-op. Use the `reload` terminal command to reload the configuration. |
| `GET_PROXY_FEATURES` | `QUIET_MODE`, `AUTO_SSL`, `AUTO_SSL_ACTIVE`, `GEO_COUNTRY_LOADED`, `GEO_ASN_LOADED`, `REPUTATION_FEED_CONFIGURED`, `REPUTATION_FEED_INTERVAL_MINUTES`, `REPUTATION_LOCAL_IPS`, `REPUTATION_LOCAL_NETWORKS`, `REPUTATION_FEED_IPS`, `REPUTATION_FEED_NETWORKS`, `REPUTATION_BUMP`, `REPUTATION_FEED_LAST_SUCCESS` (unix time, `0` = never), `REPUTATION_FEED_LAST_ERROR` (`""` = none). |
| `REFRESH_REPUTATION_FEED` | Triggers a background reputation-feed refresh. Returns `REFRESH_STARTED` and `FEED_CONFIGURED`. Fail-open like the scheduled refresh; a refresh already running is not duplicated. |

## Domain Actions

| Action | Returns |
|--------|---------|
| `GET_TOTAL_REQUESTS` | `TOTAL_REQUESTS` |
| `GET_BYPASSED_REQUESTS` | `BYPASSED_REQUESTS` |
| `GET_TOTAL_REQUESTS_PER_SECOND` | `TOTAL_REQUESTS_REQUESTS_PER_SECOND` |
| `GET_BYPASSED_REQUESTS_PER_SECOND` | `BYPASSED_REQUESTS_REQUESTS_PER_SECOND` |
| `GET_FIREWALL_RULES` | `FIREWALL_RULES` |
| `GET_LOGS` | `LOGS` |
| `GET_DOMAIN_FEATURES` | `ADAPTIVE_POW`, `POW_DIFFICULTY_MIN`, `POW_DIFFICULTY_MAX`, `CHALLENGE_PROVIDER`, `CHALLENGE_KEYS_CONFIGURED` (bool — keys themselves are never returned), `WAF_MODE`, `WAF_MODE_EFFECTIVE`, `WAF_INSPECT_BODY`, `WAF_WP_LOGIN_LIMIT`. |
| `SET_DOMAIN_FEATURES` | Adjusts runtime-tunable feature settings (see below). Returns the same fields as `GET_DOMAIN_FEATURES`. |

`SET_DOMAIN_FEATURES` accepts these parameters (v1 `params` object or v2 query string). Only supplied parameters change; unknown parameters are rejected, and validation is all-or-nothing — on any error, nothing changes:

| Parameter | Values |
|-----------|--------|
| `adaptivePow` | `true` / `false`. |
| `powDifficultyMin` | `0` (default = base difficulty) or `1`–`16`. |
| `powDifficultyMax` | `0` (default = base difficulty + 3) or `1`–`16`. Must not be below the minimum when both are set. |
| `wafMode` | `off`, `log`, or `block`. |
| `wafInspectBody` | `true` / `false`. |
| `wafWpLoginLimit` | Integer `>= 0` (`0` = default of 20/minute). |

Changes apply to the running proxy only and are **not** written back to `config.json` — a reload or restart restores the file's values. Challenge provider and keys cannot be set through the API; they live in `config.json` only.

## Reserved Paths

These paths are handled by the proxy itself and never forwarded to the backend:

| Path | Description |
|------|-------------|
| `/_bProxy/stats` | Plain-text domain statistics: stage, total/bypassed requests, requests per second, and the proxy fingerprint. |
| `/_bProxy/fingerprint` | Plain-text details about the current request: IP, request counts, suspicion level, TLS fingerprint, JA4 and HTTP fingerprints, and browser/bot identification. |
| `/_bProxy/verified` | Used by the challenge pages to confirm a solved challenge. Returns `verified`. |
| `/_bProxy/challenge-verify` | `POST` only. Receives provider challenge tokens (Turnstile / hCaptcha) from the challenge page and verifies them server-side. Other methods receive a plain 404. |
| `/_bProxy/credits` | Attribution and license information. |
| `/_bProxy/<adminsecret>/dashboard` | Web dashboard (v1, read-only monitoring). Served only on the exact admin-secret path. See [Dashboard](dashboard.md). |

The `/_bProxy/` path prefix and the challenge cookie names are kept unchanged from the original project for compatibility with existing integrations.

## Next Steps

- [Dashboard](dashboard.md) — the browser UI built on this API.
- [Configuration](configuration.md) — where `adminsecret` and `apisecret` are set.
