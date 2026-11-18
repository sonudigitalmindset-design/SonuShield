# Custom Firewall Rules

Thanks to [gofilter](https://github.com/kor44/gofilter), SonuShield lets you add your own firewall rules using a rule engine based on [Wireshark display filter expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html).

![Firewall rules schematic](assets/firewall-rules.svg)

## Fields

These fields can be used in rule expressions. Values reflect the current request and the current rate-limit window.

| Field | Type | Description |
|-------|------|-------------|
| `ip.src` | IP | The client's IP address. |
| `ip.country` | String | The client's ISO country code (e.g. `US`), from the configured GeoIP Country database. `""` when no database is configured or no record exists. In Cloudflare mode, from the `CF-IPCountry` header. |
| `ip.asn` | Int | The client's autonomous system number, from the configured GeoIP ASN database. `0` when no database is configured or no record exists. |
| `ip.engine` | String | The client's browser (`""` if it could not be identified). |
| `ip.bot` | String | The bot's name (`""` if not applicable). |
| `ip.fingerprint` | String | The client's raw TLS fingerprint (`Cloudflare` in Cloudflare mode). |
| `ip.ja4` | String | The client's JA4 fingerprint, computed by SonuShield (`""` in Cloudflare mode). Only comparable with other SonuShield-computed JA4 values. |
| `ip.reputation` | String | `"listed"` if the client IP is on the local blocklist or the fetched reputation feed, `""` otherwise. |
| `ip.risk` | Int | The composite risk score for the request, `0`–`100` (see [Risk Score](configuration.md#risk-score)). A heuristic for ranking, never a verdict — do not block on it alone without understanding the weights. |
| `ip.timing` | String | Timing/behavior verdict for the client IP: `"regular"` (inhumanly regular intervals), `"burst"` (50+ requests in a 1-second window), or `""` (no anomaly). See [Timing and Behavior Detection](configuration.md#timing-and-behavior-detection). |
| `ip.searchbot` | String | Search-bot verification result for the request: `"verified"` (claimed Googlebot/Bingbot and reverse+forward DNS confirmed it), `"fake"` (claimed it and verification failed), `"unchecked"` (DNS lookup failed, fail-open), or `""` (no search-bot user-agent claimed, or the check is disabled). See [Fake Search-Bot Verification](configuration.md#fake-search-bot-verification). |
| `ip.os` | String | The client's OS family label from passive TCP fingerprinting, or `"unknown"` when no operator signature matches (or no signatures are configured). See [Passive OS Fingerprinting](configuration.md#passive-os-fingerprinting). |
| `ip.tcpinfo` | String | A compact rendering of the raw TCP signals used for OS fingerprinting (MSS values, RTT, negotiated options), or `""` when unavailable (non-Linux platforms, Cloudflare mode). |
| `ip.behavior` | String | Mouse/scroll behavior verdict for the client: `"human"`, `"bot"`, or `""` (no signal collected or the check is disabled). See [Behavior Check](configuration.md#behavior-check). |
| `ip.http_requests` | Int | The client's forwarded HTTP requests in the current rate-limit window. |
| `ip.challenge_requests` | Int | The client's challenge attempts in the current rate-limit window. |
| `http.host` | String | The hostname of the current domain. |
| `http.version` | String | The HTTP version used by the client (for example `HTTP/1.1` or `HTTP/2`). |
| `http.method` | String | The HTTP method used by the client (all capitals). |
| `http.url` | String | The full request URI. |
| `http.query` | String | The raw query string sent by the client. |
| `http.path` | String | The path requested by the client (for example `/pictures/dogs`). |
| `http.user_agent` | String | The user agent sent by the client. **Important:** always lowercased. |
| `http.cookie` | String | The cookie string sent by the client. |
| `http.fingerprint` | String | The `sh1` HTTP request fingerprint: sorted header names, cookie presence, and client-preference signals (see below). SonuShield's own format, comparable only within SonuShield; values from before Batch 5 (three sections) are not comparable with current values (four sections). |
| `http.http2` | String | The HTTP/2 connection fingerprint (`""` for HTTP/1.x requests). Built only from signals Go's stack exposes: protocol version, TLS version/cipher, ALPN, a hash of the sorted header names, and presence flags for common headers. HTTP/2 SETTINGS order/values, WINDOW_UPDATE, and PRIORITY frames are not observable through Go's `net/http` and are not included; HTTP/1 header order is not preserved by Go either, so no header-order fingerprinting is claimed for HTTP/1. See `/_bProxy/fingerprint` for the current request's value. |
| `proxy.stage` | Int | The stage the reverse proxy is currently in. |
| `proxy.cloudflare` | Bool | `true` if the proxy is in Cloudflare mode. |
| `proxy.stage_locked` | Bool | `true` if the stage is locked to a specific stage. |
| `proxy.attack` | Bool | `true` if the proxy is under attack. |
| `proxy.bypass_attack` | Bool | `true` if the proxy is being attacked by an attack that bypasses the current security measures. |
| `proxy.rps` | Int | Currently incoming requests per second. |
| `proxy.rps_allowed` | Int | Currently incoming requests per second forwarded to the backend. |

> **Do not use** `ip.requests`, `http.headers`, or `http.body` in rules. These names are registered in the rule engine but are never given values, so rules using them will not behave as expected.

> **Bool fields cannot be compared.** The rule engine's equality test has no boolean case, so `eq`/`ne` on `proxy.cloudflare`, `proxy.stage_locked`, `proxy.attack`, and `proxy.bypass_attack` never match — this is a pre-existing limitation of the gofilter engine, not a configuration problem. The fields are listed for completeness; do not build rules that depend on comparing them. (A bare field name only tests whether the field exists, which is always true, since every field is always populated.)

> **`ip.quic` is reserved and inactive.** The field name is reserved for QUIC fingerprinting, which needs the HTTP/3 listener planned for Batch 3 — there is no QUIC traffic to fingerprint yet, so the field is always empty and the rule API rejects expressions that use it. Do not write rules on it; they will be rejected. This is documented here so the reservation is visible, not because the field does anything today.

IP literals in expressions are written **bare, never quoted**: `ip.src eq 127.0.0.1` is valid, while `ip.src eq "127.0.0.1"` fails to compile (`invalid IP address`). String literals are quoted, as in the examples below.

## The `sh1` HTTP fingerprint

`http.fingerprint` is SonuShield's own format (`sh1_<a>_<b>_<c>_<d>`), deliberately not JA4H: JA4H is part of the FoxIO JA4+ suite under a licence that needs an OEM agreement for commercial use, and a spec-compliant JA4H needs the original header transmission order, which Go's `net/http` does not preserve. The signals used, exactly:

- **Section a:** HTTP method (first 2 chars), HTTP version, cookie present/absent, referer present/absent, header count (excluding Cookie/Referer), and the first Accept-Language tag.
- **Section b:** truncated SHA-256 of the sorted, comma-joined, lowercase header names, excluding Cookie and Referer.
- **Section c:** truncated SHA-256 of the sorted, comma-joined cookie *names*. Cookie values are never included.
- **Section d** (added in Batch 5): truncated SHA-256 of the joined, normalised client-preference signals — the sorted Accept-Encoding tokens (q-values stripped), the full Accept-Language value (q-values stripped, lowercased, order preserved), the Upgrade-Insecure-Requests value, and the Sec-Fetch-Site and Sec-Fetch-Mode values. These are stable per client configuration, carry no identity, and are hashed so no raw header value is stored.

No browser fingerprinting scripts, no evercookies, no cross-site tracking: only the headers of the request being evaluated, hashed. Section d means current values are not comparable with pre-Batch-5 three-section values.

## Comparison Operators

```text
(http.path eq "/")            (http.path == "/")            identical
(http.path ne "/")            (http.path != "/")            not identical
(proxy.rps gt 200)            (proxy.rps > 200)             left greater than right
(proxy.rps lt 10)             (proxy.rps < 10)              left smaller than right
(proxy.rps_allowed ge 50)     (proxy.rps_allowed >= 50)     left greater than or equal
(proxy.rps_allowed le 50)     (proxy.rps_allowed <= 50)     left smaller than or equal
```

## Logical Operators

```text
(http.path eq "/" and http.query eq "")     (http.path eq "/" && http.query eq "")     both must be true
(http.path eq "/" or http.query eq "/x")    (http.path eq "/" || http.query eq "/x")   either must be true
!(http.path eq "/")                         not(http.path eq "/")                      negates the comparison
```

## Search / Match Operators

```text
(http.user_agent contains "chrome")                          field contains value
(http.user_agent matches "(?i)bot|crawler|spider")           field matches a regex (case-insensitive)
```

Patterns use Go's `regexp` (RE2) syntax: lookahead, lookbehind, and backreferences are **not** supported, and a pattern using them fails to compile — the rule is then rejected with a compile error.

## Structure

Firewall rules live in each domain's `firewallRules` array in `config.json`. Every rule needs an `expression` and an `action`:

```json
"firewallRules": [
  {
    "expression": "(http.path eq \"/captcha\")",
    "action": "3"
  },
  {
    "expression": "(http.path eq \"/curl\" and ip.bot eq \"Curl\")",
    "action": "0"
  }
]
```

## Priority

Rules are evaluated from top to bottom. A rule listed earlier has priority over every rule listed after it. Some actions stop SonuShield from checking further matching rules (see below), so rules with higher action values should usually be listed higher in the array as well.

## Actions

The resulting action is decided by the request's `susLv` (suspicion level), a scale from `0` to `3` and above. It starts at the domain's current stage (normally `1`, higher during attacks) and is adjusted by matching rules.

| susLv | Reaction |
|-------|----------|
| `0` | **Allow.** The request is whitelisted and will not be challenged in any form. |
| `1` | **Cookie challenge.** A simple cookie challenge, passed automatically by most good bots. |
| `2` | **JS challenge.** A JavaScript challenge that stops most bots, including good ones. |
| `3` | **Captcha.** A visual captcha the user must solve. Stops most malicious requests as well as good bots. |
| `4` or higher | **Block.** The request is blocked. |

## Adding Actions

An `action` can set the suspicion level to an exact number. When a rule with an absolute action matches, SonuShield stops checking further rules for that request:

```json
{
  "expression": "(http.host contains \":\")",
  "action": "3"
}
```

This example challenges requests whose host contains a `:` (typical of direct socket connections) with a captcha.

```json
{
  "expression": "(ip.country eq \"XX\" and http.path eq \"/wp-login.php\")",
  "action": "3"
}
```

This example (with a GeoIP Country database configured) challenges login-page requests from one country with a captcha. Replace `"XX"` with a real ISO country code.

```json
{
  "expression": "(ip.reputation eq \"listed\")",
  "action": "+1"
}
```

This example raises the suspicion level by `1` for IPs on the local blocklist or reputation feed — on top of the automatic reputation bump (see [IP Reputation](configuration.md#ip-reputation)).

Prefixing the action with `+` or `-` instead adjusts the *current* suspicion level by that amount, and SonuShield keeps checking further rules. This lets you stack multiple checks and react less aggressively when not under attack:

```json
{
  "expression": "(ip.engine eq \"\")",
  "action": "+1"
}
```

This example raises the suspicion level by `1` for requests from an unknown browser engine. A `-1` action would lower it by `1`.

## Edge Rules

`edgeRules` is a fast-path rule chain, configured per domain in `config.json` with the same `{"expression", "action"}` shape as `firewallRules`, evaluated before the general rules — behaving exactly as if its rules were prepended to the general list. A set action in the edge chain stops general evaluation, just like a set action in the general list; `+N`/`-N` actions adjust the level and evaluation continues. The intended use is cheap early decisions: known-good fingerprints, static allows, and other single-test rules that currently pay the rule-engine interpreter on every request.

```json
"edgeRules": [
  {"expression": "ip.src eq 203.0.113.10", "action": "0"}
]
```

Only a strict subset of expressions fits the fast grammar, and anything else is rejected at load time with a warning naming the rule (the rule is skipped; use `firewallRules` for it — never a panic, never a silent accept):

- One comparison only: `<field> <op> <literal>`, with the word operators `eq`, `ne`, `gt`, `ge`, `lt`, `le`, `contains`, separated by whitespace. Compound expressions (`and`/`or`/`not`, parentheses), regex `matches`, and symbolic operators (`==`, `!=`, `>`, …) are not accepted.
- Every documented field except the boolean `proxy.*` fields (boolean comparisons never match in the engine, so compiling one would create a dead rule) and except `ip.quic` (reserved, unregistered).
- `contains` only on string fields — on integer/IP fields it can never match in the engine either.
- Literals parse exactly as the engine parses them for the field's type: base-0 integers (`0x`/`0o`/`0b`/leading-zero), bare IP addresses or CIDRs, and strings via Go unquoting. Backquote literals are rejected by the engine itself.

Equivalence is enforced, not assumed: every accepted expression is first validated with the same engine the general rules use, so the fast path can never accept an expression the general evaluator would refuse; the compiled check then replicates the engine's comparison semantics, including its quirks (`ne` is the negation of `eq`, so it is true on missing or mistyped values; `le` on IPs compares without normalisation). Differential tests prove the two evaluators agree across the accepted grammar. Edge rules are config-file-only: they are not managed by the rule API, the simulator, or export/import, and they do not appear in the dashboard.

## Scheduled Rules

A rule can carry a `schedule` field — a 5-field cron expression (minute, hour, day of month, month, day of week) that limits when the rule is active:

```json
{"expression": "ip.country eq \"XX\"", "action": "4", "schedule": "0 22-6 * * *"}
```

Schedules support `*`, comma-separated lists, ranges, and steps (`*/15`, `9-17/2`); day-of-week 7 means Sunday, and month/weekday names are not supported. When both day-of-month and day-of-week are restricted, either matching activates the rule (Vixie OR semantics). Schedules are evaluated in the domain's `scheduleTimezone` (IANA name, default UTC). A rule outside its schedule is skipped entirely. Edge rules ignore schedules. An invalid schedule in `config.json` warns at load and the rule stays always-active; the API and dashboard reject invalid schedules outright. The rule simulator is expression-only and ignores schedules — it answers whether the expression matches, not whether the rule is currently active.

## Testing Rules Before Enforcing Them

Three tools help you check rules without affecting visitors:

- The **rule simulator** ([`SIMULATE_RULE`](api.md#domain-actions), also in the dashboard's Firewall rules view) evaluates one expression against sample request fields you supply and reports match/no-match plus which fields the expression used. It enforces nothing. It evaluates with the same engine and the same field types as live traffic, so its answer matches what the live proxy would do — including the bool-comparison limitation above. It ignores rule schedules (see above).
- **Dry-run mode** (`rulesDryRun` per domain, also settable in the dashboard's Settings view) evaluates the domain's rules on live traffic and logs matches as `dryrun` entries (with the suspicion level the rules *would* have set) but leaves the suspicion level unchanged, so no request is challenged or blocked by rules. Dry-run entries appear in the structured log when JSON logging is enabled; see [Structured Logs](configuration.md#structured-logs).
- **Shadow mode** (`shadowRules` / `shadowWaf` per domain) evaluates a second ruleset alongside live enforcement and logs what it *would* have decided, with a comparison report from [`GET_SHADOW_REPORT`](api.md#domain-actions). Unlike dry-run mode, live enforcement stays fully active. See [Shadow Mode](configuration.md#shadow-mode).

## Next Steps

- [Configuration](configuration.md) — the `firewallRules` array lives per domain.
- [How It Works](how-it-works.md) — how suspicion levels and stages interact.
