# Troubleshooting

Common problems and how to fix them. If your issue is not listed here, check the [README](../README.md) and the relevant docs page first — most behavior is documented there.

## The proxy refuses to start

**Secrets still contain `CHANGE_ME`.** SonuShield refuses to start if any secret still contains `CHANGE_ME`. Replace every placeholder in `config.json` with real random values (for example, from `openssl rand -hex 20`).

**Missing or invalid certificate or key.** Outside Cloudflare mode, every domain needs a valid TLS certificate and private key, loaded at startup — unless [`autoSSL`](configuration.md#automatic-ssl) is enabled and both fields are empty, in which case Let's Encrypt supplies the certificate. If either path is set but missing or invalid, SonuShield refuses to start. Check the `certificate` and `key` paths in your configuration, or generate development certificates with `./scripts/generate-certs.sh` for local testing only. In Cloudflare mode, leave both empty — they are not loaded.

**Version check failed.** At startup, SonuShield fetches version information from this repository over HTTPS. If the version check itself fails (for example, with no outbound network access), startup stops. Make sure the server has outbound HTTPS access to `raw.githubusercontent.com`. Fingerprint-list fetch failures do not stop startup, but leave the corresponding lists empty.

**Port already in use / permission denied.** The proxy binds ports 80 and 443 (80 only in Cloudflare mode). Make sure nothing else is using those ports, and that the process has permission to bind them — run as `root`, or grant the binary the `cap_net_bind_service` capability (see [Installation](installation.md#as-a-systemd-service)).

## The proxy runs, but my site is not protected

**DNS points at the backend.** Make sure **no** DNS record points directly at your backend server — otherwise attackers can bypass the proxy entirely. See [DNS Setup](installation.md#dns-setup).

**Cloudflare proxy status is wrong.** If you use SonuShield **with** Cloudflare, the DNS record's Proxy status must be **Proxied**. If you manage DNS in Cloudflare but do **not** use SonuShield with Cloudflare, it must be **DNS only**.

**Check the header.** Open your website, open DevTools, go to the Network tab, and look at a response: you should see a `SonuShield: 1.5` header — unless [`quietMode`](configuration.md#quiet-mode) is enabled, which suppresses it. If the header is missing with quiet mode off, requests are not going through the proxy.

**Cloudflare mode enabled without Cloudflare.** Enabling Cloudflare mode without actually using Cloudflare will not work. The proxy listens on port 80 only and reads the client IP from the `Cf-Connecting-Ip` header, which only Cloudflare sends. Also confirm your Cloudflare SSL/TLS encryption mode is set to `Flexible`.

## Visitors see challenges unexpectedly

**Stage escalation.** When bypassing requests exceed your `bypassStage1` / `bypassStage2` thresholds, stronger challenges activate automatically. Check the current stage in the terminal HUD or the [dashboard](dashboard.md), and review your [stage thresholds](configuration.md#stage-thresholds).

**A stage is locked.** If someone ran the `stage` terminal command, automatic switching is disabled until `stage 0` unlocks it. The HUD shows `Stage Locked: true` in that case.

**Firewall rules.** A custom rule may be raising the suspicion level. Rules are evaluated top to bottom; review your domain's `firewallRules` and the [rule actions](firewall-rules.md#actions). Note that `http.user_agent` is always lowercased in rules.

**Stage 2 never completes.** The proof-of-work challenge page loads its script from a public CDN. Visitors' browsers must be able to reach that CDN for Stage 2 challenges to complete.

## No Discord alerts

**Alerts need a webhook URL.** Leave `url` empty and alerts are disabled for that domain. Check the per-domain [`webhook`](configuration.md#webhook) settings.

**Alerts are skipped while the stage is locked.** Alerts are only sent when the stage is not locked, when the first stage starts being bypassed, and when the attack ends.

## API or dashboard problems

**API returns no API response.** Requests with a missing or wrong API secret are passed through to normal proxy handling instead of receiving an API response. Check the `Proxy-Secret` / `proxy-secret` header value against your `apisecret`, and for v1, the `adminsecret` in the path. See [API Reference](api.md).

**Dashboard page won't load.** The dashboard is served only on the exact admin-secret path. A wrong or missing secret never receives the page. If no admin secret is configured, the dashboard is not served at all. See [Dashboard](dashboard.md#authentication).

**Dashboard shows the wrong domain's stage.** Fixed: the stage now comes from the `GET_STAGE` API action and always reflects the domain being inspected. If you are running an older binary, upgrade — the old dashboard read `/_bProxy/stats`, which always reflects the domain in the address bar.

**`RELOAD` fails with `ERR_RELOAD_FAILED`.** The reload validates `config.json` before applying it, and rejects the file when secrets are missing or contain `CHANGE_ME`, no domain is configured, a firewall rule does not compile or has an unusable action, or a certificate pair cannot be loaded. The `ERROR_DETAIL` field names the problem; the running proxy is untouched. Fix the file and reload again. (A successful reload resets request counters and stage locks, like the terminal `reload` command.)

**API calls return a challenge page when a stage is locked.** Fixed: API and dashboard requests carrying a valid secret (API secret, role secret, or SSO session plus CSRF header) bypass the challenge flow, including the unlock call at a locked stage. If you still see a challenge page, the secret is missing or wrong — requests with a missing or wrong secret keep the old fall-through behavior by design. Check the `Proxy-Secret` header value. If you are running an older binary, upgrade.

**SSO sign-in fails.** Check the startup log for an `SSO disabled: …` warning — an enabled-but-invalid SSO config disables SSO rather than stopping the proxy. Common causes: the issuer or redirect URL is not HTTPS (HTTP is allowed only for loopback hosts), the discovery document's `issuer` does not exactly equal the configured issuer, or the identity provider returns no `id_token`. The sign-in failure page is deliberately generic; the server log records only the failure class, never tokens. See [SSO for the Dashboard](configuration.md#sso-for-the-dashboard).

**Log search fails with `ERR_JSON_LOGS_NOT_CONFIGURED`.** `SEARCH_LOGS` and the dashboard's log search need structured JSON logging: set `logFormat: "json"` and `logFile` in the proxy config, then reload. The attack map likewise needs JSON logs, plus a GeoIP database for country data — without either it returns an empty list rather than an error.

**Control plane: `control-setup` refuses to print a token.** A setup token is refused once an owner account exists in the account file — that is by design. If the owner password is lost, there is no recovery path in the product: restore the account file from backup, or delete it and bootstrap again (which removes all accounts).

**Control plane: login always fails / 429.** Logins are rate-limited per client IP: 5 failures in 5 minutes → `429` with `Retry-After`, and a successful login resets the counter. Behind a reverse proxy, the control plane sees the proxy's address (it does not trust `X-Forwarded-For`), so all operators share one limit — put the control plane on loopback or its own listener where possible. Failure messages are deliberately generic; the audit log records the attempt.

**Control plane: node calls fail or return the node's 404 page.** A node routes by HTTP `Host`, so the control plane must send a domain the node serves: set the node's `host` (or `serverName`, which doubles as the default) in the `controlPlane.nodes` entry. `sonushield validate` warns when a node reached by IP has neither set. Also check the node's `apiSecret` and that the node URL is reachable from the control host.

**Control plane: approvals cannot be completed.** Two-person approval through the control plane needs the same `controlPlaneSecret` on the node (`proxy.controlPlaneSecret`, restart to apply — secrets are load-only) and in the node's control-plane entry. Without it on either side, every control-plane caller looks identical to the node and a different operator's approval is rejected as a self-approval. This fails closed by design; direct API approvals with distinct secrets are unaffected.

**Control plane: SSO sign-in fails.** The identity provider only authenticates: the account must already exist in the control-plane account file (username from the `email`, `preferred_username`, or `sub` claim), or sign-in is denied with the generic failure page. Role and tenant scope come from the account, never from claims. Check the startup log for an SSO discovery/validation failure, and that `redirectUrl` points at the control host's `/sso/callback`. See [Control Plane](control-plane.md#sso).

**On-domain dashboard redirects or 404s after setting `dashboardMode`.** `"control-plane"` without a usable absolute `http(s)` `controlPlaneUrl` answers a bare 404 by design; an unknown mode value fails safe to `"off"` with a warning in the proxy log. Set the mode back to `"local"` and reload to restore the on-domain dashboard immediately. See [Control Plane](control-plane.md#dashboard-modes-and-migration).

## Rules behave unexpectedly

**Unsupported field names.** Do not use `ip.requests`, `http.headers`, or `http.body` in rules — these names are registered but never given values, so rules using them will not behave as expected. (`ip.country`, `ip.asn`, `ip.ja4`, `ip.reputation`, and `http.fingerprint` are populated — see below.) See the [field list](firewall-rules.md#fields).

**Geo/ASN rules never match.** `ip.country` and `ip.asn` need the corresponding GeoIP database configured (`geoipCountryDatabase` / `geoipASNDatabase`) — without a database they are always `""` / `0` and rules on them never match (fail-open). Check the startup log for a database-open warning, confirm the file paths, and check the load state with the [`GET_PROXY_FEATURES`](api.md#proxy-actions) API action. In Cloudflare mode the country comes from the `CF-IPCountry` header instead of the database.

**Absolute actions stop further checks.** When a rule with an absolute action (e.g. `"3"`) matches, SonuShield stops checking further rules for that request. Use `+` / `-` actions when you want checks to stack. See [Adding Actions](firewall-rules.md#adding-actions).

## Feature Problems

**Turnstile / hCaptcha challenge never appears.** The provider challenge only serves when `challengeProvider`, `challengeSiteKey`, and `challengeSecretKey` are all set for the domain. Any misconfiguration logs a startup warning and falls back to the proof-of-work challenge — check the startup log first. Keys come from your own provider account; see [Challenge Providers](configuration.md#challenge-providers). If the widget shows visibly instead of staying invisible, check the site key's widget settings in the provider's dashboard.

**Auto SSL does not issue a certificate.** Check the three requirements: the domain must resolve in public DNS to this server, TCP port 80 must be reachable from the internet for the HTTP-01 challenge, and [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/) must not be exhausted. Auto SSL is ignored in Cloudflare mode, and a domain with explicit `certificate`/`key` files never uses it. See [Automatic SSL](configuration.md#automatic-ssl).

**WAF-lite blocks legitimate requests.** The default mode is log-only, so blocking means `wafMode: "block"` is set for that domain. Check the proxy log for the matching rule name, then either set the domain back to `"log"` or `"off"`, or narrow the exposure (for example, disable `wafInspectBody`). Matches log the rule name, IP, method, and truncated path only — never the body. See [WAF-Lite](configuration.md#waf-lite).

**Reputation feed not loading.** Feed failures are fail-open: the last good data is kept and a warning is logged, so a dead feed never blocks anyone. Check the [`GET_PROXY_FEATURES`](api.md#proxy-actions) API action for the feed status and last error, confirm the URL serves plain text (one IP/CIDR per line, under 10 MB), and use `REFRESH_REPUTATION_FEED` to retry on demand. See [IP Reputation](configuration.md#ip-reputation).

**JA4 values do not match an external database.** Expected: SonuShield computes JA4 from the fields Go's TLS stack exposes, without the raw extension list, so its values are only comparable with other SonuShield-computed values. Only use JA4 values observed on your own proxy (see `/_bProxy/fingerprint`) in `ja4_fingerprints.json` and firewall rules.

**Edge rule skipped with a warning at startup.** The expression does not fit the fast grammar (compound expression, regex, symbolic operator, boolean field, `ip.quic`, or a quoted IP literal — IP literals are bare: `ip.src eq 127.0.0.1`). The warning names the rule; move it to `firewallRules`, where the full grammar applies. See [Edge Rules](firewall-rules.md#edge-rules).

**Public API returns 401 for every key.** Keys must be at least 16 characters — shorter keys never match — and travel as `Authorization: Bearer <key>` or `X-API-Key`. Keys live in the proxy-level `publicApiKeys` config; with no keys configured, every public request gets a 401. A `429` means the key's per-minute rate limit was hit; check the `Retry-After` header. See [Public API](configuration.md#public-api).

**Webhooks not arriving.** Check `GET_WEBHOOK_STATUS` for endpoint state, queue depth, and drop counts, and `TEST_WEBHOOKS` to queue a test event. An endpoint delivers only with an `http(s)` URL and a non-empty secret; at most 16 endpoints are used. Delivery retries transport errors and 5xx responses with backoff, but 3xx/4xx responses are permanent failures — check the receiver's status codes. See [Event Webhooks and SIEM Export](configuration.md#event-webhooks-and-siem-export).

**Backup restore rejected.** A redacted backup restores only onto an instance whose current config holds the secrets (placeholders are filled from it) — on a fresh instance, use an encrypted backup with its passphrase instead. A wrong passphrase, a tampered blob, or any remaining placeholder at a secret path refuses the restore, and a bad backup changes nothing. Certificate files, GeoIP databases, and template files are not in the backup — copy them separately and keep their paths valid. See the `EXPORT_BACKUP` / `RESTORE_BACKUP` actions in the [API Reference](api.md#proxy-actions).

**OS fingerprint always `unknown`.** Expected unless you configured `proxy.osSignatures`: with no signatures, `ip.os` is always `unknown` — the proxy ships no signature database. Also, OS signals are collected only on Linux and never in Cloudflare mode (the proxy never sees the client TCP connection). TTL, DF flag, option order, window-scale value, and initial window are not observable at all through Go's stack. See [Passive OS Fingerprinting](configuration.md#passive-os-fingerprinting).

**Behavior verdicts are empty.** `ip.behavior` is populated only when `behaviorCheck` is set for the domain, and only for clients that loaded a challenge page (the beacon runs on challenge pages only). Clients that never see a challenge have no verdict — that is normal, not a bug. See [Behavior Check](configuration.md#behavior-check).

**Privacy mode masked my logs retroactively.** By design: log search masks IPs and drops user-agents on the way out, including for entries written before privacy mode was enabled. The raw values are still in the log files on disk from before the mode was switched on — privacy mode does not rewrite history. To purge old entries, rotate or delete the old log files. Live enforcement state keeps exact IPs while running (required to function) but never writes them to disk or returns them unmasked. See [Privacy Mode](configuration.md#privacy-mode).

**A sensitive action returns `ERR_APPROVAL_REQUIRED`.** Two-person approval is enabled (`proxy.twoPersonApproval`): the action is pending, not failed. A different operator must approve it with `APPROVE_ACTION` (or from the dashboard's Approvals view) before the `EXPIRES_AT` time. The same secret that requested it cannot approve it. See [Two-Person Approval](configuration.md#two-person-approval).

**Scheduled rule never fires.** Check three things: the cron expression is valid (the API rejects invalid ones; a bad one in `config.json` warns at load and the rule stays always-active, so a never-firing rule usually means the schedule itself excludes the current time), the domain's `scheduleTimezone` is the timezone you meant (default UTC), and remember day-of-month/day-of-week use OR semantics. Edge rules ignore schedules entirely. See [Scheduled Rules](firewall-rules.md#scheduled-rules).

**Maintenance page shows when it shouldn't.** Either the manual override is on (check `GET_MAINTENANCE` or the dashboard's Stage view — the override survives reloads) or a scheduled window from `maintenanceWindows` is currently active. Windows are end-exclusive and use the RFC 3339 timestamps as written, including their offsets. See [Scheduled Rules and Maintenance Windows](configuration.md#scheduled-rules-and-maintenance-windows).

**Cloudflare preview translates nothing.** The preview only translates the documented expression subset; everything else is listed under `SKIPPED` with a reason. Also check the token and zone ID are set for the domain in `config.json` (config-only — the API never confirms them), and that the zone actually has firewall rules. A fetch failure returns `ERR_FETCH_FAILED` and changes nothing. See [Cloudflare Import](configuration.md#cloudflare-import).

**Wizard refuses to start.** `--wizard` exits when a `config.json` already exists in the working directory — the wizard never runs against an existing config. Start the proxy normally instead, or move the config aside first (with explicit confirmation the wizard can overwrite, keeping a timestamped backup). The wizard listens on localhost only; reach it over an SSH tunnel from a remote machine. See [Installation](installation.md#first-run).

**Attestation rejects every request on a path.** Attestation fails closed: with `enabled` and `paths` set but no `jwksUrl` or `secret`, matching requests are rejected and a startup warning is printed. Add verification material, or remove the paths. Also confirm the token's issuer/audience match the config, the verdict claim path and values match your provider's verdict vocabulary, and the token has not expired. Tokens are never logged — check the client's token against the configured claims directly. See [Mobile App Attestation](configuration.md#mobile-app-attestation).

**Passkey challenge never appears.** The passkey page serves only when `enabled`, `rpId`, and at least one enrolled credential are all present; otherwise Stage 3 falls back to the captcha — check `LIST_PASSKEYS` and the `PASSKEY_CONFIGURED` flag in `GET_DOMAIN_FEATURES`. A failed assertion (wrong origin, stale challenge, counter regression) returns the captcha page rather than an error, so check the log for `passkey_failed` entries. See [Passkey Challenge](configuration.md#passkey-challenge).

**OpenAPI validation rejects valid requests.** Validation is off unless `specFile` and `prefixes` are both set, so check the domain's `openApi` config first. The validator checks required parameters and body schemas strictly: a request missing a declared-required field, or a body field with the wrong type, is a violation. An invalid spec disables validation entirely (with a warning) rather than rejecting anything, so rejections mean the spec loaded — compare the failing request against the spec's declared shape, and use `mode: "log"` while tuning. See [OpenAPI Validation](configuration.md#openapi-validation).

**DLP redacts too much (or nothing at all).** Redaction follows the operator's regexes exactly — check the `dlp.patterns` list in `config.json` and the pattern names in the log entries. Nothing is scanned when no patterns are configured, and oversized or encoded bodies pass unscanned by design; confirm the response is a 2xx text-ish body under `maxScanBytes` without Content-Encoding. Matched content is never logged, so test patterns against a copy of the response body offline. See [DLP Scanning](configuration.md#dlp-scanning).

**CSP reports are not arriving.** The browser sends reports only when the site's `Content-Security-Policy` carries a `report-uri` or `report-to` pointing at `/_bProxy/csp-report` — the proxy does not set that directive itself. Confirm the directive is present on the served page, the report endpoint is reachable, and the report body is under 64 KiB. Reports are stored per domain (200 max) and viewable via `GET_CSP_REPORTS` or the dashboard Logs view. See [CSP Report Collector](configuration.md#csp-report-collector).

**Threat-sharing peers never sync.** Check `GET_SHARING_STATUS` for per-peer pull state and last errors. Common causes: a wrong peer URL or `sharedSecret` (signatures must match on both sides), clock skew beyond ±300 seconds (signatures carry timestamps), or the peer's sharing feature disabled. Peer errors fail open — stale indicators are kept until they expire — so a dead peer never blocks traffic. See [Threat Sharing Network](configuration.md#threat-sharing-network).

**BGP monitor reports nothing (or reports a false alarm).** The first successful check per prefix is a silent baseline, so the first alert can only come from a later check. With no `expectedOrigins` configured, nothing is ever unexpected. Fetch errors fail open and raise no alert — check `GET_BGP_STATUS` for last-check times. RIPEstat aggregates collector data over multi-hour intervals, so short-lived announcements may never appear and brief origin changes may be reported late; treat alerts as early warnings and confirm against a second source before acting. See [BGP Alerts](configuration.md#bgp-alerts).

**Live tail shows nothing.** The tail streams entries as they arrive — entries from before the dashboard opened are not replayed. Confirm the Logs view is open (the stream stops when you leave it) and that traffic is flowing. If the stream fails to connect, check the admin secret path and the `Proxy-Secret` header/SSO session; a `503` means the 16-subscriber cap was reached. The tail works even without file logging. See [Live Log Tail](configuration.md#live-log-tail).

**Synthetic checks fail with challenge pages.** Checks are ordinary requests and pass through challenges like any visitor — a check against a domain at Stage 2/3 will receive the challenge page and fail its status/body expectations. Point checks at an endpoint that does not challenge (for example a health endpoint the domain's rules allow), or accept the challenge status in `expectStatus`. See [Synthetic Checks](configuration.md#synthetic-checks).

**RUM shows no samples.** The snippet is served for operator embedding only — it is never injected into origin content. Confirm the origin pages include `<script src="/_bProxy/rum.js" async></script>` and that beacons reach `POST /_bProxy/rum` (the endpoint always answers `204`). Beacons are dropped when the payload exceeds 4 KiB. See [RUM Beacon](configuration.md#rum-beacon).

**On-call alerts still go to everyone.** With `oncall` enabled but no schedule entry matching the current time, delivery falls back to the domain's channels — that is the designed fallback, not a bug. Check the schedule's days/times/timezone and `GET_ONCALL_STATUS` for the current responder. An escalation re-send goes to every responder by design. See [On-Call Rotation](configuration.md#on-call-rotation).

**Config validator reports errors I disagree with.** The validator is strict about secrets (present, no `CHANGE_ME`), certificates (loadable, unexpired), backends (host:port), and rule grammar — the same checks `SafeReload` applies. Warnings (short secrets, unknown keys, expiry within 30 days, missing GeoIP files) do not fail validation. `--probe-backends` dials backends over TCP only; a closed port fails the probe even if the backend would be reachable later. See [Config Validator](configuration.md#config-validator).

## After an update

**Update notice and a 10-second wait.** If a newer stable version is published, the proxy prints an update notice and waits 10 seconds before starting. This is normal behavior from the startup version check.

**My configuration stopped working.** After editing `config.json` by hand, run the `reload` terminal command (or restart) to apply changes. If you added a domain with the `add` command, the configuration is reloaded automatically.
