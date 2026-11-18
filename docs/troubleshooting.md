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

**Wizard refuses to start.** `--wizard` exits when a `config.json` already exists in the working directory — the wizard never runs against an existing config. Start the proxy normally instead, or move the config aside first (with explicit confirmation the wizard can overwrite, keeping a timestamped backup). The wizard listens on localhost only; reach it over an SSH tunnel from a remote machine. See [Installation](installation.md#first-run).

## After an update

**Update notice and a 10-second wait.** If a newer stable version is published, the proxy prints an update notice and waits 10 seconds before starting. This is normal behavior from the startup version check.

**My configuration stopped working.** After editing `config.json` by hand, run the `reload` terminal command (or restart) to apply changes. If you added a domain with the `add` command, the configuration is reloaded automatically.
