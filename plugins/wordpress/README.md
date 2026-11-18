# SonuShield WordPress Plugin

An optional origin-side companion for a SonuShield reverse proxy. It forwards
WordPress login failures to the proxy's credential-stuffing detector and shows
proxy reachability in wp-admin. It does not filter traffic itself: all
protection still happens at the proxy.

## What it does

- Hooks `wp_login_failed` and posts one signal per failure to
  `POST /_bProxy/origin-signal` with the shared secret in the
  `X-SonuShield-Signal` header. The signal carries only the domain, the
  type (`login_failure`), the client IP, and the path (`/wp-login.php`).
  **Usernames and passwords are never sent.**
- Signals are throttled to one per IP per 5 seconds.
- A dashboard widget shows whether the proxy health endpoint answers, plus
  how many signals were forwarded and when the last one went out.
- A settings page (Settings → SonuShield) holds the proxy URL, the secret,
  and the domain name. Only administrators can view it.

## Requirements

- WordPress 5.8+, PHP 7.4+.
- A running SonuShield proxy with `proxy.originSignals.secret` set in
  `config.json`, and the domain's credential-stuffing paths configured to
  include `/wp-login.php` — otherwise the proxy accepts the signals but the
  stuffing detector has no watched path to count them under (see
  `docs/configuration.md`, "Credential stuffing detection").
- The proxy health endpoint (`/_bProxy/health`, enabled via
  `proxy.statusPage`) for the dashboard widget's reachability check.

## Install

1. Copy the `sonushield/` directory into `wp-content/plugins/`.
2. Activate "SonuShield Origin Signals" in wp-admin → Plugins.
3. Open Settings → SonuShield, enter the proxy base URL (the public URL
   served through the proxy, no trailing slash), the origin-signal secret
   from the proxy's `config.json`, and the domain name as configured in the
   proxy (empty means the current site host). Tick "Enable signal
   forwarding" and save.

## Trust note: client IP

The plugin reads the client IP from the `X-Real-IP` header SonuShield
stamps on forwarded requests, falling back to `REMOTE_ADDR`. That header
is only trustworthy when the origin is reachable solely through the
proxy. If the origin is also reachable directly, add this to a must-use
plugin or theme functions file to ignore the header:

```php
add_filter('sonushield_trust_proxy_ip', '__return_false');
```

## Verification limits (honest scope)

This plugin was written against the WordPress Plugin API and the
SonuShield origin-signal endpoint, but it has **not** been run inside a
WordPress installation: no PHP or WordPress environment exists where it
was built, so `php -l` and live activation were not possible. Before
relying on it, activate it on a staging site, cause a failed login, and
confirm the proxy's `GET_STUFFING_STATUS` count for `/wp-login.php`
increases. The proxy side of the endpoint is covered by the Batch 8
smoke harness.
