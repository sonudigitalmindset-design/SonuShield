# Dashboard

SonuShield includes a web dashboard and control panel, served by the proxy itself — no build step, no extra files, no external resources. It monitors the proxy and manages it: no terminal interaction is needed for day-to-day operation.

![Dashboard schematic](assets/dashboard.svg)

## Opening It

Open it at:

```text
https://<your-domain>/_bProxy/<adminsecret>/dashboard
```

In Cloudflare mode, open the same path through your Cloudflare-fronted domain as usual (the proxy itself listens on port 80 only in that mode). As with any browser request, the first visit passes through the normal cookie challenge automatically.

## Authentication

Two secrets protect the dashboard, reusing the existing API mechanisms — no new authentication scheme is added:

- The page itself is served only on the exact admin-secret path, following the v1 API pattern. A wrong or missing secret never receives the page; the request falls through to normal proxy handling, as with the v1 API. If no admin secret is configured, the dashboard is not served at all.
- After the page loads, enter your `apisecret`. The dashboard sends it only as the `Proxy-Secret` header to the existing API v2 endpoints on the same host. The secret is kept in the browser tab's session storage and is cleared when you click "Forget secret" or close the tab. It is never placed in a URL or written to a log.

## What It Shows and Does

- **Overview:** live total and bypassed requests per second, all-time totals, CPU/RAM usage, the current stage and stage-lock state, and the top requesting IPs and unknown fingerprints in the current rate-limit window. Updates every 3 seconds.
- **Domains:** the configured domain list with backends, schemes, live summaries, and rule counts. Select a domain to manage it everywhere in the dashboard; a detail panel shows its configuration summary and traffic.
- **Firewall rules:** the domain's rules in evaluation order, with a plain explanation of each action — plus add, edit, and delete. Changes are validated, saved to `config.json` immediately (with a `config.json.bak` backup), and take effect without a reload.
- **Stage:** the current stage, stage-lock, and under-attack state — plus controls to return to automatic switching, lock a stage, or switch under-attack mode on and off. Stage changes are runtime-only: a reload or restart resets them.
- **Logs:** the most recent requests that passed the challenges, newest first, with clearing per domain or for all domains.
- **Settings:** domain thresholds, proof-of-work, and WAF-lite settings, saved to `config.json` immediately; plus a read-only proxy-features panel and a reputation-feed refresh button.
- **Reports:** attack summaries from live counters, with JSON and CSV export.
- **Reload config** (top bar): validates `config.json` and reloads it into the running proxy. An invalid file is rejected with the reason shown, and the running proxy is untouched.

All data and actions go through the existing [API](api.md) v2 actions. The stage shown comes from the `GET_STAGE` API action and therefore always reflects the domain being inspected.

## What Still Needs the Config File

Secrets are never shown or accepted in the dashboard: admin/API secrets, challenge keys, the Telegram bot token, the email password, and webhook URLs (which embed a token) live only in `config.json` on the server. Admin/API secret changes need a restart. Adding or removing domains, and changing backends, schemes, certificate paths, or proxy-wide settings (timeouts, rate limits, GeoIP databases, auto SSL, metrics, logging), also need a `config.json` edit — after which Reload config here applies the change. The terminal HUD and commands remain available as a fallback; see [Commands](how-it-works.md#commands).

## Themes and Offline Use

The dashboard has two themes sharing one layout: Premium Dark (default) and Official Classic Light, switched from the top bar. The choice is stored in the browser's local storage and is never sent to the server. The page is a single self-contained file embedded in the binary: no build step and no external resources (no CDN, fonts, or icon libraries), so it works fully offline and needs no extra files in Docker.

## Next Steps

- [API](api.md) — the endpoints the dashboard uses.
- [How It Works](how-it-works.md) — the terminal HUD and commands.
- [Troubleshooting](troubleshooting.md) — if the dashboard won't load.
