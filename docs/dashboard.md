# Dashboard

SonuShield includes a read-only web dashboard, served by the proxy itself — no build step, no extra files, no external resources.

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

## What It Shows

- **Overview:** live total and bypassed requests per second, all-time totals, CPU/RAM usage, the current stage, and the top requesting IPs and unknown fingerprints in the current rate-limit window. Updates every 3 seconds.
- **Domains:** live traffic for the domain in the address bar, or for a domain name you enter.
- **Firewall rules:** the domain's rules in evaluation order, with a plain explanation of each action. Read-only.
- **Stage:** the current stage and what each stage does. Read-only.
- **Logs:** the most recent requests that passed the challenges, newest first.

All data comes from the existing [API](api.md) v2 actions and the `/_bProxy/stats` reserved path. The stage shown comes from `/_bProxy/stats` and therefore always reflects the domain in the address bar, even when another domain is being inspected.

## What It Cannot Do

The API exposes no actions for changing the stage, listing domains, reading backends or schemes, showing stage-locked or under-attack state, editing firewall rules, clearing logs, or reloading the configuration — so the dashboard does not offer them either. Those remain terminal-only (see [Commands](how-it-works.md#commands)). The dashboard adds no privileged endpoints of its own. Browser-based management is planned — see [Roadmap](roadmap.md).

## Themes and Offline Use

The dashboard has two themes sharing one layout: Premium Dark (default) and Official Classic Light, switched from the top bar. The choice is stored in the browser's local storage and is never sent to the server. The page is a single self-contained file embedded in the binary: no build step and no external resources (no CDN, fonts, or icon libraries), so it works fully offline and needs no extra files in Docker.

## Next Steps

- [API](api.md) — the endpoints the dashboard uses.
- [How It Works](how-it-works.md) — the terminal HUD and commands.
- [Troubleshooting](troubleshooting.md) — if the dashboard won't load.
