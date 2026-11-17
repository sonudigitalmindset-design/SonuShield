# Features

Everything SonuShield can do today. Every feature below exists in the current code — planned work lives separately in the [Roadmap](roadmap.md).

## TLS Fingerprinting

![TLS fingerprinting](assets/fingerprinting.svg)

TLS fingerprinting opens up a whole new range of ways to defend against malicious attacks. You can use it to whitelist specific fingerprints (for example, SEO bots), blacklist unwanted fingerprints (for example, WordPress exploit crawlers), rate-limit attackers that change IPs through proxies, or simply learn more about a visitor.

In Cloudflare mode, TLS fingerprinting is not available: the fingerprint and browser are reported as `Cloudflare` instead. Details: [How It Works](how-it-works.md#tls-fingerprinting).

Alongside the legacy fingerprint, SonuShield computes a JA4 fingerprint for every TLS connection and an `sh1` HTTP request fingerprint (sorted header names, cookie presence, and other request properties). JA4 values can be allow/block-listed like legacy fingerprints and matched in [firewall rules](firewall-rules.md) (`ip.ja4`, `http.fingerprint`). SonuShield JA4 values are computed from the fields Go's TLS stack exposes, so they are only comparable with other SonuShield-computed values — never with external JA4 databases. The built-in JA4 lists start empty; operators add values they observe themselves via `ja4_fingerprints.json` (see [Configuration](configuration.md#ja4-local-overrides)).

## Staged DDoS Mitigation

![Three challenge stages](assets/stages.svg)

Three challenges, weakest first, escalating automatically when the current one is bypassed: an invisible cookie challenge, a proof-of-work JavaScript challenge, and a custom captcha. Stage switching is driven by per-domain request-rate thresholds, and any stage can be locked manually from the terminal. Details: [How It Works](how-it-works.md#staged-ddos-mitigation).

## DDoS Alerts

![Discord DDoS alert](assets/alerts.svg)

SonuShield can notify you over Discord whenever one of your domains comes under attack and when the attack ends. Each alert is a Discord embed titled "DDoS Alert" containing your configured message plus fields for the current total and allowed requests per second. The attack-end alert additionally reports the peak request rates and includes a traffic chart.

Alerts are only sent when the stage is **not** locked, when the first stage starts being bypassed, and when the attack ends. Setup: per-domain [`webhook`](configuration.md#webhook) settings.

## Lightweight

![Lightweight](assets/lightweight.svg)

SonuShield is a single static binary designed to run smoothly on small servers with minimal resource use. Everything has its limits, though: it runs on one server, so it cannot absorb volumetric attacks large enough to saturate that server's network connection on its own. For very large attacks, use it together with an upstream protection service.

## Cloudflare Mode

![Cloudflare mode](assets/cloudflare-mode.svg)

SonuShield can run behind Cloudflare: set `cloudflare` to `true` in your configuration. The proxy listens on port 80 only, reads the client IP from the `Cf-Connecting-Ip` header, does not load TLS certificates, and TLS fingerprinting is unavailable. Your Cloudflare SSL/TLS encryption mode must be set to `Flexible`. Details: [How It Works](how-it-works.md#cloudflare-mode).

## Web Dashboard

![Dashboard schematic](assets/dashboard.svg)

A read-only monitoring dashboard served by the proxy itself: live request rates, totals, CPU/RAM, stage, top IPs, firewall rules, and recent logs — in two themes (Premium Dark and Official Classic Light), with no external resources. Details: [Dashboard](dashboard.md).

## Terminal HUD and Commands

![Terminal HUD schematic](assets/terminal-hud.svg)

While the proxy runs, the terminal shows a live HUD (CPU usage, watched domain, stage, total and bypassed requests per second, latest logs) and accepts commands: `help`, `stage`, `domain`, `add`, `clrlogs`, and `reload`. Details: [How It Works](how-it-works.md#terminal).

## Custom Firewall Rules

![Firewall rules schematic](assets/firewall-rules.svg)

Write your own rules with a Wireshark-style expression language (via gofilter): match on IP, browser, fingerprint, path, user agent, stage, request rates, and more, then set or adjust the request's suspicion level — allow, challenge, captcha, or block. Details: [Firewall Rules](firewall-rules.md).

## Adaptive Proof-of-Work

With `adaptivePow` enabled per domain, the Stage 2 puzzle difficulty scales with load — easy under normal traffic, progressively harder as an attack that bypasses Stage 1 grows — within operator-set bounds. Legitimate visitors under normal load notice nothing different. Details: [Configuration](configuration.md#adaptive-proof-of-work).

## Turnstile / hCaptcha Challenges

A domain can serve a Cloudflare Turnstile or hCaptcha challenge instead of the proof-of-work page, using the operator's own provider keys. The challenge uses the provider's invisible-mode widget with automatic execution, so legitimate visitors see only a brief verifying page. Without keys the feature is inert and proof-of-work is used. Details: [Configuration](configuration.md#challenge-providers).

## Geo / ASN Rules and IP Reputation

Firewall rules can match on country (`ip.country`) and ASN (`ip.asn`) using operator-supplied MaxMind DB files, and on IP reputation (`ip.reputation`) using a local blocklist plus an optional external feed. Both are fail-open: a missing database or a failed feed fetch never blocks anyone. Details: [Configuration](configuration.md#geo-and-asn-rules) and [IP Reputation](configuration.md#ip-reputation).

## WAF-Lite

Conservative inspection for common SQL injection, cross-site scripting, and path-traversal shapes, plus WordPress login-flood protection. Log-only by default — matches are logged and the request continues — with opt-in per-domain blocking that answers with a generic unbranded 403. Details: [Configuration](configuration.md#waf-lite).

## Automatic SSL

With `autoSSL` enabled, domains without certificate files get Let's Encrypt certificates automatically (ACME HTTP-01), cached on disk and renewed without operator action. Domains with explicit certificates keep using them. Details: [Configuration](configuration.md#automatic-ssl).

## Quiet Mode

With `quietMode` enabled, visitor-facing output carries no product identification: no `SonuShield` response header, generic block and error messages, and a generic unknown-host page. Attribution is unaffected — the credits endpoint, license, and docs credits always stay. Details: [Configuration](configuration.md#quiet-mode).

## HTTP API

![API schematic](assets/api.svg)

Two API versions expose proxy statistics, firewall rules, and logs as JSON, authenticated with your `apisecret` (v1 additionally uses the `adminsecret` path). They also expose feature controls: read live feature settings, adjust adaptive proof-of-work and WAF-lite settings at runtime, and trigger a reputation-feed refresh. The dashboard itself is built on API v2. Details: [API Reference](api.md).

## Rate Limiting

Per-IP and per-fingerprint rate limits within a configurable time window: total requests, unknown-fingerprint requests, failed challenge attempts, and connections opened without sending a request. Limits that are exceeded block the offender. Details: [Configuration](configuration.md#proxy-settings).
