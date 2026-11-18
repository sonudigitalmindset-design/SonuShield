# How an Attack Is Stopped

A plain-English walkthrough of what happens to every request that reaches SonuShield — the same journey, told twice: once for a real visitor, once for an attacker. No technical background needed. For the technical version, see [How It Works](how-it-works.md); for every feature in detail, see the [feature index](features.md).

> [← README](../README.md)

![Attack vs defense journey](assets/attack-defense-journey.svg)

The diagram shows two lanes. The **top lane** is a real visitor: they pass quietly through a few checks and reach your website, noticing nothing. The **bottom lane** is a botnet flood: the same checks catch it, its suspicion climbs step by step, it fails the challenges, gets slowed to a drip, and is blocked before it ever reaches your website. The **dark band in the middle** lists the 16 defense layers in the order every request meets them. The numbered steps below follow that exact order.

One rule governs everything below: a request's **suspicion level** starts at your domain's current stage, and **a suspicion level of 4 or higher blocks the request outright**. Each layer below either adds suspicion, acts on it, or serves the requests that passed.

## The journey, step by step

### 1. Fingerprinting — recognising the client before anything else

**What happens:** The moment a connection arrives, SonuShield takes fingerprints of the client: the TLS handshake, a [JA4](features/detection.md#ja4-fingerprinting) fingerprint, SonuShield's own `sh1` HTTP fingerprint built from request headers, an [HTTP/2](features/detection.md#http2-fingerprinting) fingerprint from the signals Go's network stack exposes, and — on HTTP/3 connections — a [QUIC](features/detection.md#quic-fingerprinting) fingerprint. Known fingerprints are looked up against lists fetched at startup. [Post-quantum TLS](features/resilience.md#pq-tls) (X25519MLKEM768) is on unless [`tlsDisablePostQuantum`](configuration.md#post-quantum-tls) opts out, and [JA4 overrides](configuration.md#ja4-local-overrides) can be set locally.

**The attacker:** A bot using a scripted client, an unusual TLS library, or a spoofed browser leaves a fingerprint that does not match any real browser — suspicion starts climbing immediately.

**The visitor:** Nothing. Fingerprinting is silent; no page loads, no delay.

**Features:** [TLS Fingerprinting](features/detection.md#tls-fingerprinting) · [JA4](features/detection.md#ja4-fingerprinting) · [sh1](features/detection.md#sh1-http-fingerprint) · [HTTP/2](features/detection.md#http2-fingerprinting) · [QUIC](features/detection.md#quic-fingerprinting) · [Passive OS Fingerprinting](features/detection.md#os-fingerprinting)

**Honest limit:** JA4 values are only comparable within SonuShield, and the HTTP/2 fingerprint sees only what Go exposes — some handshake details are unobservable and documented as such. In Cloudflare mode there is no TLS fingerprinting at all, because Cloudflare terminates TLS. Fingerprints identify *kinds* of clients, not people.

### 2. Rate limits — counting how fast requests arrive

**What happens:** Requests are counted per IP and per fingerprint within the [`ratelimit_time`](configuration.md#domain-settings) window, which is counted in seconds, defaults to 10 when unset, and is raised to 10 if set lower. There are separate counters for total requests, unknown fingerprints, challenge failures, and connections that send nothing. On multi-server setups, [Redis shared state](features/resilience.md#redis-shared-state) keeps the counters consistent across nodes.

**The attacker:** A flood from one IP or one fingerprint hits the limit within seconds and starts collecting suspicion instead of answers.

**The visitor:** Nothing. One person browsing never comes close to these limits.

**Feature:** [Rate Limits](features/performance.md#rate-limits)

**Honest limit:** The example numbers in the configuration docs are examples, not defaults — you set your own thresholds per domain. Rate limits alone cannot tell a flash crowd from a distributed flood; that is what the later layers are for. Also at this point: [per-session limits](features/firewall.md#per-session-limits), a [payload limit](features/performance.md#payload-limits) of 32 MiB by default (larger bodies get a 413 answer), and [slowloris / request-smuggling guards](features/performance.md#slowloris-guards) that rely on Go's normal request handling plus the proxy re-framing requests.

### 3. WAF-lite — scanning requests for known attack patterns

**What happens:** The request is scanned against 15 built-in patterns for common web attacks, plus a WordPress login-flood check: more than 20 POSTs per IP per minute to `/wp-login.php` or `/xmlrpc.php` trips it. [`wafMode`](configuration.md#waf-lite) defaults to `log` — matches are only logged. In `block` mode a match gets a generic 403. [`wafInspectBody`](configuration.md#waf-lite) also scans request bodies up to 1 MB.

**The attacker:** Exploit probes and login floods get logged, and blocked if you enabled block mode — with a plain 403 that reveals nothing about which pattern matched.

**The visitor:** Nothing. Normal browsing does not match attack patterns, and log-only mode never blocks anyone.

**Feature:** [WAF-lite](features/firewall.md#waf-lite)

**Honest limit:** Pattern matching is not a full web application firewall — it catches known shapes, not novel attacks. By default it only watches; blocking is your choice. The login-flood check only covers the two WordPress endpoints named above.

### 4. Traps — honeypots, impostor bots, and canary tokens

**What happens:** Three traps run together. [Honeypot endpoints](configuration.md#honeypot-endpoints) are secret URLs no real visitor ever sees; touching one adds suspicion ([`honeypotSusLv`](configuration.md#honeypot-endpoints) defaults to 2), and the match must be exact and case-sensitive. [Fake search-bot verification](configuration.md#fake-search-bot-verification) checks whether a client claiming to be Googlebot or Bingbot really comes from Google's or Microsoft's networks, using reverse and forward DNS; failures add suspicion ([`fakeBotSusLv`](configuration.md#fake-search-bot-verification) defaults to 3), results are cached (1 hour for verified or fake, 5 minutes for unchecked), and DNS failures fail open. [Canary tokens](configuration.md#canary-tokens) are secret values planted where only an attacker would find them; using one means a generic 403, maximum suspicion, and an alert — rate-limited to one alert per IP per hour, and token values are never logged.

**The attacker:** Scanners that crawl every URL, and bots faking a search-engine identity, walk straight into traps and expose themselves.

**The visitor:** Nothing. Real visitors never visit a honeypot URL or carry a canary token.

**Features:** [Honeypot Endpoints](features/detection.md#honeypot) · [Fake Search-Bot Verification](features/detection.md#fake-bot-check) · [Canary Tokens](features/detection.md#canary-tokens)

**Honest limit:** A honeypot only catches scanners that probe the exact trap URL. Fake-bot verification depends on DNS, so it fails open when DNS cannot answer. A canary only fires when someone actually uses the token.

### 5. Geo / ASN — where the request comes from

**What happens:** Using the operator's own GeoIP database (`operator.mmdb`), SonuShield looks up the request's country and network (ASN). Your rules can then treat traffic from places you do not serve, or from networks known for abuse, with extra suspicion. Without a database, this layer fails open — it adds nothing.

**The attacker:** A flood from an unexpected country or a bulletproof-hosting network stands out immediately.

**The visitor:** Nothing. Being in an ordinary location adds no suspicion at all.

**Feature:** [Geo / ASN Rules](features/detection.md#geo-asn-rules) ([configuration](configuration.md#geo-and-asn-rules))

**Honest limit:** GeoIP data is approximate, VPNs hide real locations, and you must supply the database yourself from your own MaxMind account — none is bundled. Geography is a signal, never proof.

### 6. Reputation — has this IP misbehaved before?

**What happens:** The IP is checked against your local blocklist and an optional reputation feed: a plain-text list of one IP or CIDR per line, `#` comments allowed, capped at 10 MB, refreshed every [`reputationFeedInterval`](configuration.md#ip-reputation) (default 60 minutes, minimum 5). A listed IP receives the reputation bump ([`reputationSusLv`](configuration.md#ip-reputation) defaults to 1) — applied *after* the firewall rules run. [Cross-domain sharing](configuration.md#cross-domain-reputation-sharing) lets your domains warn each other: an indicator shared from another of your domains adds 1 to suspicion. The [threat-sharing network](features/api-security.md#threat-sharing) exchanges indicators with peer operators over HMAC-signed requests, adding at most 1 suspicion, failing open, with no central server and no personal data. Your [allow and block lists](configuration.md#ip-allow-and-block-lists) also live here: an allowlisted IP starts at suspicion 0 and bypasses rate-limit and fingerprint blocks.

**The attacker:** An IP already known for abuse starts the journey with suspicion already on the board — and gets no second chance from a fresh domain, because your domains share what they learned.

**The visitor:** Nothing. Clean IPs are not on any list.

**Features:** [IP Reputation](features/detection.md#ip-reputation) · [Cross-Domain Reputation Sharing](features/detection.md#shared-reputation) · [IP Manager](features/firewall.md#ip-manager)

**Honest limit:** Lists are only as good as the feed behind them, and no feed is bundled — you bring your own. A feed that goes stale or unreachable fails open rather than blocking the world, which means a dead feed silently stops protecting you.

### 7. Risk score — one number, 0 to 100

**What happens:** All the signals so far are combined into a single risk score from 0 to 100, using fixed weights: the stage at arrival (0/10/30/50/70), a known fingerprint (−10), a bot-listed fingerprint (+25), an unknown fingerprint (+15), a reputation-listed IP (+25), shared reputation (+15), a timing anomaly (+20), challenge failures (more than 10: +10; more than 50: +20), a high-risk country (+15), and a high-risk ASN (+15). The result is clamped to 0–100, and your firewall rules can read it as the `ip.risk` field. See [Risk Score](configuration.md#risk-score) for the exact configuration.

**The attacker:** Every bad signal stacks into one visible number — and your rules can block or challenge on that number alone.

**The visitor:** Nothing. A known browser from a clean IP in an ordinary country scores near zero.

**Feature:** [Risk Score](features/detection.md#risk-score)

**Honest limit:** The weights are fixed, not learned — they do not adapt to your traffic. The score is advisory unless your rules act on it. The experimental [ML anomaly detector](features/detection.md#anomaly-detector) is separate: log-only, off by default, and evaluated only on synthetic traffic, so its threshold is expected to be miscalibrated on real traffic.

### 8. Timing and behavior — does it act like a machine?

**What happens:** Request timing is analysed for two machine patterns: *Regular* — 12 or more requests with a coefficient of variation under 0.08 and a mean interval under 500 ms — and *Burst* — 50 or more requests in one second. Slow polling (intervals of 1 second or more) is never flagged. Detection is log-only by default; [`timingEnforce`](configuration.md#timing-and-behavior-detection) applies [`timingSusLv`](configuration.md#timing-and-behavior-detection) (default 1), and at most one timing log event is written per IP per minute. Related signals run here too: [credential stuffing detection](configuration.md#credential-stuffing-detection) (per-IP threshold 10, distributed threshold 20 distinct IPs, 300-second window, failure statuses 401/403, block mode adds only +2 suspicion, and no credential data is ever stored) and [session hijack detection](configuration.md#session-hijack-detection), which flags a session only when at least 2 bound signals differ, storing cookie values only as SHA-256 hashes.

**The attacker:** A script hammering at perfectly regular intervals, or bursting 50 requests in a second, looks nothing like a human — and gets flagged as a machine.

**The visitor:** Nothing. Human browsing is irregular and slow by comparison.

**Features:** [Timing & Behavior Detection](features/detection.md#timing-detection) · [Credential Stuffing Detection](features/detection.md#credential-stuffing) · [Session Hijack Detection](features/detection.md#session-hijack)

**Honest limit:** Timing catches machine-regular and burst patterns only; a bot that deliberately randomises its delays can pass. Stuffing detection adds at most +2 suspicion, and hijack detection flags — your rules decide what happens next.

### 9. Firewall rules — your own decisions, in order

**What happens:** Your per-domain rules run, using the gofilter expression language: [edge rules](features/firewall.md#edge-rules) first, then general rules. Each matching rule adjusts the suspicion level. This is where everything so far turns into a decision — and where the block rule bites: suspicion 4 or higher blocks outright. Rules can be tested safely first with the [rule simulator](features/firewall.md#rule-simulator) and [dry-run mode](configuration.md#domain-settings) (matches only logged), evaluated without affecting traffic in [shadow mode](features/performance.md#shadow-mode), imported and exported in bulk, loaded from [community rule packs](features/firewall.md#community-packs), [imported from Cloudflare](features/firewall.md#cloudflare-import) or [nginx/Apache configs](features/firewall.md#nginx-apache-import), and switched on schedules with [scheduled rules and maintenance windows](features/firewall.md#scheduled-rules).

**The attacker:** Every bad signal collected so far is now weighed by your rules — and the request is allowed, challenged, or blocked on the total.

**The visitor:** Nothing. No rule matches an ordinary request, so it sails through.

**Features:** [gofilter Firewall](features/firewall.md#gofilter-firewall) · [Edge Rules](features/firewall.md#edge-rules) · [Rule Simulator](features/firewall.md#rule-simulator)

**Honest limit:** Rules are only as good as the person who writes them — a wrong rule can block real visitors, which is why dry-run and the simulator exist. Two gofilter quirks to know: boolean fields never match with `eq`/`ne`, and IP literals must be bare, not quoted.

### 10. Challenges — prove you are a browser, in three stages

**What happens:** Suspicious-but-not-blocked requests face a staged challenge, and the stage escalates automatically when bypasses grow, following your [stage thresholds](configuration.md#stage-thresholds); the `stage` command can lock a stage, and a stage above 3 blocks all requests. **Stage 1** is a cookie challenge: completely invisible, supported by every browser and most HTTP libraries. **Stage 2** is a proof-of-work puzzle the browser solves with JavaScript: [`stage2Difficulty`](configuration.md#adaptive-proof-of-work) defaults to 5 when unset, and [adaptive PoW](configuration.md#adaptive-proof-of-work) scales difficulty with bypassed traffic between your configured minimum and maximum. The original project measured solve times of about 3.100s at difficulty 5, 0.247s at 4, 0.244s at 3, 0.215s at 2, and 0.212s at 1. With operator keys, [Turnstile or hCaptcha](configuration.md#challenge-providers) can replace Stage 2 with an invisible-mode widget verified server-side; without valid keys it falls back to proof-of-work. [Memory-hard PoW](configuration.md#memory-hard-proof-of-work) (defaults: 4 bits, 512 KiB memory, time factor 1, 10-minute nonce) and [challenge rotation](configuration.md#challenge-rotation) vary the puzzle. **Stage 3** is the last resort: a custom captcha — drag a slider to reveal green text hidden in a picture, then type the text (up to 6 characters) — or a [passkey challenge](configuration.md#passkey-challenge) with a single-use nonce bound to IP, TLS fingerprint, and user agent (10-minute TTL), falling back to captcha. Challenge pages can use [custom pages and Hindi text](configuration.md#custom-challenge-pages), run in [quiet mode](configuration.md#quiet-mode) with no product branding, and carry a [mouse/scroll behavior check](features/detection.md#behavior-check) and [invisible markers](features/detection.md#invisible-markers) that only log. Requests to the API, dashboard, metrics, and public API paths that carry a valid secret [bypass the challenge flow entirely](features/challenges.md#challenge-exemption); a missing or wrong secret falls through to the normal flow.

**The attacker:** A script fails the invisible cookie check. A headless browser faces a puzzle that costs real CPU time on every request. A persistent bot ends at a captcha it cannot solve — and every failure raises its suspicion further.

**The visitor:** Almost always nothing: the invisible Stage 1 check passes silently. Only if your domain is under active attack and the stage has escalated might a real visitor briefly see a loading page — and even then, no puzzle to solve by hand until Stage 3.

**Features:** [Staged Challenges](features/challenges.md#staged-challenges) · [Adaptive PoW](features/challenges.md#adaptive-pow) · [Challenge Providers](features/challenges.md#challenge-providers) · [Passkey Challenge](features/challenges.md#passkey-challenge) · [Quiet Mode](features/challenges.md#quiet-mode)

**Honest limit:** Stage 3 also stops good bots. The proof-of-work page loads its solver from the 41Baloo CDN, so visitors' browsers must be able to reach it. And a determined attacker driving a real browser can pass challenges — challenges raise the attacker's cost, they do not make attacks impossible.

### 11. Tarpit — slowing confirmed-bad requests to a drip

**What happens:** Requests that are confirmed bad — by default, only blocked requests, since [`tarpitSusLv`](configuration.md#tarpit) defaults to 4 — can be tarpitted: the proxy answers excruciatingly slowly instead of refusing at once, holding the attacker's connections open and wasting the attacker's time, not yours. The delay is capped at 30 seconds, and at most [`tarpitMaxConns`](configuration.md#tarpit) connections (default 64, clamped to 1–1024) are held at once.

**The attacker:** Connections crawl. A botnet holding thousands of slow connections runs out of capacity to attack anything else.

**The visitor:** Nothing. Tarpitting only touches requests already judged bad.

**Feature:** [Tarpit](features/firewall.md#tarpit)

**Honest limit:** The delay is capped at 30 seconds, the number of held connections is bounded, and a tarpit is a delay, not a block — it buys time and wastes attacker resources, it does not remove the attacker.

### 12. Edge cache — answering repeat requests without bothering your server

**What happens:** Requests that passed all checks first look in the [edge cache](configuration.md#edge-caching): only GET requests, only statuses 200/203/301/308, entries capped at 1 MB, total size capped at [`edgeCacheMaxMB`](configuration.md#edge-caching) (default 64), entries living for [`edgeCacheTTL`](configuration.md#edge-caching) (default 60 seconds). Expired entries are kept for up to 1 hour past expiry so a stale copy can be served, clearly marked with a `Warning: 110` header, when every backend is down. The cache can be purged from the dashboard or API, and [cache analytics](configuration.md#cache-analytics-and-purge) show what is being served from it.

**The attacker:** Never gets here — blocked requests do not reach the cache. An attacker probing for cacheable pages only ever sees what a visitor would see.

**The visitor:** A faster page. Repeat visits are answered from memory, in milliseconds, without touching your server.

**Features:** [Edge Cache](features/performance.md#edge-cache) · [Cache Analytics](features/performance.md#cache-analytics)

**Honest limit:** Only GET requests and only the listed statuses are cached, and only what you enable per domain — personalised pages must stay out of the cache. A stale copy is a fallback, not fresh content, and it says so in its header.

### 13. Waiting room — a fair queue when the site is overloaded

**What happens:** When enabled and the site is loaded, excess visitors enter a [waiting room](configuration.md#waiting-room): a first-in-first-out queue admitting [`waitingRoomAdmit`](configuration.md#waiting-room) visitors per second (default 20), capped at 5,000 queued entries — beyond that, a 503 answer with a `Retry-After` header. Queue places are held with signed, IP-bound cookies; admitted visitors get a cookie good for 10 minutes, and stale entries are pruned every 15 minutes. [Fair queuing](configuration.md#fair-queuing) keeps admission round-robin per IP, so one address cannot hog the queue.

**The attacker:** Joins the back of the same queue as everyone else — and a flood from few IPs gets a fair share, not the whole site.

**The visitor:** During a genuine overload, a short, honest wait with a place in line — instead of a crashed site. When the site is not loaded, the waiting room never appears.

**Features:** [Waiting Room](features/performance.md#waiting-room) · [Fair Queuing](features/performance.md#fair-queuing)

**Honest limit:** The waiting room only runs when enabled and loaded, the queue is capped, and it needs cookies — a client that refuses cookies cannot hold a queue place.

### 14. API protection — the gate for programs, not browsers

**What happens:** Requests that passed the earlier layers and target your API face a dedicated gate: [JWT verification](configuration.md#api-protection) (HS256, or RS256/ES256 via JWKS, standard library only, `alg: none` rejected), per-key rate limits, and GraphQL depth and field limits. Around the gate: [mobile app attestation](configuration.md#mobile-app-attestation) (JWT-form verification of signature, issuer, audience, expiry, and verdict claim), [OpenAPI validation](configuration.md#openapi-validation) against your spec, [DLP scanning](configuration.md#dlp-scanning) with your own regular expressions (none bundled, matched content is never logged, stored, or returned), [signed URLs and hotlink protection](configuration.md#signed-urls-and-hotlink-protection) (strict HMAC, no clock skew, Referer allowlist), and a [form spam guard](configuration.md#form-spam-guard).

**The attacker:** Stolen or forged tokens are rejected, API keys that hammer the API are throttled, and oversized or malformed API abuse is stopped at the gate.

**The visitor:** Nothing — unless they use your app, in which case valid tokens pass silently.

**Features:** [API Protection](features/api-security.md#api-protection) · [Mobile Attestation](features/api-security.md#mobile-attestation) · [OpenAPI Validation](features/api-security.md#openapi-validation) · [DLP Scanning](features/api-security.md#dlp-scanning)

**Honest limit:** GraphQL limits are a depth and field approximation, not a full query parser. Mobile attestation verifies JWT-form tokens only — Apple App Attest CBOR is not parsed. DLP scanning fails open on oversized or encoded bodies, which pass unscanned. OpenAPI validation covers a documented subset of the schema language.

### 15. Load balancing and failover — spreading what passed across your servers

**What happens:** Surviving requests are forwarded to your backends, distributed across them when several are configured. A backend is marked down after 2 consecutive transport failures and rests for a 30-second cooldown; retries happen only when the request body can be replayed (GET/HEAD, or a body with `GetBody`). [Health checks](configuration.md#load-balancing-and-failover) probe backends every [`healthCheckInterval`](configuration.md#load-balancing-and-failover) (default 10 seconds, minimum 5) with a 3-second probe timeout. [Origin pooling and the stampede guard](configuration.md#origin-pooling-and-stampede-guard) coalesce simultaneous identical cache misses into a single origin fetch, and [WebSocket connections](configuration.md#websocket-support) are proxied through.

**The attacker:** Sees nothing of this — by now, only legitimate-looking traffic is being forwarded, and a dead backend does not become an error page for the attacker to study.

**The visitor:** A working site even when one of your servers is down, and no thundering herd when a popular page expires from the cache.

**Features:** [Load Balancing & Failover](features/performance.md#lb-failover) · [Origin Pooling](features/performance.md#origin-pooling) · [WebSocket Proxying](features/performance.md#websocket-proxying)

**Honest limit:** Failover needs at least two backends to fail over to, and health checks only see what you configure them to probe. Non-replayable requests cannot be retried on another backend.

### 16. Origin lock — making sure only SonuShield can reach your server

**What happens:** The last layer protects the path between SonuShield and your server. With [`originLockSecret`](configuration.md#origin-lock) configured, every forwarded request carries an `X-SonuShield-Origin` header with the secret — and any same-named header sent by the client is stripped first, so attackers cannot forge it. The secret lives only in the configuration file: it is never accepted or returned through the API. Responses on the way back can carry [security headers and CORS settings](configuration.md#security-headers-and-cors) (the proxy's values overwrite the backend's), and [Brotli compression and image optimization](configuration.md#brotli-and-image-optimization) (opt-in, bounded) keep responses small.

**The attacker:** Cannot bypass SonuShield by talking to your server directly — direct requests arrive without the secret header.

**The visitor:** Nothing. The header is invisible, and compression only makes pages faster.

**Features:** [Origin Lock](features/api-security.md#origin-lock) · [Security Headers](features/api-security.md#security-headers) · [Brotli & Image Optimization](features/performance.md#brotli-image-optimize)

**Honest limit:** The lock only holds if your origin is set to require the header — the proxy can only send it. And the secret must stay in the config file; anyone who can read your config can read the secret.

## What the attacker sees vs what you see

**The attacker sees:** an invisible check that silently fails them; puzzle pages that burn their CPU; a captcha they cannot solve; plain generic 403 answers that explain nothing; connections that drip instead of answering; blocks with no reason given. They never learn which layer stopped them, what their score was, or what your rules say.

**You see:** everything, live. The [dashboard and control panel](features/operations.md#dashboard-control-panel) show traffic, stages, and blocks as they happen; [alerts](features/observability.md#alerts) reach you over Discord, Telegram, email, and — via Twilio — [WhatsApp and SMS](features/observability.md#twilio-alerts); [attack reports](features/observability.md#attack-reports) summarise each wave in JSON or CSV; the [attack map](features/observability.md#attack-map) shows where it came from; and the [attack timeline and postmortem](features/observability.md#attack-timeline) reconstruct what happened afterwards. For multi-server setups, the [control plane](features/platform.md#control-plane) manages every node from one login.

**The honest ending:** no system stops 100% of attacks. Challenges raise the attacker's cost; they do not make attacks impossible — a determined attacker driving a real browser can pass them. And a volumetric flood bigger than your own connection still needs upstream help: SonuShield provides [scrubbing-integration hooks and documentation](features/resilience.md#scrubbing-hooks), but no built-in scrubbing capacity of its own. What SonuShield does guarantee is the shape of the story above: real visitors notice nothing, and attackers pay more at every step.

---

*Technical companion: [How It Works](how-it-works.md) · Every feature: [Features](features.md) · Every setting: [Configuration](configuration.md)*
