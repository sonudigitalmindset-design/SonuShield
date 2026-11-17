# SonuShield

SonuShield is a lightweight HTTP anti-DDoS reverse proxy written in Go. It sits in front of your web server, fingerprints incoming TLS connections, and automatically escalates through three challenges — an invisible cookie challenge, a proof-of-work JavaScript challenge, and a custom captcha — as attacks get stronger, while affecting real visitors as little as possible.

> **Attribution:** Originally by [41Baloo (balooProxy)](https://github.com/41Baloo/balooProxy), forked and rebuilt by [Sonu Digital Mindset](https://github.com/sonudigitalmindset-design). SonuShield is free software licensed under the [GNU General Public License v3.0](LICENSE). The original project's copyright and license notices are preserved.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Certificates](#certificates)
- [Running](#running)
- [Docker](#docker)
- [DNS Setup](#dns-setup)
- [Configuration](#configuration)
- [Terminal](#terminal)
- [Commands](#commands)
- [Custom Firewall Rules](#custom-firewall-rules)
- [API](#api)
- [Dashboard](#dashboard)
- [Startup Checks](#startup-checks)
- [Roadmap](#roadmap)
- [License](#license)

## Features

### TLS Fingerprinting

TLS fingerprinting opens up a whole new range of ways to defend against malicious attacks. You can use it to whitelist specific fingerprints (for example, SEO bots), blacklist unwanted fingerprints (for example, WordPress exploit crawlers), rate-limit attackers that change IPs through proxies, or simply learn more about a visitor.

In [Cloudflare Mode](#cloudflare-mode), TLS fingerprinting is not available: the fingerprint and browser are reported as `Cloudflare` instead.

### Staged DDoS Mitigation

SonuShield comes with 3 distinct challenges. It starts with the weakest, least noticeable challenge and automatically switches to stronger ones when it detects the current one is being bypassed.

| Stage | Challenge | Effect |
|-------|-----------|--------|
| 1 | Cookie challenge | Invisible; stops simple attacks |
| 2 | Proof-of-work JS challenge | Stops more advanced bots |
| 3 | Custom captcha | Last resort; stops most malicious requests and good bots too |

Stage switching is automatic and driven by the per-domain thresholds in your configuration (see [Stage Thresholds](#stage-thresholds)). You can also lock a stage manually with the [`stage`](#commands) terminal command. Firewall rules can raise a request's suspicion level above the current stage; a level of 4 or higher blocks the request outright (see [Custom Firewall Rules](#custom-firewall-rules)).

#### Cookie Challenge

The cookie challenge is completely invisible and supported by every web browser as well as most HTTP libraries. It is an effective method to defend against simple DDoS attacks.

#### PoW JS Challenge

The proof-of-work JavaScript challenge reliably blocks slightly more advanced bots while impacting the user experience as little as possible. The visitor sees a loading animation with the text "Completing challenge ..." while their browser solves a small proof-of-work puzzle automatically; the page then reloads into the protected site. The challenge page also displays the `publicSalt` and `challenge` values used for that attempt.

Solve times measured by the original project:

| Difficulty | Approx. solve time |
|------------|--------------------|
| 5 | ~3.100 seconds |
| 4 | ~0.247 seconds |
| 3 | ~0.244 seconds |
| 2 | ~0.215 seconds |
| 1 | ~0.212 seconds |

The difficulty is set per domain with `stage2Difficulty` (default `5` when unset). Note: the challenge page loads the `balooPow` proof-of-work script from a public CDN (the `41Baloo/balooPow` repository). Your visitors' browsers must be able to reach that CDN for Stage 2 challenges to complete.

#### Custom Captcha

The custom captcha should be your last resort, or be used to protect especially weak pages. The visitor drags a slider to reveal green text hidden in a picture, then types the text (up to 6 characters) into the form. This stops most malicious requests as well as good bots.

### DDoS Alerts

SonuShield can notify you over Discord whenever one of your domains comes under attack and when the attack ends. Each alert is a Discord embed titled "DDoS Alert" containing your configured message plus fields for the current total and allowed requests per second. The attack-end alert additionally reports the peak request rates and includes a traffic chart.

Alerts are only sent when the stage is **not** locked, when the first stage starts being bypassed, and when the attack ends. To set this up, configure the per-domain [`webhook`](#webhook) settings.

### Lightweight

SonuShield is a single static binary designed to run smoothly on small servers with minimal resource use. Everything has its limits, though: it runs on one server, so it cannot absorb volumetric attacks large enough to saturate that server's network connection on its own. For very large attacks, use it together with an upstream protection service.

### Cloudflare Mode

Not everyone can afford expensive servers and a global CDN. SonuShield can run behind Cloudflare: set `cloudflare` to `true` in your configuration. In this mode the proxy listens on port 80 only, reads the client IP from the `Cf-Connecting-Ip` header, does not load TLS certificates, and TLS fingerprinting is unavailable. Your Cloudflare SSL/TLS encryption mode must be set to `Flexible` for this to work. Enabling Cloudflare mode without actually using Cloudflare will not work.

## Requirements

- Go 1.24 or newer, to build from source.
- A server with ports 80 and 443 available (443 is only used outside Cloudflare mode).
- Outbound HTTPS access to `raw.githubusercontent.com` at startup, for the fingerprint lists and the version check (see [Startup Checks](#startup-checks)).
- One TLS certificate and private key per domain, unless you run in Cloudflare mode (see [Certificates](#certificates)).

## Installation

### Build from Source

```sh
git clone https://github.com/sonudigitalmindset-design/SonuShield.git
cd SonuShield
go build -o main .
```

This produces a `main` binary in the repository directory.

### Automatic Prerelease Builds

Every push to the `main` branch publishes an automatic prerelease build (tag `latest`) through GitHub Actions. These builds may contain bugs. You can find them on the [Releases page](https://github.com/sonudigitalmindset-design/SonuShield/releases).

### First Run

Run `./main` without a `config.json` in the same directory and SonuShield will ask you a series of setup questions (Cloudflare mode, timeouts, rate limits, then one domain) and write a `config.json` for you. Stop it with `Ctrl+C`, review the generated file, then start it again. Secrets generated during setup are random strings.

If you already have a `config.json`, place it in the same directory as the `main` binary before starting.

> **Note:** Example configurations use `CHANGE_ME` placeholder secrets. SonuShield refuses to start if any secret still contains `CHANGE_ME` — replace all of them with real random values first.

## Certificates

Outside Cloudflare mode, every domain needs a TLS certificate and private key. Their paths are set per domain with `certificate` and `key` in `config.json`, and they are loaded at startup. If a certificate or key is missing or invalid, SonuShield refuses to start.

### Development Certificates

For local testing only, generate self-signed certificates with the included script:

```sh
./scripts/generate-certs.sh
```

This writes `assets/server/server.crt` and `assets/server/server.key`, matching the paths used in `examples/config.json`. Generated certificates and keys are ignored by git and are never committed.

> **Warning:** Self-signed certificates are for development only. Browsers will show security warnings for them. In production, use real certificates (for example, from Let's Encrypt) and keep private keys secret.

Do not use any certificate or key previously found in this repository's history: the old default private key was public and must never be reused. In Cloudflare mode, leave `certificate` and `key` empty — they are not loaded.

## Running

### In the Foreground

```sh
./main
```

The terminal shows the live [HUD](#terminal) and accepts [commands](#commands). Keep the terminal open, or use one of the methods below to keep the proxy running after you log out.

### Inside a screen Session

On Ubuntu/Debian, install `screen`, then:

```sh
apt update && apt install screen
screen -S sonushield
./main
```

Detach with `Ctrl+A` then `D`. Reattach any time with:

```sh
screen -d -r
```

### As a systemd Service

Create `/etc/systemd/system/sonushield.service`:

```ini
[Unit]
Description=SonuShield anti-DDoS reverse proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sonushield
ExecStart=/opt/sonushield/main
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Place the `main` binary and your `config.json` in `/opt/sonushield`, then:

```sh
systemctl daemon-reload
systemctl enable --now sonushield
```

Binding ports 80 and 443 requires privileges: either run as `root` as above, or grant the binary the `cap_net_bind_service` capability with `setcap 'cap_net_bind_service=+ep' /opt/sonushield/main` and run it as an unprivileged user.

## Docker

The image is built in two stages: a `golang:1.24-alpine` builder stage compiles a static binary, and a minimal `alpine:3.21` runtime stage runs it as the non-root `appuser` (with `cap_net_bind_service` so it can still bind ports 80 and 443). The runtime image includes a CA certificate bundle, which the proxy needs to fetch its fingerprint lists and version information over HTTPS at startup.

Build the image from the repository root:

```sh
docker build -t sonushield .
```

Run it, mounting your configuration file into the container:

```sh
docker run -d -p 80:80 -p 443:443 -v /path/to/config.json:/app/config.json sonushield
```

Important details:

- **`config.json` is not baked into the image.** You must mount it at `/app/config.json`, as shown above.
- **Certificate files must be reachable inside the container.** If your configuration points at certificate/key paths, mount those files too and use the in-container paths in `config.json`, for example `-v /path/to/certs:/app/certs` with `certificate` set to `/app/certs/example.com.crt`. In Cloudflare mode, leave the certificate and key empty instead.
- **Generate your configuration on the host first** — run `./main` once outside Docker, or copy and edit `examples/config.json`. The interactive first-run setup is awkward inside a detached container.
- The proxy writes `crash.log` in its working directory (`/app`).

Manage the container:

```sh
docker ps                                   # find the container ID
docker attach CONTAINERID                   # open the terminal HUD
# detach from it with Ctrl+P then Ctrl+Q
docker stop CONTAINERID                     # stop the container
docker rm CONTAINERID                       # remove the container
docker rmi sonushield                       # remove the image
```

## DNS Setup

Point your domain's DNS records at the server running SonuShield:

| Type | Name | Value |
|------|------|-------|
| `A` | `@` (or your subdomain) | The proxy server's IPv4 address |
| `AAAA` | `@` (or your subdomain) | The proxy server's IPv6 address, if it has one |

Rules that matter:

- If you use SonuShield **with** Cloudflare, set the record's **Proxy status** to **Proxied**.
- If you manage DNS in Cloudflare but do **not** use SonuShield with Cloudflare, set **Proxy status** to **DNS only**.
- Make sure **no** DNS record points directly at your backend server. Otherwise attackers can bypass the proxy entirely by attacking the backend directly.
- Wait about 10 minutes for the DNS change to propagate.

To verify the proxy is in front of your site, open your website in a browser, open DevTools, go to the Network tab, and look at the response headers of a request: you should see a `SonuShield: 1.5` header. If it is there, SonuShield is successfully proxying your domain.

## Configuration

`config.json` has two top-level fields: `proxy` (general settings) and `domains` (one entry per protected domain). Firewall rules are configured per domain, under each domain's `firewallRules` — see [Custom Firewall Rules](#custom-firewall-rules).

### Example Configuration

```json
{
  "proxy": {
    "cloudflare": false,
    "adminsecret": "CHANGE_ME",
    "apisecret": "CHANGE_ME",
    "secrets": {
      "cookie": "CHANGE_ME1",
      "javascript": "CHANGE_ME2",
      "captcha": "CHANGE_ME3"
    },
    "timeout": {
      "idle": 5,
      "read": 5,
      "write": 7,
      "read_header": 5
    },
    "ratelimit_time": 120,
    "ratelimits": {
      "requests": 500,
      "unknownFingerprint": 150,
      "challengeFailures": 40,
      "noRequestsSent": 10
    },
    "colors": ["0", "31"]
  },
  "domains": [
    {
      "name": "example.com",
      "backend": "1.1.1.1",
      "scheme": "http",
      "certificate": "assets/server/server.crt",
      "key": "assets/server/server.key",
      "webhook": {
        "url": "",
        "name": "SonuShield",
        "avatar": "",
        "attack_start_msg": "Attack detected on {{domain.name}}",
        "attack_stop_msg": "Attack on {{domain.name}} has stopped"
      },
      "firewallRules": [],
      "bypassStage1": 75,
      "bypassStage2": 250,
      "stage2Difficulty": 5,
      "disableBypassStage3": 100,
      "disableRawStage3": 250,
      "disableBypassStage2": 50,
      "disableRawStage2": 75
    }
  ]
}
```

A fuller multi-domain example is available in [`examples/config.json`](examples/config.json). Remember to replace every `CHANGE_ME` secret before starting.

### Proxy Settings

| Field | Type | Description |
|-------|------|-------------|
| `cloudflare` | Bool | Set to `true` to run behind Cloudflare. See [Cloudflare Mode](#cloudflare-mode). |
| `adminsecret` | String | Secret used in the v1 API path and in the dashboard URL. Must not contain `CHANGE_ME`. |
| `apisecret` | String | Secret sent in the `proxy-secret` / `Proxy-Secret` API header. Must not contain `CHANGE_ME`. |
| `secrets` | Map[String]String | Challenge secrets with keys `cookie`, `javascript`, and `captcha`. Must not contain `CHANGE_ME`. Generate secure random values, for example with `openssl rand -hex 20` or [random.org](https://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&unique=on&format=html&rnd=new). |
| `timeout` | Object | Connection timeouts in seconds: `idle` (default 5), `read` (default 5), `write` (default 7), `read_header` (default 5). A value of `0` keeps the default. |
| `ratelimit_time` | Int | Window in seconds over which the rate limits below are counted. Values below 10 are raised to 10; defaults to 10 when unset. |
| `ratelimits` | Map[String]Int | Rate limit thresholds (see below). |
| `colors` | Array[String] | ANSI color codes for the terminal HUD, for example `["0", "31"]`. |

Rate limits (`ratelimits`), counted within the `ratelimit_time` window:

| Key | Description |
|-----|-------------|
| `requests` | Requests a single IP may send before it is blocked. |
| `unknownFingerprint` | Requests a single unknown TLS fingerprint may send before it is blocked. Only applied to clients whose browser could not be identified. |
| `challengeFailures` | Failed challenge attempts from a single IP before it is blocked. |
| `noRequestsSent` | TCP connections opened by a single IP without sending an HTTP request before it is blocked. |

### Domain Settings

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | The domain name, for example `example.com`. Requests are matched by the `Host` header. |
| `scheme` | String | Scheme used to talk to your backend: `http` or `https`. `http` is generally faster and less CPU-intensive. Note: `https` backends are contacted with TLS certificate verification disabled. |
| `backend` | String | Your backend's IP or hostname. You can specify a port, for example `1.1.1.1:8888`. |
| `certificate` | String | Path to the domain's TLS certificate, for example `assets/server/server.crt`. Not loaded in Cloudflare mode. |
| `key` | String | Path to the domain's TLS private key, for example `assets/server/server.key`. Not loaded in Cloudflare mode. |
| `webhook` | Object | Discord alert settings. See [Webhook](#webhook). |
| `firewallRules` | Array | Custom firewall rules. See [Custom Firewall Rules](#custom-firewall-rules). |
| `bypassStage1` | Int | Bypassing requests per second that activate Stage 2. |
| `bypassStage2` | Int | Bypassing requests per second that activate Stage 3. |
| `stage2Difficulty` | Int | Proof-of-work difficulty for Stage 2 (default `5` when `0`). |
| `disableBypassStage3` | Int | Bypassing requests per second low enough to disable Stage 3. |
| `disableRawStage3` | Int | Total requests per second low enough to disable Stage 3 (bypassing requests must also be low enough). |
| `disableBypassStage2` | Int | Bypassing requests per second low enough to disable Stage 2. |
| `disableRawStage2` | Int | Total requests per second low enough to disable Stage 2 (bypassing requests must also be low enough). |

Requests forwarded to your backend carry extra headers your backend can read: `x-real-ip`, `proxy-real-ip` (both the client IP), and `proxy-tls-fp` (the client's TLS fingerprint, or `Cloudflare` in Cloudflare mode).

Outside Cloudflare mode, plain HTTP requests on port 80 are redirected to HTTPS (301), except for unknown hosts, which receive an error message. In Cloudflare mode the proxy serves plain HTTP on port 80 only.

### Webhook

Each domain can send Discord DDoS alerts through a webhook. Create a webhook in your Discord server (Server Settings → Integrations → Webhooks) and see [Discord's introduction to webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) for details. Leave `url` empty to disable alerts for a domain.

| Field | Type | Description |
|-------|------|-------------|
| `url` | String | The Discord webhook URL alerts are sent to. |
| `name` | String | The name shown above the alert in Discord. |
| `avatar` | String | URL of the profile picture shown with the alert in Discord. |
| `attack_start_msg` | String | Message sent when your domain first comes under attack. |
| `attack_stop_msg` | String | Message sent when the attack has ended. |

Both messages support placeholders: `{{domain.name}}`, `{{attack.start}}`, `{{attack.end}}`, `{{proxy.cpu}}`, and `{{proxy.ram}}`.

### Stage Thresholds

The automatic stage system watches two numbers per domain: total requests per second and bypassing requests per second (requests that passed the current challenge). When bypassing requests exceed `bypassStage1`, Stage 2 activates; when they exceed `bypassStage2`, Stage 3 activates. Stages step back down when both the bypassing and total request rates fall below the matching `disable*` thresholds. Locking a stage with the [`stage`](#commands) command disables automatic switching until you unlock it with `stage 0`.

## Terminal

While SonuShield runs, the terminal shows a live HUD for the watched domain and accepts commands typed at the prompt.

### Main HUD

| Field | Description |
|-------|-------------|
| Cpu Usage | Current CPU usage of the server, in percent. |
| Domain | The domain currently being watched. |
| Stage | The stage the watched domain is currently in. |
| Stage Locked | `true` if the stage was manually set and locked with the `stage` command. |
| Total | Incoming requests per second across all requests. |
| Bypassed | Requests per second that passed the proxy and were forwarded to the backend. |
| Latest Logs | Information about the most recent requests. The number of lines shown follows the terminal height. |

### Commands

| Command | Description |
|---------|-------------|
| `help` | Shows a summary of all available commands. Type anything or press Enter to exit the help view. |
| `stage [number]` | Sets the watched domain's stage to the given number and locks it there, no matter what — even during an ongoing attack that bypasses that stage. `stage 0` unlocks the stage, resets it to 1, and re-enables automatic stage switching. A stage higher than 3 blocks all requests. |
| `domain [name]` | Switches the watched domain. With no name, lists all available domains. |
| `add` | Starts an interactive dialogue to add another domain to the proxy, then reloads the configuration. You can also edit `config.json` directly, but that requires a `reload` (or restart) to apply. |
| `clrlogs` | Clears the logs for the watched domain, or for all domains when no domain is being watched. |
| `reload` | Re-reads `config.json` and applies changes, resetting some general settings. Run this after editing the configuration by hand. |

## Custom Firewall Rules

Thanks to [gofilter](https://github.com/kor44/gofilter), SonuShield lets you add your own firewall rules using a rule engine based on [Wireshark display filter expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html).

### Fields

These fields can be used in rule expressions. Values reflect the current request and the current rate-limit window.

| Field | Type | Description |
|-------|------|-------------|
| `ip.src` | IP | The client's IP address. |
| `ip.engine` | String | The client's browser (`""` if it could not be identified). |
| `ip.bot` | String | The bot's name (`""` if not applicable). |
| `ip.fingerprint` | String | The client's raw TLS fingerprint (`Cloudflare` in Cloudflare mode). |
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
| `proxy.stage` | Int | The stage the reverse proxy is currently in. |
| `proxy.cloudflare` | Bool | `true` if the proxy is in Cloudflare mode. |
| `proxy.stage_locked` | Bool | `true` if the stage is locked to a specific stage. |
| `proxy.attack` | Bool | `true` if the proxy is under attack. |
| `proxy.bypass_attack` | Bool | `true` if the proxy is being attacked by an attack that bypasses the current security measures. |
| `proxy.rps` | Int | Currently incoming requests per second. |
| `proxy.rps_allowed` | Int | Currently incoming requests per second forwarded to the backend. |

> **Do not use** `ip.country`, `ip.asn`, `ip.requests`, `http.headers`, or `http.body` in rules. These names are registered in the rule engine but are never given values, so rules using them will not behave as expected.

### Comparison Operators

```text
(http.path eq "/")            (http.path == "/")            identical
(http.path ne "/")            (http.path != "/")            not identical
(proxy.rps gt 200)            (proxy.rps > 200)             left greater than right
(proxy.rps lt 10)             (proxy.rps < 10)              left smaller than right
(proxy.rps_allowed ge 50)     (proxy.rps_allowed >= 50)     left greater than or equal
(proxy.rps_allowed le 50)     (proxy.rps_allowed <= 50)     left smaller than or equal
```

### Logical Operators

```text
(http.path eq "/" and http.query eq "")     (http.path eq "/" && http.query eq "")     both must be true
(http.path eq "/" or http.query eq "/x")    (http.path eq "/" || http.query eq "/x")   either must be true
!(http.path eq "/")                         not(http.path eq "/")                      negates the comparison
```

### Search / Match Operators

```text
(http.user_agent contains "chrome")                          field contains value
(http.user_agent matches "(?=.*\d)(?=.*[a-z])(?=.*[A-Z])")   field matches a regex
```

### Structure

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

### Priority

Rules are evaluated from top to bottom. A rule listed earlier has priority over every rule listed after it. Some actions stop SonuShield from checking further matching rules (see below), so rules with higher action values should usually be listed higher in the array as well.

### Actions

The resulting action is decided by the request's `susLv` (suspicion level), a scale from `0` to `3` and above. It starts at the domain's current stage (normally `1`, higher during attacks) and is adjusted by matching rules.

| susLv | Reaction |
|-------|----------|
| `0` | **Allow.** The request is whitelisted and will not be challenged in any form. |
| `1` | **Cookie challenge.** A simple cookie challenge, passed automatically by most good bots. |
| `2` | **JS challenge.** A JavaScript challenge that stops most bots, including good ones. |
| `3` | **Captcha.** A visual captcha the user must solve. Stops most malicious requests as well as good bots. |
| `4` or higher | **Block.** The request is blocked. |

### Adding Actions

An `action` can set the suspicion level to an exact number. When a rule with an absolute action matches, SonuShield stops checking further rules for that request:

```json
{
  "expression": "(http.host contains \":\")",
  "action": "3"
}
```

This example challenges requests whose host contains a `:` (typical of direct socket connections) with a captcha.

Prefixing the action with `+` or `-` instead adjusts the *current* suspicion level by that amount, and SonuShield keeps checking further rules. This lets you stack multiple checks and react less aggressively when not under attack:

```json
{
  "expression": "(ip.engine eq \"\")",
  "action": "+1"
}
```

This example raises the suspicion level by `1` for requests from an unknown browser engine. A `-1` action would lower it by `1`.

## API

SonuShield exposes an HTTP API for reading proxy statistics, firewall rules, and logs. Both API versions authenticate with the `apisecret` from your configuration. The v1 path additionally contains your `adminsecret`.

> The API documentation previously hosted on SwaggerHub is no longer available. This section is the authoritative API reference for the current code.

### Version 1

Send a `POST` request with a JSON body to:

```text
POST /_bProxy/<adminsecret>/api/v1
Header: proxy-secret: <apisecret>
Body:   {"domain": "<domain name or empty>", "action": "<ACTION>"}
```

With an empty `domain`, proxy-level actions are executed. With a domain name, domain-level actions are executed for that domain.

### Version 2

Send a request to one of these paths (any method with a readable body works; the header is what authenticates the call):

```text
/_bProxy/api/v2/<ACTION>
/_bProxy/api/v2/<domain>/<ACTION>
Header: Proxy-Secret: <apisecret>
```

### Response Format

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

Requests with a missing or wrong API secret are passed through to the normal request handling instead of receiving an API response.

### Proxy Actions

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

### Domain Actions

| Action | Returns |
|--------|---------|
| `GET_TOTAL_REQUESTS` | `TOTAL_REQUESTS` |
| `GET_BYPASSED_REQUESTS` | `BYPASSED_REQUESTS` |
| `GET_TOTAL_REQUESTS_PER_SECOND` | `TOTAL_REQUESTS_REQUESTS_PER_SECOND` |
| `GET_BYPASSED_REQUESTS_PER_SECOND` | `BYPASSED_REQUESTS_REQUESTS_PER_SECOND` |
| `GET_FIREWALL_RULES` | `FIREWALL_RULES` |
| `GET_LOGS` | `LOGS` |

### Reserved Paths

These paths are handled by the proxy itself and never forwarded to the backend:

| Path | Description |
|------|-------------|
| `/_bProxy/stats` | Plain-text domain statistics: stage, total/bypassed requests, requests per second, and the proxy fingerprint. |
| `/_bProxy/fingerprint` | Plain-text details about the current request: IP, request counts, suspicion level, TLS fingerprint, and browser/bot identification. |
| `/_bProxy/verified` | Used by the challenge pages to confirm a solved challenge. Returns `verified`. |
| `/_bProxy/credits` | Attribution and license information. |
| `/_bProxy/<adminsecret>/dashboard` | Web dashboard (v1, read-only monitoring). Served only on the exact admin-secret path. See [Dashboard](#dashboard). |

The `/_bProxy/` path prefix and the challenge cookie names are kept unchanged from the original project for compatibility with existing integrations.

## Dashboard

SonuShield includes a read-only web dashboard, served by the proxy itself. Open it at:

```text
https://<your-domain>/_bProxy/<adminsecret>/dashboard
```

In Cloudflare mode, open the same path through your Cloudflare-fronted domain as usual (the proxy itself listens on port 80 only in that mode). As with any browser request, the first visit passes through the normal cookie challenge automatically.

### Authentication

Two secrets protect the dashboard, reusing the existing API mechanisms — no new authentication scheme is added:

- The page itself is served only on the exact admin-secret path, following the v1 API pattern. A wrong or missing secret never receives the page; the request falls through to normal proxy handling, as with the v1 API. If no admin secret is configured, the dashboard is not served at all.
- After the page loads, enter your `apisecret`. The dashboard sends it only as the `Proxy-Secret` header to the existing API v2 endpoints on the same host. The secret is kept in the browser tab's session storage and is cleared when you click "Forget secret" or close the tab. It is never placed in a URL or written to a log.

### What It Shows

- **Overview:** live total and bypassed requests per second, all-time totals, CPU/RAM usage, the current stage, and the top requesting IPs and unknown fingerprints in the current rate-limit window. Updates every 3 seconds.
- **Domains:** live traffic for the domain in the address bar, or for a domain name you enter.
- **Firewall rules:** the domain's rules in evaluation order, with a plain explanation of each action. Read-only.
- **Stage:** the current stage and what each stage does. Read-only.
- **Logs:** the most recent requests that passed the challenges, newest first.

All data comes from the existing [API](#api) v2 actions and the `/_bProxy/stats` reserved path. The stage shown comes from `/_bProxy/stats` and therefore always reflects the domain in the address bar, even when another domain is being inspected.

### What It Cannot Do

The API exposes no actions for changing the stage, listing domains, reading backends or schemes, showing stage-locked or under-attack state, editing firewall rules, clearing logs, or reloading the configuration — so the dashboard does not offer them either. Those remain terminal-only (see [Commands](#commands)). The dashboard adds no privileged endpoints of its own.

### Themes and Offline Use

The dashboard has two themes sharing one layout: Premium Dark (default) and Official Classic Light, switched from the top bar. The choice is stored in the browser's local storage and is never sent to the server. The page is a single self-contained file embedded in the binary: no build step and no external resources (no CDN, fonts, or icon libraries), so it works fully offline and needs no extra files in Docker.

## Startup Checks

At startup, SonuShield fetches the TLS fingerprint lists and the version information from this repository over HTTPS (`raw.githubusercontent.com`). The version check compares the published stable version against the built-in version (`1.5`); if a newer stable version exists, the proxy prints an update notice and waits 10 seconds before starting. If the version check itself fails (for example, with no outbound network access), startup stops. Fingerprint-list fetch failures do not stop startup, but leave the corresponding lists empty.

## Roadmap

> **Planned, not yet implemented.** This section describes work planned for SonuShield. Nothing listed here exists in the current code yet.
>
> - Dashboard management actions (stage control, firewall rule editing, domain management) from the browser. Dashboard v1 — read-only monitoring — already exists; see [Dashboard](#dashboard).
> - Additional protection features and management improvements.

## License

SonuShield is licensed under the [GNU General Public License v3.0](LICENSE). Originally by [41Baloo (balooProxy)](https://github.com/41Baloo/balooProxy), forked and rebuilt by [Sonu Digital Mindset](https://github.com/sonudigitalmindset-design).
