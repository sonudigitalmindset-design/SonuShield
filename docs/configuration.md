# Configuration

`config.json` has two top-level fields: `proxy` (general settings) and `domains` (one entry per protected domain). Firewall rules are configured per domain, under each domain's `firewallRules` — see [Firewall Rules](firewall-rules.md).

## Example Configuration

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

A fuller multi-domain example is available in [`examples/config.json`](../examples/config.json). Remember to replace every `CHANGE_ME` secret before starting — SonuShield refuses to start if any secret still contains `CHANGE_ME`.

## Proxy Settings

| Field | Type | Description |
|-------|------|-------------|
| `cloudflare` | Bool | Set to `true` to run behind Cloudflare. See [Cloudflare Mode](how-it-works.md#cloudflare-mode). |
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

## Domain Settings

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | The domain name, for example `example.com`. Requests are matched by the `Host` header. |
| `scheme` | String | Scheme used to talk to your backend: `http` or `https`. `http` is generally faster and less CPU-intensive. Note: `https` backends are contacted with TLS certificate verification disabled. |
| `backend` | String | Your backend's IP or hostname. You can specify a port, for example `1.1.1.1:8888`. |
| `certificate` | String | Path to the domain's TLS certificate, for example `assets/server/server.crt`. Not loaded in Cloudflare mode. |
| `key` | String | Path to the domain's TLS private key, for example `assets/server/server.key`. Not loaded in Cloudflare mode. |
| `webhook` | Object | Discord alert settings. See [Webhook](#webhook). |
| `firewallRules` | Array | Custom firewall rules. See [Firewall Rules](firewall-rules.md). |
| `bypassStage1` | Int | Bypassing requests per second that activate Stage 2. |
| `bypassStage2` | Int | Bypassing requests per second that activate Stage 3. |
| `stage2Difficulty` | Int | Proof-of-work difficulty for Stage 2 (default `5` when `0`). |
| `disableBypassStage3` | Int | Bypassing requests per second low enough to disable Stage 3. |
| `disableRawStage3` | Int | Total requests per second low enough to disable Stage 3 (bypassing requests must also be low enough). |
| `disableBypassStage2` | Int | Bypassing requests per second low enough to disable Stage 2. |
| `disableRawStage2` | Int | Total requests per second low enough to disable Stage 2 (bypassing requests must also be low enough). |

## Webhook

Each domain can send Discord DDoS alerts through a webhook. Create a webhook in your Discord server (Server Settings → Integrations → Webhooks) and see [Discord's introduction to webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) for details. Leave `url` empty to disable alerts for a domain.

| Field | Type | Description |
|-------|------|-------------|
| `url` | String | The Discord webhook URL alerts are sent to. |
| `name` | String | The name shown above the alert in Discord. |
| `avatar` | String | URL of the profile picture shown with the alert in Discord. |
| `attack_start_msg` | String | Message sent when your domain first comes under attack. |
| `attack_stop_msg` | String | Message sent when the attack has ended. |

Both messages support placeholders: `{{domain.name}}`, `{{attack.start}}`, `{{attack.end}}`, `{{proxy.cpu}}`, and `{{proxy.ram}}`.

Alerts are only sent when the stage is **not** locked, when the first stage starts being bypassed, and when the attack ends. See [DDoS Alerts](features.md#ddos-alerts).

## Stage Thresholds

The automatic stage system watches two numbers per domain: total requests per second and bypassing requests per second (requests that passed the current challenge). When bypassing requests exceed `bypassStage1`, Stage 2 activates; when they exceed `bypassStage2`, Stage 3 activates. Stages step back down when both the bypassing and total request rates fall below the matching `disable*` thresholds. Locking a stage with the [`stage`](how-it-works.md#commands) command disables automatic switching until you unlock it with `stage 0`.

## Applying Changes

After editing `config.json` by hand, run the `reload` terminal command (or restart the proxy) to apply the changes. The `add` terminal command can add a domain interactively and reloads the configuration for you.

## Next Steps

- [Firewall Rules](firewall-rules.md) — custom rules per domain.
- [API](api.md) — read stats, rules, and logs over HTTP.
- [Troubleshooting](troubleshooting.md) — if the proxy refuses to start.
