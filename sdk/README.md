# SonuShield SDKs — public API v1

Minimal clients for the tenant/reseller **public API**
(`/_bProxy/public/v1/*`), the read-only API that is distinct
from the internal control API (`/_bProxy/api/v2/*`). Both SDKs
are dependency-free.

| SDK | Location | Notes |
| --- | --- | --- |
| Go | `sdk/go/sonushield/` | Import path `sonushield/sdk/go/sonushield` |
| Python | `sdk/python/sonushield/` | Standard library only, Python 3.8+ |

## Endpoints

| Method | Path | Returns |
| --- | --- | --- |
| GET | `/v1/ping` | The key's tenant and name (auth check) |
| GET | `/v1/usage` | Tenant aggregate: requests, blocked, bytes |
| GET | `/v1/usage?domain=<name>` | Usage for one of the tenant's domains |
| GET | `/v1/domains` | The tenant's domains with stage and counters |

Auth is a per-tenant API key sent as `Authorization: Bearer
<key>` (the `X-API-Key` header is also accepted). Keys are
configured in `config.json` under `proxy.publicApiKeys` —
see `docs/configuration.md`. Each key reads only its own
tenant; a `domain` outside the tenant 404s exactly like a
nonexistent one.

Responses use the envelope `{"ok": true, "data": ...}` on
success and `{"ok": false, "error": {"code", "message"}}` on
failure, with matching HTTP status codes (401, 404, 405,
429). Per-key rate limits return `X-RateLimit-*` headers and
`Retry-After` on 429; both SDKs retry 429s honoring
`Retry-After` (capped at 30 seconds per wait).

## Go

```go
client := sonushield.NewClient("https://example.com", "your-api-key")
usage, err := client.Usage(context.Background())
```

Run the example:

```sh
SONUSHIELD_URL=https://example.com SONUSHIELD_API_KEY=your-key \
  go run ./sdk/go/example
```

## Python

```python
from sonushield import Client

client = Client("https://example.com", "your-api-key")
print(client.usage())
```

Run the example (from `sdk/python/`):

```sh
SONUSHIELD_URL=https://example.com SONUSHIELD_API_KEY=your-key \
  python3 example.py
```
