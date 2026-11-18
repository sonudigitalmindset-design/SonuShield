# Multi-server deployments (Redis shared state)

SonuShield is a single process per node. With `proxy.redis`
enabled, nodes share two pieces of state through Redis so a
load balancer can spread visitors across them without each
node enforcing limits on only the traffic it saw itself.

```json
"proxy": {
  "redis": {
    "enabled": true,
    "addr": "127.0.0.1:6379",
    "password": "",
    "db": 0,
    "tls": false,
    "keyPrefix": "sonushield",
    "sharedCache": true,
    "timeoutMs": 100
  }
}
```

All fields except `enabled` and `addr` are optional.
`enabled: false` (the default) leaves the proxy on local
in-memory state with byte-identical behavior. The password
is config-file-only: it is never logged, never returned by
any API action, and redacted from backups. Changing any
Redis setting takes effect on reload — no restart needed.

## What is shared

| State | Shared | Notes |
|---|---|---|
| Per-IP request counts | Yes | 10-second windows, summed over the rate-limit window. Every node enforces `IPRatelimit` on the global total. |
| Per-IP challenge-failure counts | Yes | Same windows; `FailChallengeRatelimit` is enforced globally. |
| Challenge-result cache | Only with `sharedCache: true` | A visitor verified on one node is not re-challenged on another within the hour. Cache keys are SHA-256 hashes — no IP, fingerprint, or user-agent is stored in Redis. |
| Stage / attack state | No | Each node escalates stages from the traffic it sees. See the limits below. |
| Per-domain counters, logs, reports | No | Local to each node. Aggregate logs centrally if you need one view. |
| Challenge OTP secrets | Derived, not shared | OTPs derive from `proxy.secrets` plus the date. Nodes with the same `config.json` compute the same OTPs; nodes with different secrets force re-challenges when a visitor switches nodes while Redis is down. |

## How it works

Counts are buffered in memory (one map write per request —
no network round trip in the hot path) and flushed to Redis
once a second with a pipelined `INCRBY` per (window, IP).
Reads sum the Redis keys for the windows inside the
rate-limit window plus the reading node's unflushed counts,
so a lone node with Redis enabled sees the same totals it
would see locally.

Keys live under `<keyPrefix>:rl:<req|ck>:<window>:<ip>` with
a TTL of the rate-limit window plus 60 seconds, and
`<keyPrefix>:cache:<sha256>` for the shared cache with a
one-hour TTL. Redis persistence is not required: every key
is ephemeral and the proxy rebuilds state from live traffic.
Use a separate database (or prefix) per SonuShield
deployment. `tls: true` enables TLS with full certificate
verification against the system root pool (for managed
Redis); there is no insecure mode.

## Failure behavior (fail-open)

Every Redis failure fails open to local state:

- A node that cannot reach Redis at startup logs one
  generic line and runs on local state. It never fails to
  start because of Redis.
- A Redis outage mid-run degrades each node to its local
  counts. Rate limits keep working per node; only the
  cross-node totals are lost until Redis returns.
- Redis commands are bounded by `timeoutMs` (default 100,
  clamped 10–5000). A slow Redis cannot stall requests.
- Availability warnings are throttled to one generic line
  per minute and never include the address, password, or
  error detail.

Check the live state with the API action
`GET_PROXY_FEATURES`: `REDIS_CONFIGURED` reports the config
flag, `REDIS_ACTIVE` reports a live connection. Neither
field exposes the address or password.

## Limits, stated plainly

- **Attack detection is per node.** Stage escalation uses
  each node's own request counters, so a flood spread
  evenly across many nodes may stay under each node's
  stage thresholds while the total is large. The shared
  rate limits still cap per-IP abuse globally. If you run
  many nodes behind a load balancer, set stage thresholds
  with the per-node share in mind.
- **Verification status.** The store is unit-tested against
  miniredis (a Redis-protocol-compatible in-memory server),
  including two store instances sharing one server, and the
  Batch 3 smoke harness runs the real proxy binary against
  a live miniredis over the real Redis protocol. A real
  Redis server with two live proxy nodes has NOT been
  verified on this VM (the proxy binds fixed ports 80/443,
  so two nodes cannot run side by side here). Verify on
  your own servers before relying on it.
- **Redis is a single point of sharing, not of serving.**
  Losing Redis degrades sharing only; no node stops
  serving. But if Redis holds the only copy of nothing
  important, do not put it on the same single host you are
  trying to make redundant — run it managed, or replicated.
