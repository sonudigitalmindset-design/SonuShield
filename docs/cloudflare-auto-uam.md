# Cloudflare automatic Under Attack Mode

When a domain is proxied through Cloudflare, SonuShield
can raise the zone's Cloudflare security level to
**Under Attack Mode** while an attack is ongoing, and
restore it when the attack ends — through the Cloudflare
API, automatically, with no operator action.

> [← README](../README.md)

```json
{
  "name": "example.com",
  "cloudflareApiToken": "TOKEN",
  "cloudflareZoneId": "ZONE_ID",
  "cloudflareAutoUAM": true,
  "cloudflareRestoreLevel": "medium"
}
```

`cloudflareAutoUAM` defaults to `false`. The token and
zone ID are the same config-file-only credentials the
[Cloudflare rule import](api.md) uses: never accepted via
the API, never logged, never returned, redacted from
backups. `cloudflareRestoreLevel` defaults to `medium`;
accepted values are `off`, `essentially_off`, `low`,
`medium`, `high`, and `under_attack`. Enabling auto-UAM
without a token and zone ID fails config validation loudly
rather than silently never working.

## How it works

The monitor evaluates attack state once a second. When an
attack starts (bypassing or raw), one `PATCH` sets the
zone's `security_level` to `under_attack`. The level stays
raised through the post-attack cooldown, matching the
attack-start/attack-end alert timing, and one more `PATCH`
restores it when the cooldown expires. Duplicate
transitions are coalesced: at most one API call is in
flight per domain, and a calm domain produces no calls at
all.

The current state is visible read-only through
`GET_DOMAIN_FEATURES`: `CLOUDFLARE_AUTO_UAM` reports the
config flag and `CLOUDFLARE_UAM_STATE` the last level this
process applied (`""` when none). Enabling or disabling
the feature is config-file-only, like the credentials.

## Failure behavior

Every failure fails open to SonuShield's own stages,
which work exactly as before with or without Cloudflare:

- A failed API call is retried no more than once a minute
  and logs one generic line (no token, zone ID, or
  response detail).
- If the proxy restarts mid-attack, it forgets the raised
  state; the next attack raises the level again (the API
  call is idempotent). State changed outside this process
  (the Cloudflare dashboard, another tool) is never read
  or overwritten except by the raise/restore transitions
  above.
- Only enable this for zones actually proxied through
  Cloudflare. For a DNS-only zone the API calls succeed
  but change nothing about the traffic reaching your
  origin.

## Verification status

The state machine and the API client are unit-tested
against a mock Cloudflare API (request shape, auth header,
raise/restore transitions, dedup, retry throttling, and
failure handling), and the Batch 3 smoke harness runs the
real proxy binary against a mock API through a full
attack wave. **No live call to the real Cloudflare API has
been made**: no Cloudflare account or token exists on this
VM. Verify with your own zone before relying on it, and
confirm in the Cloudflare dashboard that the level moves
as expected on the first real attack.
