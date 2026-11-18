# SonuShield Hosting-Panel Integration

Provision SonuShield domains from a hosting panel (cPanel/WHM, Plesk, or
any scripted environment) through the control API v2, using the included
Python client (`sonushield_panel.py`, standard library only).

## What it does

- `list-domains` — list the domains the proxy serves.
- `templates` — list the domain templates (standard, static, API, …).
- `add-domain` — create one domain from a template, with backend, scheme,
  and TLS certificate/key paths. The change is persisted to the proxy's
  `config.json` and applied without a restart.
- `import-domains` — create many domains at once from a JSON or CSV file.
  The import is all-or-nothing: one bad entry rejects the whole file.
- `get-config` — show a domain's safe (non-secret) settings.

Secrets (challenge keys, alert tokens, webhook URLs) cannot be set
through the API by design; they stay config-file-only. TLS certificate
provisioning is the panel's job — the client only tells the proxy where
the files live.

## Setup

1. Copy `sonushield_panel.py` to the panel server (it needs network
   access to the proxy's API and Python 3.8+; no packages to install).
2. Create a role secret for the panel in the proxy's `config.json`
   (`proxy.apiRoles`, role `operator` is enough for provisioning; `admin`
   is not needed). Never use the main `apisecret` for a panel integration.
3. Export the secret where the panel hooks run it, e.g. in the hook
   environment: `SONUSHIELD_API_SECRET=<role secret>`. Never put the
   secret on a command line in a shared environment.
4. Test connectivity:

```sh
SONUSHIELD_API_SECRET='...' python3 sonushield_panel.py \
  --api-url https://proxy.example.com list-domains
```

## Usage

```sh
# One domain, from the "standard" template:
SONUSHIELD_API_SECRET='...' python3 sonushield_panel.py \
  --api-url https://proxy.example.com add-domain \
  --name example.com --backend 127.0.0.1:8080 --scheme http \
  --template standard \
  --certificate /etc/sonushield/certs/example.com.crt \
  --key /etc/sonushield/certs/example.com.key

# Many domains from a JSON file (same entry shape as add-domain):
SONUSHIELD_API_SECRET='...' python3 sonushield_panel.py \
  --api-url https://proxy.example.com import-domains --file domains.json
```

The JSON import file is an array of entries:

```json
[
  {"name": "example.com", "backend": "127.0.0.1:8080", "scheme": "http", "template": "standard"},
  {"name": "api.example.com", "backend": "127.0.0.1:8081", "scheme": "http", "template": "api"}
]
```

## Panel hooks (examples)

The `examples/` directory holds hook sketches:

- `cpanel-postwwwacct.sh` — a cPanel/WHM `postwwwacct` hook sketch that
  provisions the new account's primary domain after account creation. It
  reads the account's domain and document-root backend from the hook's
  environment/arguments; adapt the backend mapping to the server's layout.
- `plesk-event-handler.sh` — a Plesk event-handler sketch for the
  "domain created" event, calling the same client.

Both are sketches, not drop-in hooks: panel hook argument formats and
event payloads vary by panel version, and the backend address mapping
depends on how the panel lays out sites. Adapt them to the panel in use
and test on a staging account first.

## Verification limits (honest scope)

The client itself is plain HTTPS against the documented API v2 surface
and follows the same request shape the dashboard uses, but it has **not**
been run against a live cPanel or Plesk installation: no panel
environment exists where it was built. The hook sketches are untested
against real panel events. Verify on a staging panel account before
production use: create an account, confirm the domain appears in
`list-domains` and serves through the proxy, then remove it from the
proxy config before relying on the flow.
