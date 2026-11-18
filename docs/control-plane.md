# Control Plane

The control plane is the Cloudflare-style management host for SonuShield: the owner, resellers, and tenants sign in to **one separate host** and manage one or more proxy nodes from the dashboard there. Protected domains carry no login page, no `/admin` path, and no management surface at all — visitors see nothing.

> [← README](../README.md)

![Control-plane schematic](assets/control-plane.svg)

The control plane is a separate server mode of the same binary (`sonushield control`). It serves the management UI and API from its own listener, and manages proxy nodes by calling their existing authenticated control API v2. It **never proxies visitor traffic itself**, and it keeps no copy of proxy configuration: the proxy remains the source of truth for every domain, rule, and stage. Everything the control plane offers works end to end against a real node — stage, rules, domain config, logs, reports, reload, and two-person approvals.

The on-domain dashboard (served by the proxy under `/_bProxy/<adminsecret>/dashboard`) still works exactly as before and stays as the fallback. Move to the control plane when you are ready, then disable the on-domain dashboard with `proxy.dashboardMode` — see [Migration](#migration-from-the-on-domain-dashboard).

## Architecture

- **Control host.** Runs `sonushield control` with a config file holding a `controlPlane` section. It serves the login page, the dashboard (the same UI codebase as the on-domain dashboard, in control-plane mode), account management, and the node API proxy. It listens on an operator-configured address, with TLS from operator certificates.
- **Nodes.** Each node is an ordinary SonuShield proxy, reached at its base URL over its control API v2 with its admin API secret. The control plane sends one HTTP `Host` header per node (see [Node Host Header](#node-host-header)), because a node routes requests by host.
- **Accounts.** Stored in a config-managed account file next to the control-plane config. Passwords are stored as bcrypt hashes only — never plaintext — and there are no default credentials.
- **Audit.** Every control-plane action is appended to a JSON-lines audit log: who, what, which node, and the result. Secrets are never written to it.

## Setup

### 1. Write the control-plane config

A control-plane config file holds only the `controlPlane` section (a proxy `config.json` may also carry one, but a dedicated file on a dedicated host is the intended deployment):

```json
{
  "controlPlane": {
    "listen": "127.0.0.1:8443",
    "certificate": "panel-cert.pem",
    "key": "panel-key.pem",
    "accountsFile": "control-accounts.json",
    "auditLog": "control-audit.log",
    "sessionSecret": "a-long-random-value",
    "nodes": [
      {
        "name": "edge-1",
        "url": "https://203.0.113.10:443",
        "apiSecret": "the-node-apisecret",
        "adminSecret": "the-node-adminsecret",
        "controlPlaneSecret": "shared-secret-matching-the-node",
        "serverName": "example.com",
        "caFile": "node-ca.pem"
      }
    ]
  }
}
```

| Field | Description |
|-------|-------------|
| `listen` | Bind address (default `127.0.0.1:8443`). Bind loopback, or put TLS on it — see [Security Notes](#security-notes). |
| `certificate` / `key` | Operator TLS certificate and key for the control listener. Without them the server runs plain HTTP and warns at startup; that is safe only on loopback or behind a TLS-terminating reverse proxy. There is no automatic (Let's Encrypt) certificate for the control listener — use operator certificates or terminate TLS in front of it. |
| `hostname` | Optional public hostname, used in guidance messages only. |
| `accountsFile` | Account file path (default `control-accounts.json`, relative to the config file). Created on first setup; written atomically with mode `0600`. |
| `sessionSecret` | Signs session cookies. Without it, an ephemeral key is generated at startup and sessions do not survive a restart (warned at startup). Set a long random value. |
| `sessionTTLHours` | Session lifetime in hours (default `8`, clamped to `1`–`72`). |
| `auditLog` | Audit log path (default `control-audit.log`, relative to the config file). |
| `branding` | The same operator branding object as the proxy dashboard (display name, logo URL, accent color). Branding never touches the About/credits text or GPL attribution. |
| `sso` | Optional OIDC login, reusing the proxy SSO config shape. See [SSO](#sso). |
| `nodes` | One entry per managed proxy node (at least one is required). |

Node fields:

| Field | Description |
|-------|-------------|
| `name` | Unique node name: lowercase letters, digits, hyphens, underscores. Shown in the dashboard node switcher and the audit log. |
| `url` | The node's base URL. The control plane calls `/_bProxy/api/v2/` under it. |
| `apiSecret` | The node's admin `apisecret`. Sent only as the `X-SonuShield-Secret` header to this node; never logged or returned. |
| `adminSecret` | The node's `adminsecret`, needed only for the live log tail (the tail path carries it). Without it, log tail is unavailable for that node through the control plane. |
| `controlPlaneSecret` | Shared secret matching the node's `proxy.controlPlaneSecret`. Lets the node tell control-plane operators apart for two-person approval. Without it (on either side), approvals through the control plane fail closed — see [Two-Person Approval](#two-person-approval). |
| `serverName` | TLS ServerName (SNI) override, for nodes reached by IP. Also the default `Host` header when `host` is unset. |
| `host` | HTTP `Host` header sent to the node. Must be a domain the node serves. Defaults to `serverName`, else the URL hostname. See [Node Host Header](#node-host-header). |
| `caFile` | PEM bundle of CAs trusted for this node. Empty means the system roots. |
| `insecureSkipVerify` | Disables certificate verification for this node. Test setups only; warned loudly at startup. |

Validate the file with `sonushield validate --config <file>`: it checks the section shape, the TLS certificate, per-node settings, and warns when a node reached by IP has neither `host` nor `serverName` set.

### Node Host Header

A SonuShield node routes every request by its HTTP `Host` header, so a control-plane call must carry a `Host` naming a domain the node serves — otherwise the node answers its generic 404 page to every call, including the domain map that scoping depends on. The effective header is `host` when set, else `serverName`, else the URL hostname. In practice, reaching a node by IP with `serverName` set to one of its domains already satisfies this; for plain-HTTP nodes, set `host` explicitly.

### 2. Create the first owner account

There are no default credentials. Generate a one-time setup token on the control host (this is the one CLI step; everything after it is done in the browser):

```text
sonushield control-setup --config control.json
```

The token is printed exactly once, is valid for one hour, and is single-use. It is refused once an owner account exists. Then open the control host, follow the setup page, and create the owner account (username rules and a minimum 12-character password are enforced). The setup page answers 404 once bootstrap is complete, and the token's state file stores only a hash.

### 3. Start the control plane

```text
sonushield control --config control.json
```

Open `https://<control-host>/` and sign in. The dashboard is the same UI as the on-domain dashboard, with a node switcher in the top bar, the signed-in account shown, and an Accounts view for owners and resellers.

## Accounts and Roles

Three roles, reusing the proxy's tenant model (domains carry a `tenant` in the proxy config; the `default` tenant is the fallback). There is no second tenancy system.

| Role | Sees | May do |
|------|------|--------|
| **Owner** | All nodes, all domains, all accounts | Everything the dashboard offers, including reload, backups, account management, and proxy-wide actions. Maps to the proxy `admin` API role. |
| **Reseller** | Only their tenants' domains, on all nodes | Reads plus operator actions on in-scope domains (stage, rules, logs, reports, approvals); creates tenant accounts only within their own tenant set. Maps to the proxy `operator` API role. |
| **Tenant** | Only their own tenant's domains | Reads only (stage, logs, reports, domain config). Maps to the proxy `viewer` API role. |

Scoping is enforced **server-side** on every call, never just hidden in the UI: domain actions are allowed only when the domain's tenant (from the node's live domain map) is in the caller's tenant set, proxy-wide actions are limited to an allowlist for scoped callers (`GET_DOMAINS`, `GET_TENANTS`, `GET_TENANT_USAGE`, `LIST_APPROVALS`, `APPROVE_ACTION`, `REJECT_ACTION`), and list responses are filtered to scope before they are returned. Unknown domains are denied for scoped callers (so tenants cannot probe for other tenants' domains). Role checks reuse the node's own role table, so a reseller cannot run an admin-only action such as `SET_DOMAIN_CONFIG` even on their own domain — that is the node's rule, mirrored here.

Account rules:

- Usernames are lowercase, 3–32 characters. Passwords are at least 12 characters, stored bcrypt-hashed.
- A reseller account carries a tenant set; a tenant account carries one tenant. An owner has no tenant restriction.
- Owners manage all accounts. Resellers see themselves plus tenant accounts in their scope, and may create or delete tenant accounts only within it. Tenants cannot list or manage accounts.
- Nobody can delete their own account, and the last enabled owner cannot be deleted or disabled.
- Changing your own password requires the current password; changing another account's password is owner-only.
- Sessions carry only the username and expiry: role, tenant scope, and disabled state are read from the account file on every request, so changes apply immediately.

## Login and Sessions

- Login exists **only on the control-plane listener** (`/login`, `/logout`, `/setup`, `/sso/*`). No login path exists on any protected domain, and none is added by enabling the control plane.
- Sessions are HMAC-signed cookies (`__sonushield_cp`, `HttpOnly`, `SameSite=Lax`, `Secure` when the control plane serves TLS). The signing key derives from `sessionSecret`.
- All session-authenticated calls require the `X-SonuShield-CSRF: 1` header. Missing session → `401`; missing CSRF header → `403`.
- Login attempts are rate-limited per client IP: 5 failures in 5 minutes → `429` with `Retry-After`. A successful login resets the counter. Failure messages are generic, and unknown usernames take the same path as wrong passwords.
- Logging out requires a POST with the CSRF header and clears the session cookie.

### SSO

Optional OIDC login coexists with password login, reusing the proxy SSO implementation and the shared JWT verifier (discovery without redirects, exact issuer match, PKCE S256, single-use state, RS256/ES256 ID tokens verified against the provider JWKS, with issuer/audience/expiry/nonce checks). Configure it under `controlPlane.sso` with the same fields as `proxy.sso`; `redirectUrl` must point at the control host's `/sso/callback`.

The identity provider only **authenticates**: the username comes from the ID token (`email`, then `preferred_username`, then `sub`) and must match an existing, enabled control-plane account. The role and tenant scope always come from that account, never from IdP claims — `defaultRole`, `roleClaim`, and `roleMapping` are ignored on the control plane. An SSO login creates the same session cookie as a password login, marked SSO in the audit log. SSO endpoints (`/sso/login`, `/sso/callback`, `/sso/logout`, `/sso/status`) exist only on the control host.

The on-domain proxy SSO paths (`/_bProxy/sso/*`) are superseded once the dashboard moves to the control host: leave them configured only while the on-domain dashboard is still in use, and prefer the control-plane login afterwards.

## Two-Person Approval

When a node has `twoPersonApproval` enabled, sensitive actions requested through the control plane return `ERR_APPROVAL_REQUIRED` with an approval ID, exactly as direct API calls do. A second, distinct operator approves or rejects from the dashboard's Approvals view.

Distinctness needs the shared secret: set the same `controlPlaneSecret` on the node (`proxy.controlPlaneSecret`) and in the node's control-plane entry. The control plane then proves each caller's identity with HMAC-signed headers, so two operators behind one node API secret still count as two people. Without the shared secret on either side, every control-plane caller looks identical to the node and approvals through the control plane fail closed (a different operator's approval is rejected as a self-approval) — direct API approvals with distinct secrets are unaffected. Scoped callers may approve only approvals whose domain is in their scope; proxy-wide approvals are owner-only, and unknown approval IDs are denied, never forwarded.

## Audit Log

Every control-plane action appends one JSON line: timestamp, user, role, auth method (password or SSO), node, action, domain, client IP, scrubbed parameters, success, and error code. Denied calls and unreachable nodes are logged too. Secrets, passwords, tokens, and cookies are never written. The log is append-only from the control plane's side; rotate it with your usual log tooling.

## Dashboard Modes and Migration

### Migration from the on-domain dashboard

1. Deploy the control plane and confirm you can sign in and manage a node through it.
2. On each node, set `proxy.dashboardMode: "control-plane"` and `proxy.controlPlaneUrl` to the control-plane dashboard URL (for example `https://panel.example.com/dashboard`), then reload. On-domain dashboard requests now redirect (302) to the control host; without a usable absolute `http(s)` URL they answer a bare 404 instead. No login form and no branding leak either way.
3. Once every operator uses the control host, set `proxy.dashboardMode: "off"` and reload. The on-domain dashboard and shell-asset paths answer a bare generic 404, as if no dashboard ever lived there.
4. To roll back, set the mode back to `"local"` and reload — the on-domain dashboard returns immediately. Mode changes apply on reload; no restart is needed.

### `proxy.dashboardMode`

| Value | On-domain dashboard path | Default |
|-------|--------------------------|---------|
| `"local"` (or empty) | Served as before, gated by the admin-secret path | Yes |
| `"control-plane"` | 302 redirect to `proxy.controlPlaneUrl`; bare 404 without a usable URL | No |
| `"off"` | Bare generic 404 | No |

Unknown values fail safe to `"off"` with a single startup warning (and a `sonushield validate` warning). The gate applies at both dashboard serve sites and both PWA shell-asset sites, so no request path bypasses it. API v1/v2, metrics, SSO, and the log tail are unaffected — only the dashboard page and its shell move. Proxy SSO paths are left untouched; they are superseded by control-plane login once the mode is not `local`.

## Security Notes

- **TLS is the operator's job on the control host.** Use operator certificates, or terminate TLS in front of the control plane. Plain HTTP is safe only on loopback; the server warns when it listens without TLS on a non-loopback address. There is no automatic certificate issuance for the control listener.
- **The control plane holds node API secrets.** Its config file is as sensitive as the nodes' `config.json` files: restrict filesystem access, and never commit it, the account file (which holds password hashes), or certificates to version control.
- **Sessions depend on `sessionSecret`.** Set a long random value; without one, sessions die on restart.
- **Node connections should be verified.** Prefer HTTPS node URLs with `caFile` for private CAs. `insecureSkipVerify` is for test setups only.
- **Rate limiting is per control-plane process, per IP.** Behind a reverse proxy, the client IP seen is the proxy's unless the deployment forwards it — the control plane reads the direct peer address and does not trust `X-Forwarded-For`.
- **Put the control host behind network allow-listing.** The login limiter slows guessing from one IP (5 failures per 5 minutes) but cannot slow a distributed guessing attack across many IPs, and there is no CAPTCHA or second factor. Restrict who can reach the control host at the network level (firewall rules, VPN, or allow-listed office IPs) so the login page is not exposed to the whole internet.
- **The audit log is local.** Ship or back it up with your usual tooling; the control plane does not replicate it.
- **No visitor traffic.** The control plane answers management routes only; unknown paths get a bare 404, and it never forwards a request to an origin backend.

## Endpoints (Control Host Only)

| Path | Description |
|------|-------------|
| `/` | Redirects to `/dashboard` when signed in, else `/login`. |
| `/login`, `/logout` | Session login (form POST) and logout (POST + CSRF). |
| `/setup` | First-owner bootstrap; 404 once an owner exists. |
| `/dashboard` | The dashboard UI (session-gated). |
| `/manifest.webmanifest`, `/sw.js`, `/icons/*` | PWA shell assets (session-gated). |
| `/sso/login`, `/sso/callback`, `/sso/logout`, `/sso/status` | OIDC login (when configured). |
| `/cp/whoami`, `/cp/nodes` | Signed-in account and node names (session + CSRF). |
| `/cp/accounts`, `/cp/accounts/password` | Account list/create/delete and password change (session + CSRF, role-checked). |
| `/cp/api/<node>/_bProxy/api/v2/[...]` | Node API proxy (session + CSRF, role- and scope-checked, audit-logged). |
| `/cp/log-tail?node=<name>` | Live log-tail SSE proxy, filtered by domain for scoped callers. |

Response envelopes follow the API v2 shape (`{"success": bool, "results": {...}}`) with UPPERCASE result keys, matching the node API.

## What Needs Operator Configuration

- A control-plane config file with at least one node, node API secret(s), and a session secret.
- Operator TLS certificates for the control listener (or a TLS-terminating reverse proxy in front of it).
- The shared `controlPlaneSecret` on nodes and in node entries, if two-person approval through the control plane is wanted.
- An OIDC provider (issuer, client ID/secret, redirect URL) if SSO login is wanted; accounts must still exist in the account file.
- A CA file per node when nodes use private-CA certificates.

Nothing else is required: accounts, sessions, audit, and scoping all work with the config file alone, and every feature stays inert until the control plane is actually run.
