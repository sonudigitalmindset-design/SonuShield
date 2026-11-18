# Platform, Tenancy & Billing

Multi-tenancy, the control plane, accounts, branding, and billing hooks.

Every diagram on this page is an animated schematic: it shows the mechanism in motion, not a screenshot. Diagrams use SMIL animation only, so they animate on GitHub.

<a id="control-plane"></a>

## Control Plane Service

![Control Plane Service schematic](../assets/features/control-plane.svg)

### How it works

The control plane is a separate service (`sonushield control`) that manages proxy nodes through the existing API v2, using a per-node API secret stored in its own config. It never proxies visitor traffic and never sees a visitor request: it is purely a management host, so it can live on its own official-style domain while protected domains carry no `/admin`, `/user`, or `/login` paths at all. Node definitions (URL, host header, secret) live in the control-plane config; the dashboard's node switcher talks to whichever node is selected. The control plane has no auto-SSL: the operator provides certificates or terminates TLS in front of it.

### Configuration

Top-level `controlPlane` section — `listen` (default `127.0.0.1:8443`), `certificate`/`key` (both empty means plain HTTP, safe only on loopback or behind a TLS-terminating reverse proxy), `hostname`, `accountsFile` (default `control-accounts.json`), `sessionSecret`, `sessionTTLHours` (default `8`, clamped 1–72), `auditLog`, `branding`, `sso`, and `nodes` (array of `{"name", "url", "apiSecret", "adminSecret?", "controlPlaneSecret?", "serverName?", "host?"}`). Run with `sonushield control --config <file>`. Node secrets are config-file-only.

### Limits

- No auto-SSL for the control listener: operator certificates or reverse-proxy termination are required for HTTPS.
- Multi-host node routing was tested with the per-node `host` field; untested topologies may need the host header set explicitly.

See also: [Control Plane](../control-plane.md)

---

<a id="accounts-roles"></a>

## Accounts & Roles (Control Plane)

![Accounts & Roles (Control Plane) schematic](../assets/features/accounts-roles.svg)

### How it works

Control-plane accounts live in an account file with bcrypt-hashed passwords, created through a setup-token bootstrap (`sonushield control-setup`, single-use token). Sign-in issues a signed session cookie with CSRF protection and login rate limiting (5 failed attempts in 5 minutes → 429 with `Retry-After`). Roles are owner, reseller, and tenant, enforced server-side with tenant scoping: a tenant sees only their own domains and data. Last-owner protection prevents removing the final owner account. Every account action is audit-logged without secrets. The account file — not any identity provider — decides roles.

### Configuration

Accounts file path in the `controlPlane` section. Bootstrap: `sonushield control-setup`. Roles: `owner`, `reseller`, `tenant`.

### Limits

- Account storage is a local file, not a directory service: there is no LDAP/AD sync.
- Login limiting is per-IP only (5 per 5 minutes plus bcrypt cost) — adequate for a management host, not a substitute for network controls.

See also: [Control Plane](../control-plane.md)

---

<a id="sso-control-host"></a>

## SSO on the Control Host

![SSO on the Control Host schematic](../assets/features/sso-control-host.svg)

### How it works

The control host supports OIDC single sign-on: the identity provider authenticates the user, and the account file decides the role. An IdP claim saying "admin" yields the account file's role for that user — verified: admin-flavored claims still yield a tenant role when the account file says tenant — and a user unknown to the account file is denied outright. SSO is authentication only; authorization never leaves the account file. Verified against a mock IdP only; a real IdP was never connected.

### Configuration

`controlPlane.sso` object (same shape as proxy SSO) — `enabled`, `issuer`, `clientId`, `clientSecret` (config-file-only), `redirectUrl`, `scopes`, `defaultRole`, `roleClaim`, `roleMapping`. Endpoints live on the control-plane listener only.

### Limits

- Real-IdP SSO is unverified: only a mock IdP was tested end to end.
- SSO users must still exist in the account file — SSO alone never creates an account.

See also: [Control Plane](../control-plane.md)

---

<a id="node-switcher"></a>

## Node Switcher

![Node Switcher schematic](../assets/features/node-switcher.svg)

### How it works

The control-plane dashboard serves one shared UI codebase with a node switcher: pick a node and every panel — domains, rules, logs, reports — talks to that node's API v2 with its stored secret. Switching nodes never requires signing in again; the session belongs to the control plane, and node credentials never reach the browser. The log-tail panel proxies per node with domain filtering (`/cp/log-tail`). Node health is shown in the switcher so a down node is visible before it is selected.

### Configuration

Nodes are defined in the `controlPlane` config section. No per-node dashboard configuration exists.

### Limits

- The switcher shows nodes the control plane knows: a node added to the fleet needs a control-plane config entry first.
- Node responses are proxied, not cached: a slow node makes its panels slow.

See also: [Control Plane](../control-plane.md)

---

<a id="dashboard-mode"></a>

## Dashboard Mode

![Dashboard Mode schematic](../assets/features/dashboard-mode.svg)

### How it works

`proxy.dashboardMode` decides where the dashboard lives: `local` (the default — the dashboard is served from each proxy node on the admin-secret path, unchanged from before the platform model), `control-plane` (the node serves no dashboard; management happens on the control host), or `off` (no dashboard anywhere on this node). The mode is reload-applied: changing it takes effect on the next config reload without a restart. In all modes, `/_bProxy/health` and `/_bProxy/status` stay available, and no `/admin`, `/user`, or `/login` path ever exists on a protected domain.

### Configuration

`proxy.dashboardMode`: `local` (default) / `control-plane` / `off`. Reload-applied.

### Limits

- `off` removes the dashboard but not the API: management is still possible through API v2 with a valid secret.
- Mode changes apply on reload, not instantly: a running dashboard session survives until the reload.

See also: [Control Plane](../control-plane.md)

---

<a id="multi-tenancy"></a>

## Multi-Tenancy

![Multi-Tenancy schematic](../assets/features/multi-tenancy.svg)

### How it works

One proxy serves many tenants: domains belong to tenants, and tenant-scoped API secrets (`tenant:<name>:<role>`) see only their tenant's domains, rules, logs, and reports. Scoping is enforced server-side on every action — a tenant cannot enumerate another tenant's domains, and tenant-scoped approvers cannot approve proxy-wide actions. The engine itself is shared: stages, rate limits, and caches operate per domain as before, and tenancy adds visibility boundaries, not performance isolation. Tenant assignment is config: domains carry a tenant name, and secrets carry the tenant scope.

### Configuration

Per domain: `tenant` (name). API secrets: `tenant:<name>:<role>` in `proxy.apiRoles`. Tenant list via `GET_TENANTS`.

### Limits

- Visibility scoping, not resource isolation: a tenant's attack still consumes shared proxy capacity.
- Tenant names are config strings, not provisioned accounts — there is no self-service tenant signup.

See also: [Configuration](../configuration.md#multi-tenancy-and-metering)

---

<a id="metering"></a>

## Metering

![Metering schematic](../assets/features/metering.svg)

### How it works

Metering counts requests and bytes per tenant per window, from the same counters that feed the dashboard — so the numbers a tenant sees and the numbers billing uses are the same numbers. Usage is exposed via `GET_TENANT_USAGE` and feeds the Stripe billing hooks. Metering is counting only: it enforces nothing, and overage policy (throttle, bill, or ignore) is the operator's decision, implemented through the billing hooks or the API. Counters reset per window and are per-node unless aggregated.

### Configuration

API action `GET_TENANT_USAGE` (scoped by tenant). No config keys; metering follows the tenant assignment on domains.

### Limits

- Counters are per-node: aggregate across nodes for fleet-wide tenant usage.
- Metering counts what the proxy saw — cached responses count as served, and blocked requests count as blocked. Overage semantics are yours to define.

See also: [Configuration](../configuration.md#multi-tenancy-and-metering)

---

<a id="roles-audit"></a>

## Roles & Audit Log

![Roles & Audit Log schematic](../assets/features/roles-audit.svg)

### How it works

API v2 enforces roles on all 84+ actions: `admin` (everything), `operator` (manage, no secret/account actions), `viewer` (read-only), plus tenant-scoped variants. The current API secret stays admin. Every action — allowed or denied — writes an audit entry: who (secret hash, never the secret), what, when, and the outcome. The audit log is append-only through the API: there is no action that edits or deletes entries. Roles are assigned in `proxy.apiRoles`, mapping secrets to roles; a secret with no entry is denied.

### Configuration

`proxy.apiRoles`: map of secret → role (`admin`, `operator`, `viewer`, `tenant:<name>:<role>`). Audit via `GET_AUDIT_LOG` (admin role).

### Limits

- Roles gate API actions only: the dashboard's admin-secret path is all-or-nothing by design.
- Audit entries record secret hashes, not identities — correlate hashes to holders outside the proxy.

See also: [API v2](../api.md)

---

<a id="sso-oidc"></a>

## SSO / OIDC Dashboard Login

![SSO / OIDC Dashboard Login schematic](../assets/features/sso-oidc.svg)

### How it works

Dashboard login can delegate to an OIDC identity provider: the browser is redirected to the IdP, returns with an authorization code, and the proxy exchanges it and issues its own session cookie. The OIDC endpoints (`/_bProxy/sso/login`, `/callback`, `/logout`, `/status`) are temporary and documented as such — they exist on the proxy listener for local-mode dashboards, while the control-plane host has its own SSO (see SSO on the Control Host). The full flow was verified end-to-end against a mock IdP, including the session handoff; a real IdP was never connected.

### Configuration

`proxy.sso` object — `enabled`, `issuer`, `clientId`, `clientSecret` (config-file-only), `redirectUrl`, `scopes`, `defaultRole`, `roleClaim`, `roleMapping`. Session cookies are signed; CSRF protection applies.

### Limits

- Verified against a mock IdP only; real-IdP behavior (claim shapes, token quirks) is unverified.
- SSO authenticates; dashboard authorization still follows the admin secret / role model.

See also: [Dashboard](../dashboard.md)

---

<a id="white-label"></a>

## White-Label Branding

![White-Label Branding schematic](../assets/features/white-label.svg)

### How it works

Operators can brand the dashboard and the built-in challenge pages with their own display name, logo URL, and accent color (`branding` per domain). Branding is display-only: it never touches the `/_bProxy/credits` endpoint, which stays byte-identical (the GPL hard limit), never removes attribution from code or docs, and never affects the LICENSE. Logo URLs are validated, accent colors are constrained to safe values, and branding never injects scripts. A domain without branding shows the default SonuShield presentation.

### Configuration

Per domain: `branding` object — `displayName`, `logoURL`, `accentColor`. See [Branding](../configuration.md#white-label-branding).

### Limits

- Branding changes display text and colors only — it cannot rename the product, remove credits, or hide the license.
- Logo URLs must be reachable by visitors' browsers; a broken logo URL shows a broken image, not a fallback.

See also: [Configuration](../configuration.md#white-label-branding)

---

<a id="stripe-hooks"></a>

## Stripe Billing Hooks

![Stripe Billing Hooks schematic](../assets/features/stripe-hooks.svg)

### How it works

Metering deltas can be reported to Stripe as usage records, so tenant billing follows measured consumption. The integration is hooks-shaped: the proxy computes exact usage deltas per tenant per window and delivers them to the configured Stripe endpoint with the operator's keys. Delivery was verified against a mock Stripe endpoint with exact-delta assertions — no live Stripe account was ever used, and no charge was ever created. Webhook verification for Stripe callbacks follows the same HMAC discipline as event webhooks.

### Configuration

`proxy.stripe` object — `secretKey` (config-file-only), `apiBase` (override for mocks/compatible APIs), `reportIntervalSeconds`, `customers` (map of tenant → `{"customerId", "requestsItemId", "bandwidthItemId"}`). No live account is required to configure it.

### Limits

- Mock-verified only: a live Stripe account, webhook endpoint, and price configuration are the operator's steps.
- The proxy reports usage; it never creates charges, subscriptions, or invoices on its own.

See also: [Configuration](../configuration.md#stripe-billing)

---

<a id="public-api-sdks"></a>

## Public API & SDKs

![Public API & SDKs schematic](../assets/features/public-api-sdks.svg)

### How it works

The public API exposes the management actions as a documented REST surface with per-key authentication (`proxy.publicApiKeys`), separate from the internal API secrets. Two SDKs wrap it: a Go SDK (`sdk/go/`) and a Python SDK (`sdk/python/`), both exercised against a live proxy in the Batch 6 harness — every SDK method maps to a real API action with the same role checks and error codes. Public API keys are scoped like API secrets and never bypass roles. The public API answers JSON even at Stage 3, thanks to the challenge-flow exemption.

### Configuration

`proxy.publicApiKeys`: array of `{"key", "tenant", "name", "requestsPerMinute"}`. SDKs: import from `sdk/go` or install `sdk/python` (see each SDK's README).

### Limits

- SDK coverage follows the documented action list; brand-new actions may lag the SDKs by a release.
- Public API keys are bearer credentials with the same care requirements as API secrets.

See also: [API v2](../api.md)

---

<a id="webhooks-siem"></a>

## Webhooks & SIEM Export

![Webhooks & SIEM Export schematic](../assets/features/webhooks-siem.svg)

### How it works

Security events (blocks, stage changes, canary trips, approvals) can be delivered to external systems as webhooks — HMAC-signed JSON over HTTP POST — or exported to SIEMs in CEF and syslog formats. HMAC verification was confirmed for all three formats. Delivery is HTTP POST only (no other methods, no other transports), with bounded retries; a failing endpoint logs and continues, never blocking the proxy. Webhook secrets are config-file-only, and payloads carry event data only — never secrets or full request bodies.

### Configuration

`proxy.eventWebhooks`: array of `{"url", "secret", "events", "format", "timeoutSeconds", "maxRetries"}`. SIEM format per endpoint: `json`, `cef`, or `syslog`. (The separate per-domain `webhook` setting is the legacy attack-alert webhook — URL, name, avatar, attack messages — not the HMAC event webhook.)

### Limits

- HTTP POST only: no GET callbacks, no message queues, no streaming protocols.
- Delivery is best-effort with bounded retries — a down SIEM loses events. Pair with JSON logs for a durable record.

See also: [Configuration](../configuration.md#event-webhooks-and-siem-export)

---

---

[← All features](../features.md)
