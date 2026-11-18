# Operations & Management

Running, configuring, and managing the proxy day to day.

Every diagram on this page is an animated schematic: it shows the mechanism in motion, not a screenshot. Diagrams use SMIL animation only, so they animate on GitHub.

<a id="dashboard-control-panel"></a>

## Dashboard & Control Panel

![Dashboard & Control Panel schematic](../assets/features/dashboard-control-panel.svg)

### How it works

The dashboard is a single-page control panel served at `/_bProxy/<adminsecret>/dashboard`, and it is the whole management surface: stage buttons, the domain list and per-domain configuration forms, the rule editor, log viewing and clearing, feed refresh, attack-report viewing and download, and reload with confirmation. Writes persist atomically to `config.json` (temp file + one `.bak` + rename, unknown keys preserved) and reload through `SafeReload`, which validates first and leaves the running config untouched on failure. Two secrets gate access (admin + API), polling never clobbers an open edit, and the UI ships as an embedded single page with system fonts and inline SVG only — zero external assets. Themes: Premium Dark (default) and Official Classic Light, persisted in localStorage.

### Configuration

`proxy.dashboardMode`: `local` (default), `control-plane`, or `off`. Dashboard route requires the admin secret; API actions require the API secret with a role. See [Dashboard Mode](platform.md#dashboard-mode).

### Limits

- The dashboard is only as secure as its secrets: anyone with the admin secret manages the proxy. Rotate secrets if one leaks.
- Stage locks set from the dashboard are runtime-only — a reload or restart resets them.

See also: [Dashboard](../dashboard.md) · [Control Plane](../control-plane.md)

---

<a id="dashboard-i18n-pwa"></a>

## Dashboard Hindi / English & PWA

![Dashboard Hindi / English & PWA schematic](../assets/features/dashboard-i18n-pwa.svg)

### How it works

The dashboard is fully bilingual: 456 translation keys in English and 456 in Hindi, switchable in the UI, covering every label, button, and message. It is also installable as a progressive web app: a shell-only service worker caches the app shell so the panel loads instantly on repeat visits, while all data still comes live from the API — the service worker never caches API responses, so the dashboard can never show stale management state. Language choice persists in localStorage alongside the theme.

### Configuration

No configuration keys: language and PWA behavior are built into the dashboard page.

### Limits

- Translation covers the dashboard UI only — challenge pages have their own Hindi variants, and API responses stay in English.
- The service worker caches the shell only; offline use shows the shell with no data.

See also: [Dashboard](../dashboard.md)

---

<a id="config-rollback"></a>

## Config Rollback

![Config Rollback schematic](../assets/features/config-rollback.svg)

### How it works

Every persisted config write keeps a rotating backup chain (`.bak.1` through `.bak.N`, default 5). `LIST_CONFIG_BACKUPS` shows the chain with timestamps and sizes; `RESTORE_CONFIG_BACKUP` restores one, again through the atomic write path and `SafeReload`, so a bad restore cannot take the proxy down either. Backups are created by the same temp + rename mechanism as normal writes, so a crash mid-write never leaves a half-written config. Rollback covers `config.json` only — runtime-only state (stage locks, rotation state) is not backed up.

### Configuration

`proxy.configBackups` (default `5`, clamped to 1–20). API actions `LIST_CONFIG_BACKUPS` / `RESTORE_CONFIG_BACKUP` (operator role; gated by two-person approval when enabled).

### Limits

- Backups hold secrets: `config.json` contains API secrets and provider keys. Protect the backup files like the config itself.
- Rollback restores config, not runtime state: stage locks and in-memory counters are unaffected.

See also: [API v2](../api.md)

---

<a id="gitops"></a>

## GitOps

![GitOps schematic](../assets/features/gitops.svg)

### How it works

GitOps mode lets `config.json` live in a git repository and be pulled on a schedule: the proxy reads the file, validates it, and applies it through the same `SafeReload` path as a manual reload — invalid files are refused and the running config is untouched. The proxy never shells out to git: pulling is the operator's job (a cron job, a sidecar, a CI deploy), and the proxy only ever reads the file. This keeps the security boundary clean — a compromised repository can at worst deliver a config the validator rejects.

### Configuration

`proxy.gitops` object — `enabled`, `directory` (the watched directory holding `config.json`), `intervalSeconds` (poll interval). The pull mechanism is external; the proxy only watches the file.

### Limits

- GitOps applies whole-config replacement only; there is no merge with dashboard edits. Pick one source of truth per deployment.
- A valid-but-wrong config (a bad backend, a typo'd domain) applies cleanly — validation checks shape, not intent.

See also: [Configuration](../configuration.md#gitops)

---

<a id="setup-wizard"></a>

## Setup Wizard

![Setup Wizard schematic](../assets/features/setup-wizard.svg)

### How it works

On first run with no `config.json`, a localhost-only setup wizard asks for the essentials — a domain, its backend, and the admin/API secrets — and writes a valid starting config. The wizard binds to localhost only, so it is never reachable from the network, and it never overwrites an existing config: if `config.json` already exists, the wizard does not run. Generated secrets are shown once and must be recorded by the operator; they are never written anywhere else.

### Configuration

No configuration keys: the wizard runs automatically when no config exists and the process is started interactively on localhost.

### Limits

- The wizard writes a minimal config: TLS, challenges, and hardening are the operator's next steps, not the wizard's.
- Secrets shown once cannot be recovered from the wizard — record them before closing it.

See also: [Installation](../installation.md)

---

<a id="domain-templates"></a>

## Domain Templates & Bulk Import

![Domain Templates & Bulk Import schematic](../assets/features/domain-templates.svg)

### How it works

Five domain templates (blog, shop, API, static site, web app) pre-fill sensible per-domain settings — stage thresholds, WAF mode, cache, and headers — so a new domain starts from a known-good baseline instead of a blank form. Bulk import (`IMPORT_DOMAINS`) loads many domains at once from JSON, validating every one before any is stored: all-or-nothing, so a single bad domain rejects the whole import. Templates are starting points, not policies: every setting remains editable afterwards.

### Configuration

API actions `GET_DOMAIN_TEMPLATES` / `IMPORT_DOMAINS` (operator role). Templates are built in; no config keys.

### Limits

- Templates encode opinions, not guarantees: a shop template's thresholds may be wrong for a flash sale. Review after applying.
- Bulk import validates shape and fields only — backend reachability is not probed unless the validator is run with `--probe-backends`.

See also: [API v2](../api.md)

---

<a id="cli-helm-installer"></a>

## CLI, Helm Chart & Installer

![CLI, Helm Chart & Installer schematic](../assets/features/cli-helm-installer.svg)

### How it works

The `sonushield` CLI wraps the proxy binary with subcommands: `validate` (config validation, with `--probe-backends`), `control` (run the control-plane service), `control-setup` (bootstrap the first control-plane account with a setup token), and the proxy itself. A Helm chart deploys it on Kubernetes, and an installer script sets up a systemd service on a Linux host. All three were fixture-tested against the repository layout — but no published release artifact or container image exists yet, so none has been exercised against a real release.

### Configuration

CLI flags per subcommand (`sonushield --help`). Helm values in `deploy/helm/sonushield/values.yaml`. Installer options via environment variables (see the installer script).

### Limits

- No published release or image exists yet: the installer and chart point at artifacts that must be built or published first.
- The CLI validates config shape; `--probe-backends` adds reachability checks but cannot verify TLS or challenge behavior.

See also: [Installation](../installation.md)

---

<a id="config-validator"></a>

## Config Validator & CI

![Config Validator & CI schematic](../assets/features/config-validator.svg)

### How it works

`sonushield validate` checks a `config.json` without starting the proxy: JSON shape, required fields, rule compilation, schedule parsing, and secret hygiene — secrets are never printed, and exit codes distinguish valid (0) from invalid (non-zero). `--probe-backends` additionally checks that each backend is reachable. The same checks run in CI on every push (`.github/workflows/ci.yml`: build + vet + validator + tests), alongside CodeQL, so a broken config or a failing test never reaches `main` unnoticed.

### Configuration

CLI: `sonushield validate [--probe-backends] [--config path]`. CI needs no configuration; it runs on the repository's workflows.

### Limits

- Validation checks shape and reachability, not correctness: a valid config can still point at the wrong backend.
- The validator never prints secret values — if it reports a secret problem, it names the key, not the value.

See also: [Installation](../installation.md)

---

<a id="backup-migrate"></a>

## Backup & Migrate

![Backup & Migrate schematic](../assets/features/backup-migrate.svg)

### How it works

Backup and migration move configuration between proxies as envelopes: a redacted envelope (secrets stripped, safe to store or share) or an encrypted envelope (secrets included, protected by a passphrase). Restore validates the envelope before applying anything — a corrupt or tampered envelope is refused — and applies through the same atomic write + `SafeReload` path as any other config change. Migration is whole-config: the destination's config is replaced, not merged.

### Configuration

API actions `EXPORT_BACKUP` / `RESTORE_BACKUP` (admin role). `EXPORT_BACKUP` takes `include_secrets` and `passphrase` parameters; encrypted envelopes need the passphrase supplied at export and import.

### Limits

- A redacted envelope cannot restore a working proxy on its own — secrets must be re-entered afterwards.
- An encrypted envelope is only as safe as its passphrase. Losing the passphrase loses the backup.

See also: [API v2](../api.md)

---

<a id="wordpress-plugins"></a>

## WordPress & Hosting-Panel Plugins

![WordPress & Hosting-Panel Plugins schematic](../assets/features/wordpress-plugins.svg)

### How it works

A WordPress plugin (`plugins/wordpress/`, 320 lines of PHP) lets a site owner purge the edge cache, check domain status, and manage basic rules from WP-admin without touching the dashboard, authenticating with an API key. A hosting-panel client with cPanel/Plesk hook sketches (`plugins/panels/`) shows how the same API calls wire into panel workflows. Both are integration starting points: the plugin was never tested in a real WordPress install (no PHP on the build VM), and the panel hooks are untested sketches.

### Configuration

Plugin settings: proxy URL + API key (stored in WordPress options). Panel hooks: see the examples under `plugins/panels/examples/`.

### Limits

- Untested in real WordPress / cPanel / Plesk environments — treat as a starting point, not a finished integration.
- The plugin's API key needs only the roles its actions require; do not give it an admin secret.

See also: [WordPress plugin](../../plugins/wordpress/) · [Panel hooks](../../plugins/panels/)

---

<a id="visual-rule-builder"></a>

## Visual Rule Builder

![Visual Rule Builder schematic](../assets/features/visual-rule-builder.svg)

### How it works

A dashboard-only visual rule builder lets operators assemble firewall rules by picking a field, an operator, and a value from dropdowns, with a live expression preview. It generates only expressions the engine accepts — fields, operators, and value shapes are constrained to the documented set — and every generated rule still passes through the same server-side validation as a hand-written one, so the builder cannot produce a rule the engine would reject. It is a UI convenience, not a second engine.

### Configuration

No configuration keys: built into the dashboard.

### Limits

- The builder covers the documented field/operator set only — exotic expressions still need the text editor.
- Server-side validation is unchanged: a builder-generated rule is validated exactly like a hand-written one.

See also: [Dashboard](../dashboard.md)

---

<a id="two-person-approval"></a>

## Two-Person Approval

![Two-Person Approval schematic](../assets/features/two-person-approval.svg)

### How it works

Seven sensitive actions require two-person approval: `RESTORE_CONFIG_BACKUP`, `RESTORE_BACKUP`, `IMPORT_RULES`, `IMPORT_DOMAINS`, `IMPORT_RULE_PACK`, `CF_APPLY_IMPORT`, and `CREATE_DOMAIN_FROM_TEMPLATE`. The requester proposes the action, and a second, distinct approver must confirm it before it executes — distinctness is by caller identity (the SHA-256 of the presented API secret, or of the SSO session cookie value; values are never stored or logged). The approver must also satisfy the action's role requirement and the same tenant scoping as the original call, so a tenant approver cannot approve a proxy-wide action. Approvals expire, and every step — request, approval, rejection, expiry — is audit-logged.

### Configuration

`proxy.twoPersonApproval` (bool), `proxy.approvalExpirySeconds`. Queue via `LIST_APPROVALS` / `APPROVE_ACTION` / `REJECT_ACTION`.

### Limits

- Approval gates the action, not the judgment: two people can still approve a bad rule. The audit log is the backstop.
- Expiry is fixed per deployment; an approval that lapses must be re-requested from scratch.

See also: [API v2](../api.md)

---

<a id="privacy-mode"></a>

## Privacy Mode

![Privacy Mode schematic](../assets/features/privacy-mode.svg)

### How it works

Privacy mode reduces what the proxy retains: IP addresses are masked in logs, reports, and API responses; user-agents are not stored; and log retention is capped (2 files). Enforcement state — the rate limiter, the IP cache, the challenge cookies — keeps exact IPs, because enforcement cannot work on masked data; the masking applies to what leaves the enforcement path. The mode is proxy-wide and applies from the moment it is enabled; previously written logs are not retroactively masked.

### Configuration

`proxy.privacyMode` (bool). Retention cap is fixed at 2 files while enabled.

### Limits

- Enforcement state keeps exact IPs by necessity — privacy mode is about retention and display, not about enforcement blindness.
- Enabling privacy mode does not rewrite existing logs. Rotate or delete old logs separately if needed.

See also: [Configuration](../configuration.md#privacy-mode)

---

<a id="on-call"></a>

## On-Call Rotation

![On-Call Rotation schematic](../assets/features/on-call.svg)

### How it works

On-call rotations route alerts to the person currently on duty, timezone-aware, with escalation when an alert is not acknowledged in time. The rotation schedule lives in config; the current on-call is resolved at alert time, and acknowledgment happens through the API (`ACK_ALERT`). When no rotation covers the current time, alerts fall back to all configured channels — an alert is never silently dropped for lack of an on-call. Escalation and ACK state are audit-logged.

### Configuration

`proxy.oncall` object — `enabled`, `responders` (name + per-channel settings: telegram, email, twilio, webhook), `schedule` (responder, days, start/end, timezone), `escalationMinutes`. ACK via `ACK_ALERT`.

### Limits

- Rotations are config, not a calendar sync: holidays and swaps must be edited in config.
- Escalation needs at least two tiers configured; a single-tier rotation escalates to the fallback channels.

See also: [Configuration](../configuration.md#on-call-rotation)

---

<a id="api-v1-v2"></a>

## API v1 & v2

![API v1 & v2 schematic](../assets/features/api-v1-v2.svg)

### How it works

Two API generations serve management clients. **v1** is the original single-secret action API, kept for compatibility: one secret, one flat action namespace. **v2** adds role-scoped secrets (`proxy.apiRoles`: admin / operator / viewer / tenant-scoped), an audit log of every action, structured error codes (`ERR_FORBIDDEN`, `ERR_RELOAD_FAILED`, `ERR_CONFIG_WRITE_FAILED`, `ERR_JSON_LOGS_NOT_CONFIGURED`), and a response envelope whose result key is `results`. Bodies are capped at 1 MiB. All 84+ actions are role-checked; the current API secret stays admin. Both versions are served from the same `/_bProxy/` paths, and secret-authenticated API requests are exempt from the challenge flow.

### Configuration

`proxy.apisecret` (admin), `proxy.apiRoles` (map of secret → role). v1 uses the single secret; v2 honors roles. See [API v2](../api.md) for the full action list.

### Limits

- v1 has no roles: anyone with the v1 secret can do everything. Prefer v2 secrets with the least role needed.
- API secrets are bearer credentials: anyone holding one acts with its role. Rotate on suspicion of leak.

See also: [API v2](../api.md)

---

---

[← All features](../features.md)
