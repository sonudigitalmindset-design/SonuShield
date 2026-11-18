# Clean-History Review

A scan of the **full** git history — the fork's inherited upstream history
plus all SonuShield work — for committed secrets, keys, and tokens. No
history was rewritten: the findings below remain in history, and this page
exists so nobody mistakes that for safety.

**No secret values are printed in this document.** Findings are identified
by file name, blob/commit SHA, and secret type only.

## Scope and method — 18 November 2026

- 265 commits, from the upstream initial commit (8 January 2023) through
  the SonuShield sale-readiness work (18 November 2026), including the
  `1.2`–`1.4` tags.
- All 1,358 blobs scanned for: PEM private keys, OpenSSH/PGP private keys,
  GitHub personal access tokens, AWS access keys, Slack tokens, Discord
  webhook URLs, and JWT-shaped strings. All file names scanned for
  key/certificate/credential/secret/token patterns. All commit messages
  scanned for the same patterns.
- Every match was classified by hand: file type, whether the value is a
  real credential or a placeholder/example, and which commits introduced
  and removed it.
- Live/dead status was **not** probed for third-party credentials: checking
  whether someone else's webhook or key still works would mean using it.
  Treat every real-looking value below as compromised.

## Findings

### 1. baloo.dog TLS certificate + RSA private key — KNOWN, DEAD, NEVER REUSE

- **Files:** `assets/server/server.crt` (blob `d1082e63…`) and
  `assets/server/server.key` (blob `c779acc3…`, RSA private key).
- **Certificate (public information):** CN `baloo.dog`, SANs `baloo.dog`
  and `www.baloo.dog`, issued by ZeroSSL, valid 17 December 2022 – 17 March
  2023. **Expired.**
- **History:** present from upstream commit `1fcb542` (31 January 2023);
  removed in SonuShield commit `609f148` (17 November 2026), which added
  the dev certificate generator (`scripts/generate-certs.sh`) instead.
- **Status:** dead as a TLS identity (expired, and the domain is the
  upstream author's, not SonuShield's). The private key must **never be
  reused** for any purpose: it has been public since 2023, so anything
  ever secured with it should be treated as exposed. No committed binary
  embeds the key material (verified: 0 of 54 binary blobs contain it).
- **Action:** none for SonuShield operators beyond never reusing it. The
  key stays in history; rewriting history would break every fork and clone
  for no security gain, since the key has been public for years.

### 2. Discord webhook URL — REAL-LOOKING, OWNER MUST ROTATE

- **File:** upstream-era root `config.json` (several blobs, 2023).
- **Type:** one Discord webhook URL (webhook ID `1055573557880569886`,
  68-character token — token value redacted). A webhook URL is a bearer
  credential: anyone holding it can post messages to that channel.
- **History:** introduced in upstream commits `c1f12b9` / `c2f24ba`
  (February 2023). The root `config.json` was deleted from tracking in
  `dc58504` (29 July 2023). The same webhook ID still appears in the
  current `examples/config.json`, with the token replaced by `XXX…`
  placeholders.
- **Status:** live/dead unverified (not probed). The webhook belongs to
  the upstream project, not SonuShield — only its owner can regenerate or
  delete it. SonuShield operators must never use this URL.
- **Action:** recommended to the upstream owner: regenerate or delete the
  webhook. A second webhook URL in the same files (36-character token,
  reused identically across three domains) is placeholder-shaped and is
  not treated as a credential.

### 3. Upstream-era config secrets — REAL-LOOKING, DEAD WITH THE 2023 CONFIGS

- **File:** upstream-era root `config.json` (2023 blobs).
- **Types:** 8 distinct values — 1 admin secret, 1 API secret, and 6
  challenge secrets (`cookie` / `javascript` / `captcha`, two generations).
  Values redacted; identified here only by count and field.
- **History:** committed in upstream 2023 configs; the file left tracking
  in `dc58504` (29 July 2023). No SonuShield-era commit (November 2026)
  ever committed a live `config.json`.
- **Status:** dead with the configs that held them — but the values must
  never be reused anywhere. They are upstream development secrets, not
  SonuShield operator secrets.
- **Action:** none, beyond the standing rule: generate fresh secrets per
  deployment (the setup wizard and validator enforce non-placeholder
  values).

### 4. Compiled binaries matching "PRIVATE KEY" — FALSE POSITIVES

- **Files:** 54 blobs named `main` or `oryxBuildBinary` (committed Go
  binaries, upstream era through November 2026).
- **Finding:** every one contains the byte string `PRIVATE KEY` — the Go
  standard library's PEM block-type constant, embedded in any binary that
  links `crypto/x509` / `encoding/pem`. None contains actual key material
  (verified by fragment search against finding 1's key).
- **History:** `main` binaries left tracking in upstream commit `91fc8bf`
  (13 June 2024); `oryxBuildBinary` was removed in SonuShield commit
  `11d43d8` (17 November 2026) and is now gitignored.
- **Action:** none. Binaries must stay out of the repo (gitignored).

## Clean results

- **Zero** GitHub tokens, AWS keys, Slack tokens, JWTs, SSH keys, or PGP
  private keys anywhere in history.
- **Zero** secrets in commit messages.
- **Zero** secrets introduced by any SonuShield-era commit (17–18 November
  2026). The SonuShield work only ever committed placeholder configs.
- **HEAD is clean:** the only config file tracked is `examples/config.json`,
  whose secrets are `CHANGE_ME…` placeholders (5 occurrences) and `XXX…`
  webhook tokens. No certificate, key, or live config is tracked.

## Prevention

`.gitignore` now covers the recurrence paths (added with this review):

- `/config.json`, `/control-accounts.json` (password hashes),
  `/control-audit.log` — anchored to the repo root so
  `examples/config.json` stays tracked.
- Pre-existing: `assets/server/`, `*.crt`, `*.key`, `*.mmdb`,
  `autocert-cache/`, `oryxBuildBinary`, `main`.

The validator rejects `CHANGE_ME` secrets, and the setup wizard generates
fresh secrets — but neither can stop a determined `git add -f`. The rule
stands: **never commit `config.json`, certificates, keys, secrets, or
password hashes.** If a live secret is ever committed, rotate it first and
treat the history entry as permanently public; history rewrites do not
unexpose a secret that was ever pushed.

## Recommended rotations (summary)

| Secret | Owner | Action |
|---|---|---|
| baloo.dog RSA key (finding 1) | Upstream / public since 2023 | Never reuse; rotate anything ever secured with it |
| Discord webhook (finding 2) | Upstream webhook owner | Regenerate or delete the webhook |
| 2023 config secrets (finding 3) | Upstream / dead | Never reuse the values |
| SonuShield operator secrets | Each operator | Fresh per deployment; nothing to rotate from this review |
