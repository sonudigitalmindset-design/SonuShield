# Installation

How to get SonuShield running: requirements, building, certificates, running it, Docker, and DNS.

> [← README](../README.md)

> **New here?** Start with the [README](../README.md), then come back here. For what every setting does, see [Configuration](configuration.md).

## Requirements

- Go 1.24 or newer, to build from source.
- A server with ports 80 and 443 available (443 is only used outside Cloudflare mode).
- Outbound HTTPS access to `raw.githubusercontent.com` at startup, for the fingerprint lists and the version check (see [Startup Checks](how-it-works.md#startup-checks)).
- One TLS certificate and private key per domain, unless you run in Cloudflare mode (see [Certificates](#certificates)).

## Quick Setup Script (testing VPS)

`scripts/setup-vps.py` automates the whole testing install on an Ubuntu VPS: it detects the server's public IP, installs dependencies, generates a self-signed certificate for a local hostname (default `test.local` — add `<ip> test.local` to your PC's hosts file; browsers send no SNI for bare IP literals, and SonuShield selects certificates by SNI), downloads the `latest` prerelease binary (size-verified, smoke-checked), writes a `config.json` with fresh random secrets, validates it, and installs systemd services for the proxy and a test backend page. Review it before running — it prints every step, and `--dry-run` previews without changing anything. `--plain-http` selects the old IP-based Cloudflare-mode setup, which is not recommended: challenge cookies carry the `Secure` flag, so challenge pages redirect-loop over plain HTTP.

```sh
curl -L -o setup-vps.py https://raw.githubusercontent.com/sonudigitalmindset-design/SonuShield/main/scripts/setup-vps.py
sudo python3 setup-vps.py            # real run, needs root
python3 setup-vps.py --dry-run       # preview only
```

Testing only: the certificate is self-signed, so browsers warn once before proceeding. See the script's header comment for details.

## Build from Source

```sh
git clone https://github.com/sonudigitalmindset-design/SonuShield.git
cd SonuShield
go build -o main .
```

This produces a `main` binary in the repository directory.

## Automatic Prerelease Builds

Every push to the `main` branch publishes an automatic prerelease build (tag `latest`) through GitHub Actions. These builds may contain bugs. You can find them on the [Releases page](https://github.com/sonudigitalmindset-design/SonuShield/releases).

## First Run

### Setup Wizard (Web)

The easiest first run is the web-based setup wizard. Start the binary with `--wizard`:

```sh
./main --wizard
```

The wizard serves a three-step setup page on `http://127.0.0.1:8080` (localhost only; use an SSH tunnel from a remote machine, and `--wizard-listen=ADDR` to change the address). It validates your inputs, generates the internal secrets, offers a backend health check, and writes `config.json` with mode `0600`. It never overwrites an existing config without explicit confirmation, and `--wizard` refuses to start when a config already exists. The wizard also starts automatically when the binary is launched without a `config.json` and without a terminal on stdin (for example, under a process manager) — an interactive launch without a config keeps the terminal setup below instead. The wizard page is English-only.

### Terminal Setup

Run `./main` without a `config.json` in the same directory and SonuShield will ask you a series of setup questions (Cloudflare mode, timeouts, rate limits, then one domain) and write a `config.json` for you. Stop it with `Ctrl+C`, review the generated file, then start it again. Secrets generated during setup are random strings.

If you already have a `config.json`, place it in the same directory as the `main` binary before starting.

> [!NOTE]
> Example configurations use `CHANGE_ME` placeholder secrets. SonuShield refuses to start if any secret still contains `CHANGE_ME` — replace all of them with real random values first.

## Command-Line Interface

The binary is also a small CLI (standard-library flags only). With no arguments it runs the proxy, exactly as before; `run` is the explicit equivalent:

```sh
./main run                          # start the proxy
./main validate [--config PATH]     # validate a config file, exit 0/1
./main export [--config PATH] [--include-secrets]
                                    # print the config; secrets redacted
                                    # unless --include-secrets is given
./main backup [--config PATH] [--output FILE] [--include-secrets]
                                    # write a backup envelope (see below)
./main restore [--config PATH] BACKUP_FILE
                                    # validate and apply a backup envelope
./main version                      # print the version (also --version)
./main help                         # usage (also --help / -h)
```

`validate` runs the same checks as an API reload (secrets, domains, rules, certificate pairs) without starting the proxy — use it in CI or before a reload. `export` prints the config document with every secret-bearing field replaced by `REDACTED` (role-secret map keys are numbered `REDACTED-N`); `--include-secrets` prints the real values — only use it where the output stays private. `backup` writes a backup envelope to stdout or `--output` (mode `0600`); `--include-secrets` requires the passphrase in the `SONUSHIELD_BACKUP_PASSPHRASE` environment variable (never a flag) and encrypts the secrets into the envelope. `restore` validates the envelope and the resulting config before writing anything, keeps a `.bak` copy of the current file, and prints a restart instruction — it never starts the proxy. See the `EXPORT_BACKUP` / `RESTORE_BACKUP` actions in the [API Reference](api.md#proxy-actions) for the envelope format. The version string is stamped at build time with `-ldflags "-X main.version=vX.Y.Z"`; unstamped builds report `dev`.

## Install Script

`scripts/install.sh` installs a pinned release binary with checksum verification. It is safe to inspect before running: no hidden downloads, no pipes into a shell, no `sudo`, no `eval` — it downloads exactly the release tarball and its `.sha256` file, prints both URLs first, verifies the checksum, checks the tarball contains exactly one file named `sonushield`, smoke-checks the binary, and installs it atomically to `$PREFIX/bin/sonushield` (default prefix `/usr/local`). A version is required — there is no "latest":

```sh
./scripts/install.sh --version v1.0.0 [--prefix /usr/local] [--dry-run]
```

`--dry-run` prints what would happen without downloading or installing. `SONUSHIELD_RELEASE_BASE_URL` overrides the download base for mirrors and tests only. **No versioned releases exist yet** — the only published artifacts are the automatic `latest` prereleases, which the installer deliberately refuses (unpinned). The installer is ready for the first versioned release; until then, build from source.

## Helm Chart

`deploy/helm/sonushield/` is a Helm chart for Kubernetes deployment (single replica, `Recreate` strategy — the proxy keeps in-memory state). The image tag is required (`--set image.tag=...`); the default repository is `ghcr.io/sonudigitalmindset-design/sonushield`, but **no image is published yet** — build and push one first, or point `image.repository` at your own registry. Exactly one config source must be set: inline `config`, an `existingConfigMap`, or (recommended) an `existingSecret` holding `config.json`, mounted read-only via `subPath`. With no config source the pod starts in wizard bootstrap mode. TLS comes from `tls.existingSecret` mounted at `/certs`. Probes are TCP checks on port 443, and the pod runs with all capabilities dropped except `NET_BIND_SERVICE` under the RuntimeDefault seccomp profile. Note: `helm lint` with default values fails YAML parsing because the required tag leaves the template unrendered — lint with `--set image.tag=...`.

## Certificates

Outside Cloudflare mode, every domain needs a TLS certificate and private key. Their paths are set per domain with `certificate` and `key` in `config.json`, and they are loaded at startup. If a certificate or key is missing or invalid, SonuShield refuses to start.

### Development Certificates

For local testing only, generate self-signed certificates with the included script:

```sh
./scripts/generate-certs.sh
```

This writes `assets/server/server.crt` and `assets/server/server.key`, matching the paths used in `examples/config.json`. Generated certificates and keys are ignored by git and are never committed.

> [!WARNING]
> Self-signed certificates are for development only. Browsers will show security warnings for them. In production, use real certificates (for example, from Let's Encrypt) and keep private keys secret.

Do not use any certificate or key previously found in this repository's history: the old default private key was public and must never be reused. In Cloudflare mode, leave `certificate` and `key` empty — they are not loaded.

## Running

### In the Foreground

```sh
./main
```

The terminal shows the live HUD and accepts [commands](how-it-works.md#terminal). Keep the terminal open, or use one of the methods below to keep the proxy running after you log out.

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

## Next Steps

- [Configuration](configuration.md) — every setting explained.
- [How It Works](how-it-works.md) — architecture, challenges, and Cloudflare mode.
- [Troubleshooting](troubleshooting.md) — if something goes wrong.
