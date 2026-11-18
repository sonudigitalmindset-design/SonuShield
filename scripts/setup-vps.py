#!/usr/bin/env python3
"""SonuShield one-shot testing setup for an Ubuntu VPS (IP + HTTP, no domain).

What it does, in order:
  1. Detects the VPS public IP (override with --ip).
  2. Installs curl, git, ufw, python3 and opens ports 22/80/443.
  3. Downloads the automatic `latest` prerelease binary from GitHub.
  4. Creates a test backend page, a config.json with fresh random secrets
     (Cloudflare mode = plain HTTP on port 80, the VPS IP as the domain),
     and a mode-0600 secrets file.
  5. Runs `main validate` and STOPS if validation fails.
  6. Installs and starts systemd units for SonuShield and the test site.
  7. Prints the site URL and the dashboard URL.

TESTING ONLY: plain HTTP, so the dashboard secret travels unencrypted, and
Cloudflare mode disables TLS fingerprinting (one detection layer less).
Never use this setup for a real site with real users.

Usage (run as root on the VPS):
    sudo python3 setup-vps.py [--ip 1.2.3.4] [--force]
    python3 setup-vps.py --dry-run        # preview only, changes nothing

If /opt/sonushield/config.json already exists, the script refuses to
overwrite it unless --force is given (then it keeps a timestamped .bak).
Standard library only; no third-party packages.
"""

import argparse
import datetime
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
import urllib.request

RELEASE_URL = "https://github.com/sonudigitalmindset-design/SonuShield/releases/download/latest/main"
INSTALL_DIR = "/opt/sonushield"
SITE_DIR = "/opt/sonushield/site"
BINARY = "/opt/sonushield/main"
CONFIG = "/opt/sonushield/config.json"
SECRETS_FILE = "/root/sonushield-secrets.txt"
IP_SERVICES = ["https://ifconfig.me", "https://api.ipify.org"]

DRY_RUN = False


def step(text):
    print(f"\n== {text} ==", flush=True)


def run(cmd, check=True, env=None):
    shown = " ".join(cmd)
    if DRY_RUN:
        print(f"  [dry-run] $ {shown}")
        return None
    print(f"  $ {shown}", flush=True)
    return subprocess.run(cmd, check=check, env=env)


def write_file(path, content, mode=None):
    if DRY_RUN:
        print(f"  [dry-run] write {path} ({len(content)} bytes)")
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    if mode is not None:
        os.chmod(path, mode)
    print(f"  wrote {path}")


def detect_ip():
    for url in IP_SERVICES:
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                candidate = resp.read().decode("utf-8").strip()
            ipaddress.ip_address(candidate)  # raises if not a valid IP
            return candidate
        except Exception as exc:  # noqa: BLE001 - try next service
            print(f"  IP lookup via {url} failed: {exc}")
    return None


def download_binary():
    if DRY_RUN:
        print(f"  [dry-run] download {RELEASE_URL} -> {BINARY}")
        return
    print(f"  downloading {RELEASE_URL}", flush=True)
    with urllib.request.urlopen(RELEASE_URL, timeout=120) as resp, open(BINARY, "wb") as fh:
        shutil.copyfileobj(resp, fh, length=1024 * 1024)
    size = os.path.getsize(BINARY)
    if size < 1_000_000:
        raise SystemExit(f"ERROR: downloaded binary is only {size} bytes - refusing to use it.")
    os.chmod(BINARY, 0o755)
    print(f"  downloaded {size} bytes")


def build_config(ip, admin, api, s1, s2, s3):
    return {
        "proxy": {
            "cloudflare": True,
            "adminsecret": admin,
            "apisecret": api,
            "secrets": {"captcha": s1, "cookie": s2, "javascript": s3},
            "timeout": {"idle": 5, "read": 5, "write": 7, "read_header": 5},
            "ratelimits": {
                "challengeFailures": 40,
                "noRequestsSent": 10,
                "requests": 500,
                "unknownFingerprint": 150,
            },
            "colors": ["0", "31"],
        },
        "domains": [
            {
                "name": ip,
                "backend": "127.0.0.1:8000",
                "scheme": "http",
                "certificate": "",
                "key": "",
                "webhook": {"url": "", "name": "", "avatar": "",
                            "attack_start_msg": "", "attack_stop_msg": ""},
                "firewallRules": [
                    {"expression": '(http.path eq "/captcha")', "action": "3"},
                    {"expression": '(http.path eq "/js")', "action": "2"},
                    {"expression": '(ip.engine eq "" or ((ip.engine eq "Firefox" and http.user_agent contains "chrome") or (ip.engine eq "Chromium" and http.user_agent contains "firefox")))',
                     "action": "+1"},
                    {"expression": '(http.method ne "GET" and http.method ne "POST")',
                     "action": "+2"},
                ],
                "bypassStage1": 75,
                "bypassStage2": 250,
                "disableBypassStage3": 100,
                "disableRawStage3": 250,
                "disableBypassStage2": 50,
                "disableRawStage2": 75,
            }
        ],
    }


SONUSHIELD_UNIT = """[Unit]
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
"""

TESTSITE_UNIT = """[Unit]
Description=Test backend website
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/sonushield/site
ExecStart=/usr/bin/python3 -m http.server 8000 --bind 127.0.0.1
Restart=always

[Install]
WantedBy=multi-user.target
"""

TEST_PAGE = "<h1>SonuShield test OK</h1><p>Agar ye dikh raha hai to proxy kaam kar raha hai.</p>\n"


def main():
    global DRY_RUN
    parser = argparse.ArgumentParser(description="Set up SonuShield for testing on an Ubuntu VPS (IP + HTTP).")
    parser.add_argument("--ip", help="VPS public IP to use as the domain (default: auto-detect)")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing config.json (a .bak copy is kept)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print every step without changing anything")
    args = parser.parse_args()
    DRY_RUN = args.dry_run

    if not DRY_RUN and os.geteuid() != 0:
        raise SystemExit("ERROR: run as root (sudo python3 setup-vps.py) or use --dry-run to preview.")

    step("1. Detecting VPS public IP")
    ip = args.ip
    if ip is not None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise SystemExit(f"ERROR: --ip value {ip!r} is not a valid IP address.")
    else:
        ip = detect_ip()
        if ip is None:
            if DRY_RUN:
                ip = "203.0.113.10"
                print("  [dry-run] no IP detected; using placeholder 203.0.113.10")
            else:
                raise SystemExit("ERROR: could not detect the VPS public IP. Re-run with --ip 1.2.3.4")
    print(f"  VPS IP: {ip}")

    step("2. Installing packages + firewall")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(["apt-get", "update"], env=env)
    run(["apt-get", "install", "-y", "curl", "git", "ufw", "python3"], env=env)
    for port in ("22/tcp", "80/tcp", "443/tcp"):
        result = run(["ufw", "allow", port], check=False)
        if result is not None and result.returncode != 0:
            print(f"  WARNING: ufw allow {port} failed (continuing anyway)")
    result = run(["ufw", "--force", "enable"], check=False)
    if result is not None and result.returncode != 0:
        print("  WARNING: ufw enable failed (continuing anyway - ports may already be open)")

    step("3. Folders + test page + binary")
    if DRY_RUN:
        print(f"  [dry-run] mkdir -p {INSTALL_DIR} {SITE_DIR}")
    else:
        os.makedirs(SITE_DIR, exist_ok=True)
    write_file(os.path.join(SITE_DIR, "index.html"), TEST_PAGE)
    download_binary()
    run([BINARY, "version"], check=False)

    step("4. Secrets + config.json")
    if os.path.exists(CONFIG) and not DRY_RUN:
        if not args.force:
            raise SystemExit(
                f"ERROR: {CONFIG} already exists. Re-run with --force to overwrite it "
                "(a timestamped .bak copy is kept), or delete it first.")
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{CONFIG}.bak-{stamp}"
        shutil.copy2(CONFIG, backup)
        print(f"  existing config backed up to {backup}")
    if DRY_RUN:
        admin = api = s1 = s2 = s3 = "REDACTED"
    else:
        admin, api = secrets.token_hex(16), secrets.token_hex(16)
        s1, s2, s3 = secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(16)
    write_file(CONFIG, json.dumps(build_config(ip, admin, api, s1, s2, s3), indent=4) + "\n", mode=0o600)
    secrets_text = (
        f"VPS IP: {ip}\n"
        f"Site: http://{ip}/\n"
        f"Dashboard: http://{ip}/_bProxy/{admin}/dashboard\n"
        f"adminsecret: {admin}\n"
        f"apisecret: {api}\n"
    )
    write_file(SECRETS_FILE, secrets_text, mode=0o600)

    step("5. Validating config (stops here on error)")
    if not DRY_RUN:
        result = subprocess.run([BINARY, "validate", "--config", CONFIG])
        if result.returncode != 0:
            raise SystemExit("ERROR: config validation failed - services NOT started. Fix the error above and re-run.")
        print("  config valid")
    else:
        print(f"  [dry-run] $ {BINARY} validate --config {CONFIG}")

    step("6. systemd services")
    write_file("/etc/systemd/system/sonushield.service", SONUSHIELD_UNIT)
    write_file("/etc/systemd/system/testsite.service", TESTSITE_UNIT)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "testsite", "sonushield"])
    if not DRY_RUN:
        result = subprocess.run(["systemctl", "is-active", "sonushield"],
                                capture_output=True, text=True)
        state = result.stdout.strip()
        print(f"  sonushield service state: {state}")
        if state != "active":
            print("  WARNING: service is not active - check: journalctl -u sonushield --no-pager | tail -30")

    step("DONE - testing setup complete")
    print(f"  Site:      http://{ip}/")
    print(f"  Dashboard: http://{ip}/_bProxy/{admin}/dashboard")
    print(f"  Secrets:   {SECRETS_FILE}  (mode 0600 - never share this file)")
    print("  Status:    systemctl status sonushield --no-pager")
    print("  Logs:      journalctl -u sonushield -f")
    print("  NOTE: testing only - plain HTTP, no TLS fingerprinting in Cloudflare mode.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
