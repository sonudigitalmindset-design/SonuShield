#!/usr/bin/env python3
"""Example program for the SonuShield public API client.

    SONUSHIELD_URL=https://example.com SONUSHIELD_API_KEY=your-key python3 example.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sonushield import Client, SonuShieldError  # noqa: E402


def main():
    base_url = os.environ.get("SONUSHIELD_URL")
    api_key = os.environ.get("SONUSHIELD_API_KEY")
    if not base_url or not api_key:
        print("set SONUSHIELD_URL and SONUSHIELD_API_KEY", file=sys.stderr)
        return 2
    client = Client(base_url, api_key)
    try:
        ping = client.ping()
        print(f"tenant: {ping['tenant']} (key: {ping['key_name']})")
        usage = client.usage()
        print(
            f"requests: {usage['requests']} (blocked {usage['blocked']}), "
            f"bytes: {usage['bytes_total']} across {len(usage['domains'])} domains"
        )
        domains = client.domains()
        for d in domains["domains"]:
            print(
                f"- {d['name']} stage {d['stage']} ({d['stage_name']}) "
                f"under_attack={d['under_attack']} requests={d['requests']}"
            )
    except SonuShieldError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
