"""Minimal client for the SonuShield public API v1.

The public API (/_bProxy/public/v1/*) is the tenant/reseller
read API, distinct from the internal control API. It uses
per-tenant API keys (Bearer token) and per-key rate limits.

Standard library only — no third-party dependencies.

Example:

    from sonushield import Client

    client = Client("https://example.com", "your-api-key")
    print(client.usage())
"""

from .client import Client, SonuShieldError

__all__ = ["Client", "SonuShieldError"]
