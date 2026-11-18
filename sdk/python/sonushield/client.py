"""Client for the SonuShield public API v1 (stdlib only)."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

# Number of 429 retries per call.
DEFAULT_MAX_RETRIES = 3

# Cap on each Retry-After wait, in seconds.
MAX_RETRY_WAIT = 30


class SonuShieldError(Exception):
    """A public API failure.

    Attributes:
        status_code: HTTP status of the response (0 when no
            response was received, e.g. a network error).
        code: machine-readable error code from the envelope
            ("unauthorized", "rate_limited", "not_found", ...).
        message: human-readable message from the envelope.
        retry_after: seconds from the Retry-After header on
            rate-limit errors, or None.
    """

    def __init__(self, message, status_code=0, code="", retry_after=None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retry_after = retry_after

    def __str__(self):
        if self.code:
            return f"sonushield: HTTP {self.status_code} ({self.code}): {self.message}"
        if self.status_code:
            return f"sonushield: HTTP {self.status_code}: {self.message}"
        return f"sonushield: {self.message}"


class Client:
    """Talks to one SonuShield instance's public API.

    Args:
        base_url: the proxy origin, e.g. "https://example.com".
        api_key: the tenant's API key.
        timeout: per-request timeout in seconds.
        max_retries: number of 429 retries per call (honoring
            Retry-After, capped at 30s per wait).
    """

    def __init__(self, base_url, api_key, timeout=15, max_retries=DEFAULT_MAX_RETRIES):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries

    def _get(self, path):
        url = f"{self.base_url}/_bProxy/public/v1/{path}"
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, method="GET")
            req.add_header("Authorization", f"Bearer {self.api_key}")
            req.add_header("Accept", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return self._decode(resp)
            except urllib.error.HTTPError as exc:
                body = exc.read()
                if exc.code == 429 and attempt < self.max_retries:
                    time.sleep(self._retry_wait(exc.headers))
                    continue
                raise self._error(exc, body) from None
            except urllib.error.URLError as exc:
                raise SonuShieldError(str(exc.reason)) from None
        raise SonuShieldError("unreachable")  # pragma: no cover

    @staticmethod
    def _decode(resp):
        try:
            payload = json.loads(resp.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SonuShieldError(f"invalid response: {exc}") from None
        if not payload.get("ok"):
            err = payload.get("error") or {}
            raise SonuShieldError(
                err.get("message", "request failed"),
                status_code=resp.status,
                code=err.get("code", ""),
            )
        return payload.get("data")

    @staticmethod
    def _retry_wait(headers):
        try:
            seconds = int(headers.get("Retry-After", "1"))
        except ValueError:
            seconds = 1
        return max(1, min(seconds, MAX_RETRY_WAIT))

    @staticmethod
    def _error(exc, body):
        retry_after = None
        try:
            retry_after = int(exc.headers.get("Retry-After"))
        except (TypeError, ValueError):
            pass
        try:
            payload = json.loads(body.decode("utf-8"))
            err = payload.get("error") or {}
            return SonuShieldError(
                err.get("message") or exc.reason,
                status_code=exc.code,
                code=err.get("code", ""),
                retry_after=retry_after,
            )
        except (ValueError, UnicodeDecodeError):
            return SonuShieldError(
                exc.reason, status_code=exc.code, retry_after=retry_after
            )

    def ping(self):
        """Check the key; returns {"tenant": ..., "key_name": ...}."""
        return self._get("ping")

    def usage(self, domain=None):
        """Tenant aggregate usage; with domain, one of the tenant's
        domains. Returns {"tenant", "requests", "blocked",
        "bytes_in", "bytes_out", "bytes_total", "domains"}.
        Domains outside the tenant raise a not_found error,
        exactly like nonexistent ones."""
        path = "usage"
        if domain is not None:
            path += "?domain=" + urllib.parse.quote(domain, safe="")
        return self._get(path)

    def domains(self):
        """List the tenant's domains with stage and counters.
        Returns {"tenant", "domains": [{...}, ...]}."""
        return self._get("domains")
