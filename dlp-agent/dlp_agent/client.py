"""HTTPS client for the platform's /agent routes (stdlib only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from dlp_agent import __version__


class Offline(Exception):
    """Network failure or server error: retry later."""


class AuthRejected(Exception):
    """The server rejected the device key (revoked or invalid)."""


class Rejected(Exception):
    """The server refused this request (4xx other than auth); retrying will not help."""


def validate_server_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("server URL must use https (http is allowed for localhost only)")
    if not parsed.hostname:
        raise ValueError("server URL has no host")
    return url.rstrip("/")


class ServerClient:
    def __init__(self, server_url: str, device_key: Optional[str] = None, timeout: float = 15.0) -> None:
        self.base = validate_server_url(server_url)
        self._key = device_key
        self._timeout = timeout

    def _request(self, method: str, path: str, body: Optional[dict[str, Any]] = None, auth: bool = True) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json", "User-Agent": f"dlp-agent/{__version__}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if auth and self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310 - scheme validated
                return json.loads(response.read(10_000_000) or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise AuthRejected("device credentials rejected") from None
            if exc.code in (408, 425, 429) or exc.code >= 500:
                raise Offline(f"server returned {exc.code}") from None
            raise Rejected(f"server returned {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise Offline(type(exc).__name__) from None

    def enrol(self, token: str, hostname: str, os_name: str) -> dict[str, Any]:
        return self._request("POST", "/agent/enrol", {"enrolment_token": token, "hostname": hostname[:255],
                                                      "os_name": os_name[:100], "agent_version": __version__}, auth=False)

    def heartbeat(self, queue_depth: int, config_version: int, tamper: list[str]) -> dict[str, Any]:
        return self._request("POST", "/agent/heartbeat", {"agent_version": __version__, "queue_depth": queue_depth,
                                                          "config_version": config_version, "tamper": tamper})

    def events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return self._request("POST", "/agent/events", {"events": events})

    def scan(self, filename: str, chunks: list[dict[str, Any]]) -> dict[str, Any]:
        return self._request("POST", "/agent/scan", {"filename": filename, "chunks": chunks})
