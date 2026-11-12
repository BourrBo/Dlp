"""GitHub App cryptographic and installation-token primitives.

The private key is passed in by the caller. Production routes must obtain it
from P2's credential vault and send returned installation tokens back to that
vault; this module deliberately does not persist or log credentials.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import time
from collections.abc import Mapping, Sequence

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
MAX_APP_JWT_LIFETIME_SECONDS = 600
DEFAULT_APP_JWT_LIFETIME_SECONDS = 540
INSTALLATION_PERMISSIONS = {"contents": "read", "metadata": "read", "checks": "write"}


class GitHubAppError(RuntimeError):
    """Sanitized GitHub App integration error with no credential material."""


@dataclass(frozen=True)
class InstallationToken:
    token: str = field(repr=False)
    expires_at: str
    permissions: Mapping[str, str]
    repository_selection: str | None = None


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_github_app_jwt(
    issuer: str,
    private_key_pem: bytes,
    *,
    now: int | None = None,
    lifetime_seconds: int = DEFAULT_APP_JWT_LIFETIME_SECONDS,
) -> str:
    """Create an RS256 JWT with GitHub's 60-second clock-skew allowance.

    GitHub accepts a JWT for at most ten minutes from its issue time. The
    default `iat=now-60, exp=now+540` keeps the complete interval to ten
    minutes while allowing for clock drift.
    """
    if not issuer or not isinstance(issuer, str):
        raise ValueError("GitHub App issuer must be a non-empty client or app ID")
    if not isinstance(private_key_pem, bytes) or not private_key_pem:
        raise ValueError("GitHub App private key is required")
    if not 1 <= lifetime_seconds <= MAX_APP_JWT_LIFETIME_SECONDS - 60:
        raise ValueError("GitHub App JWT lifetime must be between 1 and 540 seconds")

    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("GitHub App private key must be an unencrypted PEM key") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("GitHub App private key must be RSA")

    timestamp = int(time.time()) if now is None else int(now)
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps(
            {"iat": timestamp - 60, "exp": timestamp + lifetime_seconds, "iss": issuer},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def verify_github_webhook_signature(payload: bytes, signature: str | None, secret: str | None) -> bool:
    """Verify GitHub's `X-Hub-Signature-256` value against the raw request bytes."""
    if not isinstance(payload, bytes) or not secret or not signature:
        return False
    if not signature.startswith("sha256="):
        return False
    received = signature[7:]
    if len(received) != hashlib.sha256().digest_size * 2:
        return False
    try:
        bytes.fromhex(received)
    except ValueError:
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(received.lower(), expected)


def create_installation_access_token(
    installation_id: int,
    issuer: str,
    private_key_pem: bytes,
    *,
    repository_ids: Sequence[int] | None = None,
    client: httpx.Client | None = None,
) -> InstallationToken:
    """Mint a least-privilege installation token without persisting it.

    The caller is responsible for storing the returned secret through P2's
    vault and restricting access to the installation's repository set.
    """
    if isinstance(installation_id, bool) or not isinstance(installation_id, int) or installation_id <= 0:
        raise ValueError("GitHub installation ID must be a positive integer")
    if repository_ids is not None and (
        not repository_ids
        or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in repository_ids)
    ):
        raise ValueError("Repository IDs must be a non-empty sequence of positive integers")

    jwt_token = create_github_app_jwt(issuer, private_key_pem)
    url = f"{GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {jwt_token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    body: dict[str, object] = {"permissions": INSTALLATION_PERMISSIONS}
    if repository_ids is not None:
        body["repository_ids"] = list(repository_ids)

    owned_client = client is None
    http_client = client or httpx.Client(timeout=15.0)
    try:
        response = http_client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise GitHubAppError("GitHub installation-token request failed") from exc
    finally:
        if owned_client:
            http_client.close()

    if response.status_code not in {200, 201}:
        raise GitHubAppError(f"GitHub installation-token request failed with HTTP {response.status_code}")
    try:
        result = response.json()
        token = result["token"]
        expires_at = result["expires_at"]
        permissions = result.get("permissions", INSTALLATION_PERMISSIONS)
        repository_selection = result.get("repository_selection")
    except (ValueError, KeyError, TypeError) as exc:
        raise GitHubAppError("GitHub returned an invalid installation-token response") from exc
    if not isinstance(token, str) or not token or not isinstance(expires_at, str) or not isinstance(permissions, dict):
        raise GitHubAppError("GitHub returned an invalid installation-token response")

    return InstallationToken(
        token=token,
        expires_at=expires_at,
        permissions=permissions,
        repository_selection=repository_selection if isinstance(repository_selection, str) else None,
    )
