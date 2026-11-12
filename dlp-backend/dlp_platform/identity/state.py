"""Signed, short-lived browser binding for OIDC/SAML transactions."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any


class StateError(ValueError):
    """Invalid or expired SSO browser transaction."""


def new_secret(size: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(size)).decode().rstrip("=")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _key() -> bytes:
    value = os.getenv("DLP_SSO_STATE_SECRET", "").encode()
    if len(value) < 32:
        raise StateError("SSO transaction protection is not configured")
    return value


def seal(payload: dict[str, Any]) -> str:
    body = (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def open_cookie(value: str, *, state: str) -> dict[str, Any]:
    try:
        body, signature = value.split(".", 1)
        expected = hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise StateError("SSO transaction is invalid")
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        payload = json.loads(raw)
        if (
            not isinstance(payload, dict)
            or payload.get("state") != state
            or not isinstance(payload.get("exp"), int)
            or payload["exp"] < int(time.time())
            or payload["exp"] > int(time.time()) + 600
            or not all(
                isinstance(payload.get(key), str)
                for key in ("nonce", "verifier", "config_id", "org_id")
            )
        ):
            raise StateError("SSO transaction is invalid")
        return payload
    except StateError:
        raise
    except Exception as exc:
        raise StateError("SSO transaction is invalid") from exc


def cookie_name(state: str) -> str:
    suffix = hashlib.sha256(state.encode()).hexdigest()[:20]
    return f"__Host-dlp-sso-{suffix}"
