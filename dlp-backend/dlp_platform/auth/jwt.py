"""Strict Supabase-compatible JWT verification."""

from functools import lru_cache
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError
from jwt.types import Options

from dlp_platform.auth.settings import AuthSettings


class TokenRejected(ValueError):
    """Raised when a bearer token cannot be validated."""


@lru_cache(maxsize=4)
def _jwks_client(url: str) -> PyJWKClient:
    return PyJWKClient(url, timeout=5, cache_keys=True)


def decode_access_token(token: str, settings: AuthSettings) -> dict[str, object]:
    """Verify the token signature and required registered claims."""
    try:
        if bool(settings.jwt_secret) == bool(settings.jwks_url):
            raise TokenRejected("configure exactly one JWT verification key source")
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        if algorithm == "HS256" and settings.jwt_secret:
            key: Any = settings.jwt_secret
            algorithms = ["HS256"]
        elif algorithm in {"RS256", "ES256"} and settings.jwks_url:
            key = _jwks_client(settings.jwks_url).get_signing_key_from_jwt(token).key
            algorithms = ["RS256", "ES256"]
        else:
            raise TokenRejected("unsupported JWT algorithm")

        options: Options = {"require": ["exp", "sub", "aud"], "verify_aud": True}
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=algorithms,
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            leeway=settings.jwt_leeway_seconds,
            options=options,
        )
        return decoded
    except TokenRejected:
        raise
    except (PyJWTError, OSError, ValueError) as exc:
        raise TokenRejected("invalid bearer token") from exc


def decode_sso_access_token(token: str, settings: AuthSettings) -> dict[str, object]:
    """Validate short-lived P11 tokens signed by a separate application key."""
    if settings.sso_token_secret is None or len(settings.sso_token_secret.encode()) < 32:
        raise TokenRejected("SSO token verification is not configured")
    try:
        claims = jwt.decode(
            token,
            settings.sso_token_secret,
            algorithms=["HS256"],
            audience=settings.sso_token_audience,
            issuer=settings.sso_token_issuer,
            leeway=0,
            options={"require": ["exp", "iat", "sub", "aud", "iss", "org_id", "amr"]},
        )
        if claims.get("amr") != ["sso"] or not isinstance(claims.get("org_id"), str):
            raise TokenRejected("invalid SSO access token")
        return claims
    except TokenRejected:
        raise
    except (PyJWTError, OSError, ValueError) as exc:
        raise TokenRejected("invalid SSO access token") from exc
