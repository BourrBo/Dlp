"""Synthetic token helpers; no real credentials are present."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt

from platform_tests.auth.conftest import ISSUER, JWT_SECRET, ORG_A


def signed_token(
    subject: str = "user-owner-a",
    organization_id: UUID = ORG_A,
    *,
    secret: str = JWT_SECRET,
    audience: str = "authenticated",
    expires_in: int = 300,
    algorithm: str = "HS256",
    include_org: bool = True,
) -> str:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "sub": subject,
        "iss": ISSUER,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "jti": str(uuid4()),
    }
    if include_org:
        payload["org_id"] = str(organization_id)
    return jwt.encode(payload, secret, algorithm=algorithm)


def auth_headers(token: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token or signed_token()}"}
