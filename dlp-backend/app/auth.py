from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings
from app.database import get_authenticated_supabase


_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    user_id: UUID
    org_id: UUID
    access_token: str


def get_current_principal(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer_scheme),
    ],
) -> AuthenticatedPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer authentication required")

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_role_key:
        raise HTTPException(status_code=503, detail="Supabase authentication is not configured")

    try:
        response = httpx.get(
            f"{settings.supabase_url.rstrip('/')}/auth/v1/user",
            headers={
                "apikey": settings.supabase_service_role_key,
                "Authorization": f"Bearer {credentials.credentials}",
            },
            timeout=10.0,
        )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail="Unable to verify authentication") from exc

    if response.status_code in (401, 403):
        raise HTTPException(status_code=401, detail="Invalid or expired bearer token")
    if response.is_error:
        raise HTTPException(status_code=503, detail="Unable to verify authentication")

    try:
        user_id = UUID(response.json()["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid authentication response") from exc

    try:
        memberships = (
            get_authenticated_supabase(credentials.credentials)
            .table("org_members")
            .select("org_id")
            .eq("user_id", str(user_id))
            .limit(1)
            .execute()
            .data
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to resolve organization membership",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to resolve organization membership",
        ) from exc

    if not memberships:
        raise HTTPException(status_code=403, detail="No organization membership found")

    try:
        org_id = UUID(memberships[0]["org_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Invalid organization membership data") from exc

    return AuthenticatedPrincipal(
        user_id=user_id,
        org_id=org_id,
        access_token=credentials.credentials,
    )
