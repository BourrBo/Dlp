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
    # "user" = verified Supabase session; "api_key" = platform-issued service key.
    # API-key principals carry no Supabase token and may only call scan routes.
    auth_method: str = "user"
    scopes: tuple[str, ...] = ()


def get_current_principal(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer_scheme),
    ],
) -> AuthenticatedPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer authentication required")

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_publishable_key:
        raise HTTPException(status_code=503, detail="Supabase authentication is not configured")

    try:
        response = httpx.get(
            f"{settings.supabase_url.rstrip('/')}/auth/v1/user",
            headers={
                "apikey": settings.supabase_publishable_key,
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
    except (httpx.HTTPError, RuntimeError) as exc:
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


def require_org_membership(principal: AuthenticatedPrincipal, org_id: UUID) -> None:
    if principal.auth_method == "api_key":
        if principal.org_id != org_id:
            raise HTTPException(status_code=403, detail="Organization membership required")
        return
    try:
        memberships = (
            get_authenticated_supabase(principal.access_token)
            .table("org_members")
            .select("org_id")
            .eq("user_id", str(principal.user_id))
            .eq("org_id", str(org_id))
            .limit(1)
            .execute()
            .data
        )
    except (httpx.HTTPError, RuntimeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to resolve organization membership",
        ) from exc

    if not memberships:
        raise HTTPException(status_code=403, detail="Organization membership required")


SCAN_SCOPE = "scan:request"


def resolve_org(principal: AuthenticatedPrincipal, org_id: UUID | None) -> UUID:
    """Return the organization a request acts on.

    Clients using an API key (extension, CLI, agents) omit ``org_id``; it is the
    key's organization. An explicit ``org_id`` must match the caller's membership.
    """
    if org_id is None:
        return principal.org_id
    require_org_membership(principal, org_id)
    return org_id


def get_scan_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> AuthenticatedPrincipal:
    """Principal for scan routes: a Supabase user session or a platform API key.

    Extension, CLI, device and CI callers use ``dlp_...`` keys minted at
    ``/platform/api-keys``; dashboard users use their Supabase session.
    """
    if credentials is not None and credentials.scheme.lower() == "bearer" \
            and credentials.credentials.startswith("dlp_"):
        from app.platform_bridge import platform_enabled

        if not platform_enabled():
            raise HTTPException(status_code=503, detail="API key authentication is not configured")
        from app.platform_bridge.api_keys import verify_api_key

        try:
            identity = verify_api_key(credentials.credentials)
        except Exception as exc:  # database outage must not read as "bad key"
            raise HTTPException(status_code=503, detail="Unable to verify API key") from exc
        if identity is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if SCAN_SCOPE not in identity.scopes:
            raise HTTPException(status_code=403, detail="API key lacks the scan:request scope")
        return AuthenticatedPrincipal(
            user_id=identity.user_id, org_id=identity.org_id, access_token="",
            auth_method="api_key", scopes=identity.scopes,
        )
    return get_current_principal(credentials)
