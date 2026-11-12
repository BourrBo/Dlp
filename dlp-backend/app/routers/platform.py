"""Link the signed-in user's organization into the platform and report its status."""

import logging
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthenticatedPrincipal, get_current_principal
from app.database import get_authenticated_supabase
from app.platform_bridge import platform_enabled

router = APIRouter(prefix="/api/platform", tags=["platform"])
logger = logging.getLogger(__name__)
Principal = Annotated[AuthenticatedPrincipal, Depends(get_current_principal)]


@router.get("/status")
def platform_status(principal: Principal) -> dict:
    return {"enabled": platform_enabled(), "base_path": "/platform" if platform_enabled() else None}


@router.post("/link")
def link_platform(principal: Principal) -> dict:
    """Make the caller a platform member of their organization (idempotent).

    After linking, the same Supabase session works against ``/platform/*`` and
    the user can mint scan API keys at ``/platform/api-keys``.
    """
    if not platform_enabled():
        raise HTTPException(status_code=503, detail="Platform is not enabled")
    client = get_authenticated_supabase(principal.access_token)
    try:
        membership = (client.table("org_members").select("*").eq("user_id", str(principal.user_id))
                      .eq("org_id", str(principal.org_id)).limit(1).execute().data)
        org = client.table("organizations").select("name").eq("id", str(principal.org_id)).limit(1).execute().data
    except (httpx.HTTPError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Unable to read organization") from exc
    if not membership:
        raise HTTPException(status_code=403, detail="Organization membership required")
    from app.platform_bridge.link import link_member

    try:
        role = link_member(
            str(principal.org_id), (org[0]["name"] if org else "Organization"),
            str(principal.user_id), membership[0].get("email"), membership[0].get("role"),
        )
    except Exception as exc:
        logger.error("Platform link failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Platform link failed") from exc
    return {"linked": True, "role": role, "org_id": str(principal.org_id)}
