"""Approved-fingerprint allowlist consumed by ``dlp sync-allowlist``.

Reads accept a platform API key (what the CLI and CI hold). Changes require a
signed-in organization member. Only 16-hex fingerprints are stored, never values.
"""

import logging
import re
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import database
from app.auth import AuthenticatedPrincipal, get_current_principal, get_scan_principal

router = APIRouter(prefix="/api/v1/allowlist", tags=["allowlist"])
logger = logging.getLogger(__name__)
_FINGERPRINT = re.compile(r"^[0-9a-f]{16}$")
Reader = Annotated[AuthenticatedPrincipal, Depends(get_scan_principal)]
Writer = Annotated[AuthenticatedPrincipal, Depends(get_current_principal)]


class AllowlistResponse(BaseModel):
    fingerprints: list[str]


class AllowlistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str = Field(pattern=r"^[0-9a-f]{16}$")
    reason: str | None = Field(default=None, max_length=500)


@router.get("", response_model=AllowlistResponse)
def read_allowlist(principal: Reader) -> AllowlistResponse:
    try:
        rows = (database.get_supabase().table("dlp_allowlist").select("fingerprint")
                .eq("org_id", str(principal.org_id)).limit(10000).execute().data)
    except (httpx.HTTPError, RuntimeError) as exc:
        logger.error("Allowlist read failed: %s", exc)
        raise HTTPException(status_code=503, detail="Allowlist storage is unavailable") from exc
    return AllowlistResponse(fingerprints=sorted({r["fingerprint"] for r in rows if _FINGERPRINT.match(r["fingerprint"])}))


@router.post("", response_model=AllowlistResponse, status_code=201)
def add_fingerprint(entry: AllowlistEntry, principal: Writer) -> AllowlistResponse:
    client = database.get_authenticated_supabase(principal.access_token)
    try:
        client.table("dlp_allowlist").insert({
            "org_id": str(principal.org_id), "fingerprint": entry.fingerprint,
            "reason": entry.reason, "created_by": str(principal.user_id),
        }).execute()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 409:  # already approved is fine
            raise HTTPException(status_code=503, detail="Allowlist storage is unavailable") from exc
    except (httpx.HTTPError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Allowlist storage is unavailable") from exc
    return read_allowlist(principal)


@router.delete("/{fingerprint}", response_model=AllowlistResponse)
def remove_fingerprint(fingerprint: str, principal: Writer) -> AllowlistResponse:
    if not _FINGERPRINT.match(fingerprint):
        raise HTTPException(status_code=422, detail="Fingerprint must be 16 lowercase hex characters")
    client = database.get_authenticated_supabase(principal.access_token)
    try:
        client.table("dlp_allowlist").eq("org_id", str(principal.org_id)).eq("fingerprint", fingerprint).delete().execute()
    except (httpx.HTTPError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Allowlist storage is unavailable") from exc
    return read_allowlist(principal)
