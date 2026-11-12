import logging
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.auth import AuthenticatedPrincipal, get_current_principal
from app.database import get_authenticated_supabase
from app.models.persisted_finding import FindingStatus, PersistedFinding

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])
logger = logging.getLogger(__name__)
Principal = Annotated[AuthenticatedPrincipal, Depends(get_current_principal)]


class FindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus | None = None
    owner: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _non_empty(self) -> "FindingUpdate":
        if not self.model_fields_set:
            raise ValueError("Provide at least one of status, owner or notes")
        if "status" in self.model_fields_set and self.status is None:
            raise ValueError("status cannot be null")
        return self


def _query(principal: AuthenticatedPrincipal):
    return (
        get_authenticated_supabase(principal.access_token)
        .table("dlp_findings").select("*").eq("org_id", str(principal.org_id))
    )


def _db_error(exc: httpx.HTTPError):
    logger.error("Findings database request failed: %s", exc)
    raise HTTPException(status_code=503, detail="Finding storage is unavailable") from exc


@router.get("", response_model=list[PersistedFinding])
def list_findings(
    principal: Principal,
    status: FindingStatus | None = None,
    severity: str | None = Query(default=None, min_length=1, max_length=40),
    data_type: str | None = Query(default=None, min_length=1, max_length=60),
    source: str | None = Query(default=None, min_length=1, max_length=60),
    limit: int = Query(default=200, ge=1, le=500),
) -> list[PersistedFinding]:
    query = _query(principal).order("created_at", desc=True).limit(limit)
    for column, value in (("status", status.value if status else None), ("severity", severity),
                          ("data_type", data_type), ("source", source)):
        if value is not None:
            query = query.eq(column, value)
    try:
        return [PersistedFinding.model_validate(r) for r in query.execute().data]
    except httpx.HTTPError as exc:
        _db_error(exc)


@router.get("/{finding_id}", response_model=PersistedFinding)
def get_finding(finding_id: UUID, principal: Principal) -> PersistedFinding:
    try:
        rows = _query(principal).eq("id", str(finding_id)).limit(1).execute().data
    except httpx.HTTPError as exc:
        _db_error(exc)
    if not rows:
        raise HTTPException(status_code=404, detail="Finding not found")
    return PersistedFinding.model_validate(rows[0])


@router.patch("/{finding_id}", response_model=PersistedFinding)
def update_finding(finding_id: UUID, request: FindingUpdate, principal: Principal) -> PersistedFinding:
    changes = request.model_dump(exclude_unset=True, mode="json")
    try:
        if not _query(principal).eq("id", str(finding_id)).limit(1).execute().data:
            raise HTTPException(status_code=404, detail="Finding not found")
        rows = _query(principal).eq("id", str(finding_id)).update(
            {**changes, "updated_at": datetime.now(timezone.utc).isoformat()}
        ).execute().data
    except httpx.HTTPError as exc:
        _db_error(exc)
    if not rows:
        raise HTTPException(status_code=404, detail="Finding not found")
    return PersistedFinding.model_validate(rows[0])
