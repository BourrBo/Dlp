"""Tenant-scoped exact-match P06 suppressions with mandatory expiry."""

import re
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import insert, select, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session

from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.clock import SystemClock
from dlp_platform.policy.admin_audit import record_admin_change
from dlp_platform.routes.p06_support import (
    SessionDependency,
    member_id,
    rate_limit_p06,
    require_read,
    require_write,
)
from dlp_platform.tables import SUPPRESSIONS

router = APIRouter(
    prefix="/suppressions", tags=["suppressions"], dependencies=[Depends(rate_limit_p06)]
)


class SuppressionWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    match: dict[str, str] = Field(min_length=1, max_length=1)
    reason: str = Field(min_length=1, max_length=500)
    expires_at: datetime
    enabled: bool = True

    @field_validator("match")
    @classmethod
    def validate_match(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) != 1:
            raise ValueError("Exactly one suppression match key is required")
        key, pattern = next(iter(value.items()))
        if key == "fingerprint":
            if not re.fullmatch(r"[a-fA-F0-9]{64}", pattern):
                raise ValueError("fingerprint must be a 64-character hexadecimal HMAC")
        elif key == "path":
            if not pattern or len(pattern) > 2048 or "\x00" in pattern:
                raise ValueError("path must be a non-empty exact path")
        elif key == "pattern":
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", pattern):
                raise ValueError("pattern must be an exact detector identifier")
        else:
            raise ValueError("match key must be fingerprint, path, or pattern")
        return value

    @field_validator("reason")
    @classmethod
    def nonblank_reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Reason is required")
        return value.strip()


class SuppressionRead(BaseModel):
    suppression_id: UUID
    organization_id: UUID
    match: dict[str, str]
    reason: str
    created_by: str
    updated_by: str
    enabled: bool
    expires_at: datetime
    created_at: datetime
    updated_at: datetime


def _now(request: Request) -> datetime:
    clock = getattr(request.app.state, "p06_clock", None) or SystemClock()
    return clock.now()


def _valid_expiration(value: datetime, request: Request) -> None:
    if value.tzinfo is None or value.utcoffset() is None or value <= _now(request):
        raise HTTPException(
            status_code=422, detail="expires_at must be a future timezone-aware value"
        )


def _row(row: RowMapping | dict[str, Any]) -> SuppressionRead:
    data = dict(row)
    return SuppressionRead(
        suppression_id=UUID(data["id"]),
        organization_id=UUID(data["org_id"]),
        match=data["match"],
        reason=data["reason"],
        created_by=data["created_by"],
        updated_by=data["updated_by"],
        enabled=data["enabled"],
        expires_at=data["expires_at"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


def _get_owned(session: Session, suppression_id: UUID, organization_id: UUID) -> RowMapping:
    row = (
        session.execute(
            select(SUPPRESSIONS).where(
                SUPPRESSIONS.c.id == str(suppression_id),
                SUPPRESSIONS.c.org_id == str(organization_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Suppression not found")
    return row


@router.get("", response_model=list[SuppressionRead])
def list_suppressions(
    principal: CurrentPrincipal, session: SessionDependency
) -> list[SuppressionRead]:
    require_read(principal)
    rows = (
        session.execute(
            select(SUPPRESSIONS)
            .where(SUPPRESSIONS.c.org_id == str(principal.organization_id))
            .order_by(SUPPRESSIONS.c.expires_at, SUPPRESSIONS.c.id)
        )
        .mappings()
        .all()
    )
    return [_row(row) for row in rows]


@router.post("", response_model=SuppressionRead, status_code=status.HTTP_201_CREATED)
def create_suppression(
    body: SuppressionWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> SuppressionRead:
    require_write(principal)
    _valid_expiration(body.expires_at, request)
    actor, now, suppression_id = member_id(session, principal), _now(request), uuid4()
    values = {
        "id": str(suppression_id),
        "org_id": str(principal.organization_id),
        "match": body.match,
        "reason": body.reason,
        "created_by": actor,
        "updated_by": actor,
        "enabled": body.enabled,
        "expires_at": body.expires_at,
        "created_at": now,
        "updated_at": now,
    }
    try:
        session.execute(insert(SUPPRESSIONS).values(**values))
        record_admin_change(
            session,
            request,
            principal,
            resource="suppression",
            resource_id=str(suppression_id),
            operation="create",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Suppression could not be created") from exc
    return _row(values)


@router.get("/{suppression_id}", response_model=SuppressionRead)
def get_suppression(
    suppression_id: UUID, principal: CurrentPrincipal, session: SessionDependency
) -> SuppressionRead:
    require_read(principal)
    return _row(_get_owned(session, suppression_id, principal.organization_id))


@router.put("/{suppression_id}", response_model=SuppressionRead)
def update_suppression(
    suppression_id: UUID,
    body: SuppressionWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> SuppressionRead:
    require_write(principal)
    current = dict(_get_owned(session, suppression_id, principal.organization_id))
    _valid_expiration(body.expires_at, request)
    actor, now = member_id(session, principal), _now(request)
    values = {
        "match": body.match,
        "reason": body.reason,
        "updated_by": actor,
        "enabled": body.enabled,
        "expires_at": body.expires_at,
        "updated_at": now,
    }
    try:
        session.execute(
            update(SUPPRESSIONS)
            .where(
                SUPPRESSIONS.c.id == str(suppression_id),
                SUPPRESSIONS.c.org_id == str(principal.organization_id),
            )
            .values(**values)
        )
        record_admin_change(
            session,
            request,
            principal,
            resource="suppression",
            resource_id=str(suppression_id),
            operation="update",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Suppression could not be updated") from exc
    return _row({**current, **values})


@router.delete("/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_suppression(
    suppression_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    require_write(principal)
    _get_owned(session, suppression_id, principal.organization_id)
    actor, now = member_id(session, principal), _now(request)
    record_admin_change(
        session,
        request,
        principal,
        resource="suppression",
        resource_id=str(suppression_id),
        operation="revoke",
    )
    session.execute(
        update(SUPPRESSIONS)
        .where(
            SUPPRESSIONS.c.id == str(suppression_id),
            SUPPRESSIONS.c.org_id == str(principal.organization_id),
        )
        .values(enabled=False, updated_by=actor, updated_at=now)
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
