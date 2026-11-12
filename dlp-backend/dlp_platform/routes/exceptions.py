"""Tenant-scoped, time-limited P06 policy exceptions."""

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
from dlp_platform.policy.models import ConditionValue, validate_conditions
from dlp_platform.routes.p06_support import (
    SessionDependency,
    member_id,
    owned_policy_exists,
    rate_limit_p06,
    require_read,
    require_write,
)
from dlp_platform.tables import EXCEPTIONS

router = APIRouter(
    prefix="/exceptions", tags=["policy exceptions"], dependencies=[Depends(rate_limit_p06)]
)
Member = CurrentPrincipal


class ExceptionWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: UUID
    scope: dict[str, ConditionValue] = Field(min_length=1, max_length=7)
    reason: str = Field(min_length=1, max_length=500)
    expires_at: datetime
    enabled: bool = True

    @field_validator("scope")
    @classmethod
    def valid_scope(cls, value: dict[str, ConditionValue]) -> dict[str, ConditionValue]:
        try:
            validate_conditions(value)
        except ValueError as exc:
            raise ValueError("Invalid exception scope") from exc
        if not value:
            raise ValueError("Exception scope must be narrow and non-empty")
        return value

    @field_validator("reason")
    @classmethod
    def nonblank_reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Reason is required")
        return value.strip()


class ExceptionRead(BaseModel):
    exception_id: UUID
    organization_id: UUID
    policy_id: UUID
    scope: dict[str, Any]
    reason: str
    approver_id: str
    created_by: str
    updated_by: str
    enabled: bool
    expires_at: datetime
    created_at: datetime
    updated_at: datetime


def _now(request: Request) -> datetime:
    clock = getattr(request.app.state, "p06_clock", None) or SystemClock()
    return clock.now()


def _row(row: RowMapping | dict[str, Any]) -> ExceptionRead:
    data = dict(row)
    return ExceptionRead(
        exception_id=UUID(data["id"]),
        organization_id=UUID(data["org_id"]),
        policy_id=UUID(data["policy_id"]),
        scope=data["scope"],
        reason=data["reason"],
        approver_id=data["approver_id"],
        created_by=data["created_by"],
        updated_by=data["updated_by"],
        enabled=data["enabled"],
        expires_at=data["expires_at"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


def _valid_expiration(value: datetime, request: Request) -> None:
    if value.tzinfo is None or value.utcoffset() is None or value <= _now(request):
        raise HTTPException(
            status_code=422, detail="expires_at must be a future timezone-aware value"
        )


def _get_owned(session: Session, exception_id: UUID, organization_id: UUID) -> RowMapping:
    row = (
        session.execute(
            select(EXCEPTIONS).where(
                EXCEPTIONS.c.id == str(exception_id),
                EXCEPTIONS.c.org_id == str(organization_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    return row


@router.get("", response_model=list[ExceptionRead])
def list_exceptions(principal: Member, session: SessionDependency) -> list[ExceptionRead]:
    require_read(principal)
    rows = (
        session.execute(
            select(EXCEPTIONS)
            .where(EXCEPTIONS.c.org_id == str(principal.organization_id))
            .order_by(EXCEPTIONS.c.expires_at, EXCEPTIONS.c.id)
        )
        .mappings()
        .all()
    )
    return [_row(row) for row in rows]


@router.post("", response_model=ExceptionRead, status_code=status.HTTP_201_CREATED)
def create_exception(
    body: ExceptionWrite,
    request: Request,
    principal: Member,
    session: SessionDependency,
) -> ExceptionRead:
    require_write(principal)
    _valid_expiration(body.expires_at, request)
    if not owned_policy_exists(session, body.policy_id, principal.organization_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    actor = member_id(session, principal)
    now, exception_id = _now(request), uuid4()
    values = {
        "id": str(exception_id),
        "org_id": str(principal.organization_id),
        "policy_id": str(body.policy_id),
        "scope": body.scope,
        "reason": body.reason,
        "approver_id": actor,
        "created_by": actor,
        "updated_by": actor,
        "enabled": body.enabled,
        "expires_at": body.expires_at,
        "created_at": now,
        "updated_at": now,
    }
    try:
        session.execute(insert(EXCEPTIONS).values(**values))
        record_admin_change(
            session,
            request,
            principal,
            resource="exception",
            resource_id=str(exception_id),
            operation="create",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Exception could not be created") from exc
    return _row(values)


@router.get("/{exception_id}", response_model=ExceptionRead)
def get_exception(
    exception_id: UUID, principal: Member, session: SessionDependency
) -> ExceptionRead:
    require_read(principal)
    return _row(_get_owned(session, exception_id, principal.organization_id))


@router.put("/{exception_id}", response_model=ExceptionRead)
def update_exception(
    exception_id: UUID,
    body: ExceptionWrite,
    request: Request,
    principal: Member,
    session: SessionDependency,
) -> ExceptionRead:
    require_write(principal)
    current = dict(_get_owned(session, exception_id, principal.organization_id))
    _valid_expiration(body.expires_at, request)
    if not owned_policy_exists(session, body.policy_id, principal.organization_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    now, actor = _now(request), member_id(session, principal)
    values = {
        "policy_id": str(body.policy_id),
        "scope": body.scope,
        "reason": body.reason,
        "approver_id": actor,
        "updated_by": actor,
        "enabled": body.enabled,
        "expires_at": body.expires_at,
        "updated_at": now,
    }
    try:
        session.execute(
            update(EXCEPTIONS)
            .where(
                EXCEPTIONS.c.id == str(exception_id),
                EXCEPTIONS.c.org_id == str(principal.organization_id),
            )
            .values(**values)
        )
        record_admin_change(
            session,
            request,
            principal,
            resource="exception",
            resource_id=str(exception_id),
            operation="update",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Exception could not be updated") from exc
    return _row({**current, **values})


@router.delete("/{exception_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_exception(
    exception_id: UUID,
    request: Request,
    principal: Member,
    session: SessionDependency,
) -> Response:
    require_write(principal)
    _get_owned(session, exception_id, principal.organization_id)
    actor, now = member_id(session, principal), _now(request)
    record_admin_change(
        session,
        request,
        principal,
        resource="exception",
        resource_id=str(exception_id),
        operation="revoke",
    )
    session.execute(
        update(EXCEPTIONS)
        .where(
            EXCEPTIONS.c.id == str(exception_id),
            EXCEPTIONS.c.org_id == str(principal.organization_id),
        )
        .values(enabled=False, updated_by=actor, updated_at=now)
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
