"""Tenant-scoped read-only audit query API."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from dlp_platform.audit.service import (
    MAX_CHAIN_VERIFICATION_EVENTS,
    AuditPersistenceError,
    AuditService,
    AuditVerificationLimitError,
)
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.audit_event import AuditAction, AuditEvent, AuditOutcome
from dlp_platform.database import get_session

router = APIRouter(prefix="/audit/events", tags=["audit"])
SessionDependency = Annotated[Session, Depends(get_session)]
_audit = AuditService()


@router.get("", response_model=list[AuditEvent])
def list_audit_events(
    principal: CurrentPrincipal,
    session: SessionDependency,
    action: AuditAction | None = None,
    actor_id: Annotated[str | None, Query(max_length=256)] = None,
    resource_type: Annotated[str | None, Query(max_length=64)] = None,
    resource_id: Annotated[str | None, Query(max_length=256)] = None,
    outcome: AuditOutcome | None = None,
    correlation_id: UUID | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> list[AuditEvent]:
    require_permission(principal, Permission.AUDIT_READ)
    if from_time is not None and (from_time.tzinfo is None or from_time.utcoffset() is None):
        raise HTTPException(status_code=422, detail="from_time must include a timezone")
    if to_time is not None and (to_time.tzinfo is None or to_time.utcoffset() is None):
        raise HTTPException(status_code=422, detail="to_time must include a timezone")
    if from_time is not None and to_time is not None and from_time > to_time:
        raise HTTPException(status_code=422, detail="Invalid time range")
    try:
        return _audit.list_events(
            session,
            principal.organization_id,
            action=action,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            correlation_id=correlation_id,
            from_time=from_time,
            to_time=to_time,
            limit=limit,
            offset=offset,
        )
    except AuditPersistenceError:
        raise HTTPException(status_code=503, detail="Audit events unavailable") from None


@router.get("/verify-chain")
def verify_audit_chain(
    principal: CurrentPrincipal, session: SessionDependency
) -> dict[str, object]:
    """Run a bounded, tenant-scoped online integrity check without writing an event."""
    require_permission(principal, Permission.AUDIT_READ)
    try:
        result = _audit.verify_chain_result(
            session,
            principal.organization_id,
            max_events=MAX_CHAIN_VERIFICATION_EVENTS,
        )
    except AuditVerificationLimitError:
        raise HTTPException(
            status_code=413,
            detail="Audit chain exceeds the online verification limit",
        ) from None
    except AuditPersistenceError:
        raise HTTPException(status_code=503, detail="Audit chain unavailable") from None
    return {
        "valid": result.valid,
        "checked_events": result.checked_events,
        "checked_at": datetime.now(UTC),
        "online_limit": MAX_CHAIN_VERIFICATION_EVENTS,
    }
