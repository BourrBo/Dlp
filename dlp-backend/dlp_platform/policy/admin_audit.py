"""Adapter from existing P05/P06 admin mutations to the P10 audit service."""

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from dlp_platform.audit.service import (
    AuditContext,
    AuditPersistenceError,
    AuditService,
    context_from_request,
)
from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.contracts.principal import Principal

_ACTIONS: dict[tuple[str, str], AuditAction] = {
    ("policy", "create"): AuditAction.POLICY_CREATED,
    ("policy", "update"): AuditAction.POLICY_UPDATED,
    ("policy", "disable"): AuditAction.POLICY_DELETED,
    ("policy", "rollback"): AuditAction.POLICY_ROLLED_BACK,
    ("exception", "create"): AuditAction.EXCEPTION_CREATED,
    ("exception", "update"): AuditAction.EXCEPTION_UPDATED,
    ("exception", "revoke"): AuditAction.EXCEPTION_REVOKED,
    ("suppression", "create"): AuditAction.SUPPRESSION_CREATED,
    ("suppression", "update"): AuditAction.SUPPRESSION_UPDATED,
    ("suppression", "revoke"): AuditAction.SUPPRESSION_REVOKED,
    ("destination", "create"): AuditAction.DESTINATION_CREATED,
    ("destination", "update"): AuditAction.DESTINATION_UPDATED,
    ("destination", "delete"): AuditAction.DESTINATION_DELETED,
}


def record_admin_change(
    session: Session,
    request: Request,
    principal: Principal,
    *,
    resource: str,
    resource_id: str,
    operation: str,
) -> None:
    """Append a safe event within the caller's business transaction."""
    action = _ACTIONS.get((resource, operation))
    if action is None:
        raise HTTPException(status_code=503, detail="Audit event unavailable")
    context: AuditContext = context_from_request(request)
    try:
        AuditService().record_event(
            session,
            principal,
            action=action,
            resource_type=resource,
            resource_id=resource_id,
            context=context,
        )
    except (AuditPersistenceError, ValueError):
        session.rollback()
        raise HTTPException(status_code=503, detail="Audit event unavailable") from None
