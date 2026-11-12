"""P07 tenant-scoped action and approval APIs."""

from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import CursorResult, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from dlp_platform.actions.interfaces import ActionExecutor, UnavailableActionExecutor
from dlp_platform.approvals.models import ActionView, ApprovalCreate, ApprovalDecision, ApprovalView
from dlp_platform.approvals.notifier_interface import ApprovalNotifier, UnconfiguredApprovalNotifier
from dlp_platform.approvals.state_machine import decide, refreshed_state
from dlp_platform.approvals.validation import safe_justification
from dlp_platform.audit.service import AuditService, context_from_request
from dlp_platform.auth.permissions import require_permission, require_role
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.common import Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter
from dlp_platform.routes.p06_support import member_id
from dlp_platform.tables import ACTIONS, APPROVALS, POLICIES

router = APIRouter(tags=["actions and approvals"])
SessionDependency = Annotated[Session, Depends(get_session)]
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]
_executor: ActionExecutor = UnavailableActionExecutor()
_notifier: ApprovalNotifier = UnconfiguredApprovalNotifier()
_EXPIRY = timedelta(hours=24)
_ESCALATION = timedelta(hours=12)


def configure_action_executor(executor: ActionExecutor) -> None:
    """Install an executor supplied by a future connector integration."""
    global _executor
    _executor = executor


def configure_approval_notifier(notifier: ApprovalNotifier) -> None:
    """Install a P4-owned notification handoff without adding a P07 sender."""
    global _notifier
    _notifier = notifier


def _limit(request: Request, principal: Principal, limiter: RateLimiter) -> None:
    identity = str(getattr(request.state, "rate_limit_identity", principal.subject_id))
    result = limiter.check(identity, str(principal.organization_id))
    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(result.retry_after)},
        )


def _refresh(
    session: Session,
    approval: dict[str, Any],
    now: datetime,
    principal: Principal,
    request: Request,
) -> dict[str, Any]:
    expires_at = approval["expires_at"]
    created_at = approval["created_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=now.tzinfo)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=now.tzinfo)
    state = refreshed_state(str(approval["status"]), expires_at, now)
    if state != approval["status"]:
        changed = cast(
            CursorResult[Any],
            session.execute(
                APPROVALS.update()
                .where(
                    APPROVALS.c.id == approval["id"],
                    APPROVALS.c.status.in_(("pending", "escalated")),
                )
                .values(status=state)
            ),
        )
        if changed.rowcount == 1:
            session.execute(
                ACTIONS.update()
                .where(ACTIONS.c.id == approval["action_id"])
                .values(status="expired", updated_at=now)
            )
            approval["status"] = state
            if state == "expired":
                AuditService().record_event(
                    session,
                    principal,
                    action=AuditAction.APPROVAL_EXPIRED,
                    resource_type="approval",
                    resource_id=str(approval["id"]),
                    metadata={"action_id": str(approval["action_id"])},
                    context=context_from_request(request),
                )
        else:
            approval["status"] = session.execute(
                select(APPROVALS.c.status).where(APPROVALS.c.id == approval["id"])
            ).scalar_one()
    elif state == "pending" and created_at + _ESCALATION <= now:
        changed = cast(
            CursorResult[Any],
            session.execute(
                APPROVALS.update()
                .where(APPROVALS.c.id == approval["id"], APPROVALS.c.status == "pending")
                .values(status="escalated", escalated_at=now)
            ),
        )
        if changed.rowcount == 1:
            approval["status"] = "escalated"
            with suppress(Exception):
                _notifier.notify_approvers(str(approval["org_id"]), str(approval["id"]))
        else:
            approval["status"] = session.execute(
                select(APPROVALS.c.status).where(APPROVALS.c.id == approval["id"])
            ).scalar_one()
    return approval


def _view(session: Session, row: dict[str, Any]) -> ApprovalView:
    action = (
        session.execute(
            ACTIONS.select().where(
                ACTIONS.c.id == row["action_id"], ACTIONS.c.org_id == row["org_id"]
            )
        )
        .mappings()
        .one()
    )
    return ApprovalView(
        approval_id=UUID(str(row["id"])),
        action_id=UUID(str(action["id"])),
        request_id=UUID(str(action["request_id"])),
        action=str(action["action"]),
        action_status=str(action["status"]),
        status=str(row["status"]),
        justification=str(row["justification"]),
        requested_by=str(row["requested_by"]),
        expires_at=row["expires_at"],
        decided_by=str(row["decided_by"]) if row["decided_by"] else None,
        decision_reason=str(row["decision_reason"]) if row["decision_reason"] else None,
        created_at=row["created_at"],
        decided_at=row["decided_at"],
    )


@router.post("/approvals", response_model=ApprovalView, status_code=status.HTTP_201_CREATED)
def create_approval(
    payload: ApprovalCreate,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
) -> ApprovalView:
    require_permission(principal, Permission.SCAN_REQUEST)
    _limit(request, principal, limiter)
    try:
        justification = safe_justification(payload.justification)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Justification is not safe") from exc
    if not justification:
        raise HTTPException(status_code=422, detail="Justification must not be blank")
    org_id = str(principal.organization_id)
    policy_version = payload.policy_version
    if payload.policy_id is None and policy_version is not None:
        raise HTTPException(status_code=422, detail="Policy version requires a policy ID")
    if payload.action == "user_override" and payload.policy_id is None:
        raise HTTPException(status_code=422, detail="User overrides require a policy reference")
    if payload.policy_id is not None:
        policy = session.execute(
            select(POLICIES.c.id, POLICIES.c.version).where(
                POLICIES.c.id == str(payload.policy_id), POLICIES.c.org_id == org_id
            )
        ).one_or_none()
        if policy is None:
            raise HTTPException(status_code=404, detail="Policy not found")
        if policy_version is not None and policy_version != policy.version:
            raise HTTPException(status_code=409, detail="Policy version has changed")
        policy_version = policy.version
    requester_id = member_id(session, principal)
    now = datetime.now(UTC)
    action_id = uuid5(NAMESPACE_URL, f"dlp-p07:{org_id}:{payload.request_id}:{payload.action}")
    approval_id = uuid5(NAMESPACE_URL, f"dlp-p07-approval:{action_id}")
    action_status = "pending_approval"
    metadata = {"policy_id": str(payload.policy_id)} if payload.policy_id else {}
    insert = (
        pg_insert if session.bind and session.bind.dialect.name == "postgresql" else sqlite_insert
    )
    action_insert = cast(
        CursorResult[Any],
        session.execute(
            insert(ACTIONS)
            .values(
                id=str(action_id),
                org_id=org_id,
                request_id=str(payload.request_id),
                policy_id=str(payload.policy_id) if payload.policy_id else None,
                policy_version=policy_version,
                requested_by=requester_id,
                action=payload.action,
                status=action_status,
                justification=justification,
                metadata=metadata,
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_nothing(index_elements=["org_id", "request_id", "action"])
        ),
    )
    existing_action = session.execute(
        select(ACTIONS.c.id, ACTIONS.c.requested_by).where(
            ACTIONS.c.org_id == org_id,
            ACTIONS.c.request_id == str(payload.request_id),
            ACTIONS.c.action == payload.action,
        )
    ).one()
    if str(existing_action.requested_by) != requester_id:
        raise HTTPException(
            status_code=409, detail="Request ID already belongs to another requester"
        )
    actual_action_id = existing_action.id
    if str(actual_action_id) != str(action_id):
        action_id = UUID(str(actual_action_id))
        approval_id = uuid5(NAMESPACE_URL, f"dlp-p07-approval:{action_id}")
    approval_insert = cast(
        CursorResult[Any],
        session.execute(
            insert(APPROVALS)
            .values(
                id=str(approval_id),
                org_id=org_id,
                action_id=str(action_id),
                requested_by=requester_id,
                status="pending",
                justification=justification,
                expires_at=now + _EXPIRY,
                created_at=now,
            )
            .on_conflict_do_nothing(index_elements=["action_id"])
        ),
    )
    row = (
        session.execute(
            APPROVALS.select().where(
                APPROVALS.c.action_id == str(action_id), APPROVALS.c.org_id == org_id
            )
        )
        .mappings()
        .one()
    )
    view = _view(session, dict(row))
    if action_insert.rowcount == 1 and approval_insert.rowcount == 1:
        AuditService().record_event(
            session,
            principal,
            action=AuditAction.APPROVAL_REQUESTED,
            resource_type="approval",
            resource_id=str(row["id"]),
            metadata={"action_id": str(action_id)},
            context=context_from_request(request),
        )
    session.commit()
    if action_insert.rowcount == 1 and approval_insert.rowcount == 1:
        with suppress(Exception):
            _notifier.notify_approvers(org_id, str(row["id"]))
    return view


@router.get("/approvals", response_model=list[ApprovalView])
def list_approvals(
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
) -> list[ApprovalView]:
    require_permission(principal, Permission.IDENTITY_READ)
    _limit(request, principal, limiter)
    now = datetime.now(UTC)
    rows = (
        session.execute(
            APPROVALS.select()
            .where(APPROVALS.c.org_id == str(principal.organization_id))
            .order_by(APPROVALS.c.created_at.desc())
            .limit(500)
        )
        .mappings()
        .all()
    )
    results = [
        _view(session, _refresh(session, dict(row), now, principal, request)) for row in rows
    ]
    session.commit()
    return results


@router.get("/approvals/{approval_id}", response_model=ApprovalView)
def get_approval(
    approval_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
) -> ApprovalView:
    require_permission(principal, Permission.IDENTITY_READ)
    _limit(request, principal, limiter)
    row = (
        session.execute(
            APPROVALS.select().where(
                APPROVALS.c.id == str(approval_id),
                APPROVALS.c.org_id == str(principal.organization_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    view = _view(session, _refresh(session, dict(row), datetime.now(UTC), principal, request))
    session.commit()
    return view


def _decide(
    approval_id: UUID,
    choice: Literal["approved", "rejected"],
    payload: ApprovalDecision,
    request: Request,
    principal: Principal,
    session: Session,
) -> ApprovalView:
    require_permission(principal, Permission.APPROVALS_DECIDE)
    require_role(principal, Role.OWNER, Role.ADMIN)
    org_id = str(principal.organization_id)
    row = (
        session.execute(
            APPROVALS.select()
            .where(APPROVALS.c.id == str(approval_id), APPROVALS.c.org_id == org_id)
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    row_data = _refresh(session, dict(row), datetime.now(UTC), principal, request)
    if row_data["status"] == "expired":
        session.commit()
        raise HTTPException(status_code=409, detail="Approval has expired")
    requester = str(row_data["requested_by"])
    approver = member_id(session, principal)
    if requester == approver:
        raise HTTPException(status_code=403, detail="Requesters cannot approve their own requests")
    try:
        next_state = decide(str(row_data["status"]), choice)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Approval is no longer pending") from exc
    now = datetime.now(UTC)
    try:
        reason = safe_justification(payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Decision reason is not safe") from exc
    session.execute(
        APPROVALS.update()
        .where(APPROVALS.c.id == str(approval_id))
        .values(status=next_state, decided_by=approver, decision_reason=reason, decided_at=now)
    )
    action = (
        session.execute(
            ACTIONS.select().where(
                ACTIONS.c.id == row_data["action_id"], ACTIONS.c.org_id == org_id
            )
        )
        .mappings()
        .one()
    )
    action_state = "rejected" if choice == "rejected" else "approved"
    action_attempted = False
    if choice == "approved" and action["action"] not in {"user_override", "require_approval"}:
        action_attempted = True
        try:
            execution = _executor.execute(
                str(action["id"]), action["action"], dict(action["metadata"])
            )
            action_state = execution.status
        except Exception:
            action_state = "failed"
        if action_state not in {
            "pending_executor",
            "succeeded",
            "failed",
            "executing",
            "cancelled",
        }:
            action_state = "failed"
    session.execute(
        ACTIONS.update()
        .where(ACTIONS.c.id == row_data["action_id"])
        .values(status=action_state, updated_at=now)
    )
    result = dict(row_data)
    result.update(status=next_state, decided_by=approver, decision_reason=reason, decided_at=now)
    view = _view(session, result)
    AuditService().record_event(
        session,
        principal,
        action=(
            AuditAction.APPROVAL_APPROVED if choice == "approved" else AuditAction.APPROVAL_REJECTED
        ),
        resource_type="approval",
        resource_id=str(approval_id),
        metadata={"action_id": str(row_data["action_id"]), "result": action_state},
        context=context_from_request(request),
    )
    if action_attempted:
        AuditService().record_event(
            session,
            principal,
            action=(
                AuditAction.ACTION_EXECUTED
                if action_state in {"succeeded", "failed", "cancelled"}
                else AuditAction.ACTION_REQUESTED
            ),
            resource_type="action",
            resource_id=str(row_data["action_id"]),
            outcome=(
                AuditOutcome.FAILURE
                if action_state in {"failed", "cancelled"}
                else AuditOutcome.SUCCESS
            ),
            metadata={"result": action_state},
            context=context_from_request(request),
        )
    session.commit()
    return view


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalView)
def approve(
    approval_id: UUID,
    payload: ApprovalDecision,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
) -> ApprovalView:
    _limit(request, principal, limiter)
    return _decide(approval_id, "approved", payload, request, principal, session)


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalView)
def reject(
    approval_id: UUID,
    payload: ApprovalDecision,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
) -> ApprovalView:
    _limit(request, principal, limiter)
    return _decide(approval_id, "rejected", payload, request, principal, session)


@router.post("/approvals/{approval_id}/cancel", response_model=ApprovalView)
def cancel(
    approval_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
) -> ApprovalView:
    _limit(request, principal, limiter)
    org_id = str(principal.organization_id)
    row = (
        session.execute(
            APPROVALS.select()
            .where(APPROVALS.c.id == str(approval_id), APPROVALS.c.org_id == org_id)
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    row_data = _refresh(session, dict(row), datetime.now(UTC), principal, request)
    if row_data["status"] == "expired":
        session.commit()
        raise HTTPException(status_code=409, detail="Approval has expired")
    requester = member_id(session, principal)
    if requester != str(row_data["requested_by"]):
        require_permission(principal, Permission.APPROVALS_DECIDE)
    if row_data["status"] not in {"pending", "escalated"}:
        raise HTTPException(status_code=409, detail="Approval is no longer pending")
    now = datetime.now(UTC)
    session.execute(
        APPROVALS.update().where(APPROVALS.c.id == str(approval_id)).values(status="cancelled")
    )
    session.execute(
        ACTIONS.update()
        .where(ACTIONS.c.id == row_data["action_id"])
        .values(status="cancelled", updated_at=now)
    )
    row_data["status"] = "cancelled"
    view = _view(session, row_data)
    AuditService().record_event(
        session,
        principal,
        action=AuditAction.APPROVAL_CANCELLED,
        resource_type="approval",
        resource_id=str(approval_id),
        context=context_from_request(request),
    )
    session.commit()
    return view


@router.get("/actions", response_model=list[ActionView])
def list_actions(
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
) -> list[ActionView]:
    require_permission(principal, Permission.IDENTITY_READ)
    _limit(request, principal, limiter)
    rows = (
        session.execute(
            ACTIONS.select()
            .where(ACTIONS.c.org_id == str(principal.organization_id))
            .order_by(ACTIONS.c.created_at.desc())
            .limit(500)
        )
        .mappings()
        .all()
    )
    return [
        ActionView(
            action_id=UUID(str(row["id"])),
            request_id=UUID(str(row["request_id"])),
            policy_id=UUID(str(row["policy_id"])) if row["policy_id"] else None,
            policy_version=int(row["policy_version"]) if row["policy_version"] else None,
            action=str(row["action"]),
            status=str(row["status"]),
            justification=str(row["justification"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in rows
    ]
