"""P14 retention, legal hold, organization deletion, and subject export APIs."""

from collections.abc import Callable
from typing import Annotated, ParamSpec, TypeVar
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from dlp_platform.audit.service import context_from_request
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.common import ActorType, ContractModel, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.lifecycle import service
from dlp_platform.tables import MEMBERS, ORGANIZATIONS

router = APIRouter(tags=["data lifecycle"])
SessionDependency = Annotated[Session, Depends(get_session)]
P = ParamSpec("P")
T = TypeVar("T")


class RetentionWrite(ContractModel):
    retention_days: int = Field(ge=1, le=3650)
    enabled: bool


class HoldWrite(ContractModel):
    name: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=1, max_length=1000)
    scope_category: str | None = None


class HoldRelease(ContractModel):
    release_reason: str = Field(min_length=1, max_length=1000)


class DeleteConfirmation(ContractModel):
    confirmation_name: str = Field(min_length=1, max_length=255)


def _interactive(principal: Principal) -> None:
    if (
        principal.actor_type is not ActorType.USER
        or principal.member_id is None
        or principal.session_id is None
    ):
        raise HTTPException(status_code=403, detail="Interactive user session required")


def _admin(principal: Principal, permission: Permission) -> None:
    _interactive(principal)
    require_permission(principal, permission)
    if principal.role not in {Role.OWNER, Role.ADMIN}:
        raise HTTPException(status_code=403, detail="Forbidden")


def _invoke(call: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    try:
        return call(*args, **kwargs)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except service.LifecycleError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


def _name(session: Session, organization_id: UUID) -> str:
    name = session.execute(
        select(ORGANIZATIONS.c.name).where(ORGANIZATIONS.c.id == str(organization_id))
    ).scalar_one_or_none()
    if name is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return str(name)


@router.get("/organizations/current/retention")
def get_retention(
    principal: CurrentPrincipal, session: SessionDependency
) -> list[dict[str, object]]:
    _admin(principal, Permission.DATA_LIFECYCLE_READ)
    return service.retention_settings(session, principal.organization_id)


@router.put("/organizations/current/retention/{category}")
def put_retention(
    category: str,
    body: RetentionWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _admin(principal, Permission.DATA_LIFECYCLE_WRITE)
    return _invoke(
        service.save_retention_policy,
        session,
        principal,
        category=category,
        retention_days=body.retention_days,
        enabled=body.enabled,
        context=context_from_request(request),
    )


@router.post("/organizations/current/retention/{category}/run")
def run_retention(
    category: str,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limit: int = 500,
) -> dict[str, object]:
    _admin(principal, Permission.DATA_LIFECYCLE_WRITE)
    return _invoke(
        service.run_retention_batch,
        session,
        principal,
        category=category,
        limit=limit,
        context=context_from_request(request),
    )


@router.get("/organizations/current/legal-holds")
def get_holds(principal: CurrentPrincipal, session: SessionDependency) -> list[dict[str, object]]:
    _admin(principal, Permission.DATA_LIFECYCLE_READ)
    return service.list_legal_holds(session, principal.organization_id)


@router.post("/organizations/current/legal-holds", status_code=201)
def post_hold(
    body: HoldWrite, request: Request, principal: CurrentPrincipal, session: SessionDependency
) -> dict[str, object]:
    _admin(principal, Permission.DATA_LIFECYCLE_WRITE)
    return _invoke(
        service.create_legal_hold,
        session,
        principal,
        name=body.name,
        reason=body.reason,
        scope_category=body.scope_category,
        context=context_from_request(request),
    )


@router.post("/organizations/current/legal-holds/{hold_id}/release")
def release_hold(
    hold_id: UUID,
    body: HoldRelease,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _admin(principal, Permission.DATA_LIFECYCLE_WRITE)
    return _invoke(
        service.release_legal_hold,
        session,
        principal,
        hold_id=hold_id,
        release_reason=body.release_reason,
        context=context_from_request(request),
    )


@router.get("/organizations/current/deletion")
def get_deletion(principal: CurrentPrincipal, session: SessionDependency) -> dict[str, object]:
    _admin(principal, Permission.ORGANIZATION_DELETE)
    return {
        **service.deletion_status(session, principal.organization_id),
        "organization_name": _name(session, principal.organization_id),
        "active_legal_holds": service.active_hold_count(session, principal.organization_id),
    }


@router.post("/organizations/current/deletion-requests", status_code=201)
def request_deletion(
    body: DeleteConfirmation,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _admin(principal, Permission.ORGANIZATION_DELETE)
    return _invoke(
        service.request_organization_deletion,
        session,
        principal,
        confirmation_name=body.confirmation_name,
        actual_name=_name(session, principal.organization_id),
        context=context_from_request(request),
    )


@router.post("/organizations/current/deletion/confirm")
def confirm_deletion(
    body: DeleteConfirmation,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _admin(principal, Permission.ORGANIZATION_DELETE)
    return _invoke(
        service.confirm_organization_deletion,
        session,
        principal,
        confirmation_name=body.confirmation_name,
        actual_name=_name(session, principal.organization_id),
        context=context_from_request(request),
    )


@router.post("/organizations/current/deletion/execute")
def execute_deletion(
    request: Request, principal: CurrentPrincipal, session: SessionDependency, max_batches: int = 20
) -> dict[str, object]:
    _admin(principal, Permission.ORGANIZATION_DELETE)
    return _invoke(
        service.execute_organization_deletion,
        session,
        principal,
        max_batches=max_batches,
        context=context_from_request(request),
    )


def _export(
    session: Session, request: Request, principal: Principal, member_id: UUID
) -> dict[str, object]:
    subject = session.execute(
        select(MEMBERS.c.auth_subject_id).where(
            MEMBERS.c.id == str(member_id),
            MEMBERS.c.organization_id == str(principal.organization_id),
        )
    ).scalar_one_or_none()
    if subject is None:
        raise HTTPException(status_code=404, detail="Subject not found")
    context = context_from_request(request)
    service.record_subject_export(
        session,
        principal,
        member_id=member_id,
        result="requested",
        context=context,
    )
    try:
        data = service.build_subject_export(
            session,
            organization_id=principal.organization_id,
            organization_name=_name(session, principal.organization_id),
            member_id=member_id,
            subject_id=str(subject),
        )
    except Exception:
        service.record_subject_export(
            session, principal, member_id=member_id, result="failed", context=context
        )
        raise HTTPException(
            status_code=503, detail="Subject export could not be completed"
        ) from None
    service.record_subject_export(
        session, principal, member_id=member_id, result="completed", context=context
    )
    return data


@router.post("/identity/export")
def export_self(
    request: Request, principal: CurrentPrincipal, session: SessionDependency
) -> dict[str, object]:
    _interactive(principal)
    if principal.member_id is None:
        raise HTTPException(status_code=403, detail="Membership required")
    return _export(session, request, principal, principal.member_id)


@router.post("/organizations/current/subjects/{member_id}/export")
def export_subject(
    member_id: UUID, request: Request, principal: CurrentPrincipal, session: SessionDependency
) -> dict[str, object]:
    _interactive(principal)
    if member_id != principal.member_id:
        _admin(principal, Permission.SUBJECT_DATA_EXPORT)
    return _export(session, request, principal, member_id)
