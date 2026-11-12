"""Interactive session, organization-context, and IP policy APIs."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy import delete, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditService, context_from_request
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import ROLE_PERMISSIONS, Permission
from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.contracts.common import ActorType, ContractModel, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.identity.network import parse_network
from dlp_platform.tables import (
    APP_SESSIONS,
    IP_ALLOWLIST_ENTRIES,
    IP_ALLOWLIST_SETTINGS,
    MEMBERS,
    ORGANIZATIONS,
)

router = APIRouter(tags=["identity"])
SessionDependency = Annotated[Session, Depends(get_session)]
_audit = AuditService()


class IPAllowlistUpdate(ContractModel):
    enabled: bool


class IPAllowlistEntryWrite(ContractModel):
    network: str = Field(min_length=1, max_length=50)
    label: str = Field(min_length=1, max_length=120)


def _interactive(principal: Principal) -> None:
    if (
        principal.actor_type is not ActorType.USER
        or principal.session_id is None
        or principal.member_id is None
    ):
        raise HTTPException(status_code=403, detail="Interactive user session required")


def _identity_admin(principal: Principal) -> None:
    _interactive(principal)
    require_permission(principal, Permission.IDENTITY_SECURITY_WRITE)
    if principal.role not in {Role.OWNER, Role.ADMIN}:
        raise HTTPException(status_code=403, detail="Forbidden")


def _record(
    session: Session,
    request: Request,
    principal: Principal,
    action: AuditAction,
    resource_type: str,
    resource_id: str,
    operation: str,
) -> None:
    _audit.record_event(
        session,
        principal,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata={"operation": operation},
        context=context_from_request(request),
    )


def _membership_rows(session: Session, principal: Principal) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            MEMBERS.c.id.label("member_id"),
            MEMBERS.c.organization_id,
            MEMBERS.c.role,
            MEMBERS.c.active,
            ORGANIZATIONS.c.name.label("organization_name"),
        )
        .join(ORGANIZATIONS, ORGANIZATIONS.c.id == MEMBERS.c.organization_id)
        .where(MEMBERS.c.auth_subject_id == principal.subject_id)
        .order_by(ORGANIZATIONS.c.name, MEMBERS.c.organization_id)
    ).mappings()
    return [dict(row) for row in rows]


@router.get("/identity/profile")
def profile(principal: CurrentPrincipal, session: SessionDependency) -> dict[str, object]:
    row = session.execute(
        select(
            MEMBERS.c.id,
            MEMBERS.c.email,
            MEMBERS.c.active,
            ORGANIZATIONS.c.name.label("organization_name"),
        )
        .join(ORGANIZATIONS, ORGANIZATIONS.c.id == MEMBERS.c.organization_id)
        .where(MEMBERS.c.id == str(principal.member_id))
    ).mappings().one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return {
        "member_id": row["id"],
        "subject_id": principal.subject_id,
        "email": row["email"],
        "active": row["active"],
        "organization_id": str(principal.organization_id),
        "organization_name": row["organization_name"],
        "role": principal.role.value,
        "auth_method": principal.auth_method.value,
    }


@router.get("/organizations")
def organizations(
    principal: CurrentPrincipal, session: SessionDependency
) -> list[dict[str, object]]:
    _interactive(principal)
    return [
        {
            "member_id": row["member_id"],
            "organization_id": row["organization_id"],
            "organization_name": row["organization_name"],
            "role": row["role"],
            "active": row["active"],
            "current": str(row["organization_id"]) == str(principal.organization_id),
        }
        for row in _membership_rows(session, principal)
    ]


@router.get("/organizations/current")
def current_organization(
    principal: CurrentPrincipal, session: SessionDependency
) -> dict[str, object]:
    row = session.execute(
        select(ORGANIZATIONS.c.id, ORGANIZATIONS.c.name).where(
            ORGANIZATIONS.c.id == str(principal.organization_id)
        )
    ).mappings().one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return {
        "organization_id": row["id"],
        "organization_name": row["name"],
        "member_id": str(principal.member_id) if principal.member_id else None,
        "role": principal.role.value,
    }


@router.post("/organizations/{organization_id}/switch")
def switch_organization(
    organization_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _interactive(principal)
    membership = session.execute(
        select(MEMBERS.c.id, MEMBERS.c.role, MEMBERS.c.active).where(
            MEMBERS.c.organization_id == str(organization_id),
            MEMBERS.c.auth_subject_id == principal.subject_id,
        )
    ).mappings().one_or_none()
    if membership is None or not membership["active"]:
        raise HTTPException(status_code=403, detail="Active organization membership required")
    changed = session.execute(
        update(APP_SESSIONS)
        .where(
            APP_SESSIONS.c.id == str(principal.session_id),
            APP_SESSIONS.c.member_id == str(principal.member_id),
            APP_SESSIONS.c.revoked_at.is_(None),
        )
        .values(
            org_id=str(organization_id),
            member_id=str(membership["id"]),
            last_seen_at=datetime.now(UTC),
        )
    )
    if not isinstance(changed, CursorResult) or changed.rowcount != 1:
        session.rollback()
        raise HTTPException(status_code=401, detail="Session is no longer valid")
    selected = Principal(
        organization_id=organization_id,
        subject_id=principal.subject_id,
        actor_type=principal.actor_type,
        role=Role(membership["role"]),
        scopes=tuple(
            sorted(permission.value for permission in ROLE_PERMISSIONS[Role(membership["role"])])
        ),
        auth_method=principal.auth_method,
        member_id=UUID(str(membership["id"])),
        session_id=principal.session_id,
    )
    _record(
        session,
        request,
        principal,
        AuditAction.IDENTITY_ORGANIZATION_SWITCHED,
        "session",
        str(principal.session_id),
        "organization_switch",
    )
    session.commit()
    return selected.model_dump(mode="json")


@router.get("/auth/sessions")
def list_sessions(
    principal: CurrentPrincipal, session: SessionDependency
) -> list[dict[str, object]]:
    _interactive(principal)
    rows = session.execute(
        select(APP_SESSIONS)
        .where(
            APP_SESSIONS.c.member_id == str(principal.member_id),
            APP_SESSIONS.c.org_id == str(principal.organization_id),
            APP_SESSIONS.c.revoked_at.is_(None),
            APP_SESSIONS.c.expires_at > datetime.now(UTC),
        )
        .order_by(APP_SESSIONS.c.created_at.desc())
        .limit(100)
    ).mappings()
    return [
        {
            "session_id": row["id"],
            "current": row["id"] == str(principal.session_id),
            "created_at": row["created_at"],
            "last_seen_at": row["last_seen_at"],
            "expires_at": row["expires_at"],
            "revoked_at": row["revoked_at"],
            "auth_method": row["auth_method"],
            "source_ip": row["source_ip"],
            "user_agent": row["user_agent"],
        }
        for row in rows
    ]


@router.delete("/auth/sessions/current", status_code=204)
def revoke_current_session(
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    _interactive(principal)
    now = datetime.now(UTC)
    session.execute(
        update(APP_SESSIONS)
        .where(APP_SESSIONS.c.id == str(principal.session_id))
        .values(revoked_at=now)
    )
    _record(
        session,
        request,
        principal,
        AuditAction.IDENTITY_SESSION_REVOKED,
        "session",
        str(principal.session_id),
        "logout_current",
    )
    session.commit()
    return Response(status_code=204)


@router.delete("/auth/sessions/{session_id}", status_code=204)
def revoke_session(
    session_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    _interactive(principal)
    result = session.execute(
        update(APP_SESSIONS)
        .where(
            APP_SESSIONS.c.id == str(session_id),
            APP_SESSIONS.c.member_id == str(principal.member_id),
            APP_SESSIONS.c.org_id == str(principal.organization_id),
            APP_SESSIONS.c.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(UTC))
    )
    if not isinstance(result, CursorResult) or result.rowcount != 1:
        session.rollback()
        raise HTTPException(status_code=404, detail="Session not found")
    _record(
        session,
        request,
        principal,
        AuditAction.IDENTITY_SESSION_REVOKED,
        "session",
        str(session_id),
        "revoke_session",
    )
    session.commit()
    return Response(status_code=204)


@router.post("/auth/sessions/revoke-others", status_code=200)
def revoke_other_sessions(
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, int]:
    _interactive(principal)
    changed = session.execute(
        update(APP_SESSIONS)
        .where(
            APP_SESSIONS.c.member_id == str(principal.member_id),
            APP_SESSIONS.c.org_id == str(principal.organization_id),
            APP_SESSIONS.c.id != str(principal.session_id),
            APP_SESSIONS.c.revoked_at.is_(None),
            APP_SESSIONS.c.expires_at > datetime.now(UTC),
        )
        .values(revoked_at=datetime.now(UTC))
    )
    _record(
        session,
        request,
        principal,
        AuditAction.IDENTITY_SESSIONS_REVOKED,
        "session",
        str(principal.member_id),
        "revoke_others",
    )
    session.commit()
    revoked_count = changed.rowcount if isinstance(changed, CursorResult) else 0
    return {"revoked_count": int(revoked_count or 0)}


def _allowlist_view(session: Session, organization_id: UUID) -> dict[str, object]:
    enabled = session.execute(
        select(IP_ALLOWLIST_SETTINGS.c.enabled).where(
            IP_ALLOWLIST_SETTINGS.c.org_id == str(organization_id)
        )
    ).scalar_one_or_none()
    entries = session.execute(
        select(IP_ALLOWLIST_ENTRIES).where(
            IP_ALLOWLIST_ENTRIES.c.org_id == str(organization_id)
        ).order_by(IP_ALLOWLIST_ENTRIES.c.created_at)
    ).mappings()
    return {
        "enabled": bool(enabled),
        "entries": [
            {
                "id": row["id"],
                "network": str(row["network"]),
                "label": row["label"],
                "created_at": row["created_at"],
            }
            for row in entries
        ],
    }


@router.get("/organizations/current/ip-allowlist")
def get_ip_allowlist(
    principal: CurrentPrincipal, session: SessionDependency
) -> dict[str, object]:
    _identity_admin(principal)
    return _allowlist_view(session, principal.organization_id)


@router.put("/organizations/current/ip-allowlist")
def update_ip_allowlist(
    body: IPAllowlistUpdate,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _identity_admin(principal)
    org_id = str(principal.organization_id)
    now = datetime.now(UTC)
    networks = session.execute(
        select(IP_ALLOWLIST_ENTRIES.c.id).where(IP_ALLOWLIST_ENTRIES.c.org_id == org_id)
    ).first()
    if body.enabled and networks is None:
        raise HTTPException(status_code=409, detail="Add at least one network before enabling")
    values = dict(
        org_id=org_id,
        enabled=body.enabled,
        updated_by=str(principal.member_id),
        updated_at=now,
    )
    setting_insert = (
        pg_insert(IP_ALLOWLIST_SETTINGS)
        if session.bind and session.bind.dialect.name == "postgresql"
        else sqlite_insert(IP_ALLOWLIST_SETTINGS)
    )
    session.execute(
        setting_insert
        .values(
            **values
        )
        .on_conflict_do_update(
            index_elements=[IP_ALLOWLIST_SETTINGS.c.org_id],
            set_={
                "enabled": body.enabled,
                "updated_by": str(principal.member_id),
                "updated_at": now,
            },
        )
    )
    _record(
        session,
        request,
        principal,
        AuditAction.IDENTITY_IP_ALLOWLIST_ENABLED
        if body.enabled
        else AuditAction.IDENTITY_IP_ALLOWLIST_DISABLED,
        "ip_allowlist",
        org_id,
        "enable" if body.enabled else "disable",
    )
    session.commit()
    return _allowlist_view(session, principal.organization_id)


@router.post("/organizations/current/ip-allowlist/entries", status_code=201)
def add_ip_allowlist_entry(
    body: IPAllowlistEntryWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _identity_admin(principal)
    try:
        network = str(parse_network(body.network))
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IP address or CIDR") from None
    label = body.label.strip()
    if not label:
        raise HTTPException(status_code=422, detail="Label is required")
    org_id = str(principal.organization_id)
    now = datetime.now(UTC)
    setting_insert = (
        pg_insert(IP_ALLOWLIST_SETTINGS)
        if session.bind and session.bind.dialect.name == "postgresql"
        else sqlite_insert(IP_ALLOWLIST_SETTINGS)
    )
    session.execute(
        setting_insert.values(
            org_id=org_id,
            enabled=False,
            updated_by=str(principal.member_id),
            updated_at=now,
        ).on_conflict_do_nothing(index_elements=[IP_ALLOWLIST_SETTINGS.c.org_id])
    )
    entry_id = uuid4()
    try:
        session.execute(
            insert(IP_ALLOWLIST_ENTRIES).values(
                id=str(entry_id),
                org_id=org_id,
                network=network,
                label=label,
                created_by=str(principal.member_id),
                created_at=now,
            )
        )
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Network already exists") from None
    _record(
        session,
        request,
        principal,
        AuditAction.IDENTITY_IP_ALLOWLIST_ENTRY_ADDED,
        "ip_allowlist_entry",
        str(entry_id),
        "add_network",
    )
    session.commit()
    return {"id": str(entry_id), "network": network, "label": label, "created_at": now}


@router.delete("/organizations/current/ip-allowlist/entries/{entry_id}", status_code=204)
def remove_ip_allowlist_entry(
    entry_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    _identity_admin(principal)
    org_id = str(principal.organization_id)
    enabled = session.execute(
        select(IP_ALLOWLIST_SETTINGS.c.enabled).where(IP_ALLOWLIST_SETTINGS.c.org_id == org_id)
    ).scalar_one_or_none()
    if enabled:
        count = session.execute(
            select(IP_ALLOWLIST_ENTRIES.c.id).where(IP_ALLOWLIST_ENTRIES.c.org_id == org_id)
        ).all()
        if len(count) <= 1:
            raise HTTPException(
                status_code=409,
                detail="Disable the allowlist before removing its final network",
            )
    removed = session.execute(
        delete(IP_ALLOWLIST_ENTRIES).where(
            IP_ALLOWLIST_ENTRIES.c.id == str(entry_id),
            IP_ALLOWLIST_ENTRIES.c.org_id == org_id,
        )
    )
    if not isinstance(removed, CursorResult) or removed.rowcount != 1:
        session.rollback()
        raise HTTPException(status_code=404, detail="Network not found")
    _record(
        session,
        request,
        principal,
        AuditAction.IDENTITY_IP_ALLOWLIST_ENTRY_REMOVED,
        "ip_allowlist_entry",
        str(entry_id),
        "remove_network",
    )
    session.commit()
    return Response(status_code=204)
