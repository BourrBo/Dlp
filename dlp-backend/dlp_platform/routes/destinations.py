"""Tenant-scoped destination classification CRUD for P05."""

from typing import Annotated, Any, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.engine import CursorResult, RowMapping
from sqlalchemy.orm import Session

from dlp_platform.auth.permissions import require_permission, require_role
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.common import Role
from dlp_platform.database import get_session
from dlp_platform.policy.admin_audit import record_admin_change
from dlp_platform.policy.matching import normalize_destination_pattern
from dlp_platform.policy.models import Destination
from dlp_platform.policy.repository import MAX_TENANT_DESTINATIONS
from dlp_platform.tables import DESTINATIONS

router = APIRouter(prefix="/destinations", tags=["destinations"])
SessionDependency = Annotated[Session, Depends(get_session)]


class DestinationWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination_class: str = Field(pattern=r"^(internal|public|personal|partner)$")
    kind: str = Field(pattern=r"^(domain|repo|email_domain)$")
    pattern: str = Field(min_length=1, max_length=255)


def _read(principal: CurrentPrincipal) -> None:
    require_permission(principal, Permission.IDENTITY_READ)


def _write(principal: CurrentPrincipal) -> None:
    require_permission(principal, Permission.API_KEYS_WRITE)
    require_role(principal, Role.OWNER, Role.ADMIN)


def _normalize(body: DestinationWrite) -> str:
    try:
        return normalize_destination_pattern(body.kind, body.pattern)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid destination pattern") from exc


def _model(row: RowMapping | dict[str, Any]) -> Destination:
    data = dict(row)
    return Destination(
        destination_id=UUID(data["id"]),
        organization_id=UUID(data["org_id"]),
        destination_class=data["destination_class"],
        kind=data["kind"],
        pattern=data["pattern"],
    )


@router.get("", response_model=list[Destination])
def list_destinations(principal: CurrentPrincipal, session: SessionDependency) -> list[Destination]:
    _read(principal)
    rows = session.execute(
        select(DESTINATIONS)
        .where(DESTINATIONS.c.org_id == str(principal.organization_id))
        .order_by(DESTINATIONS.c.kind, DESTINATIONS.c.pattern, DESTINATIONS.c.id)
    ).mappings()
    return [_model(row) for row in rows]


@router.post("", response_model=Destination, status_code=status.HTTP_201_CREATED)
def create_destination(
    body: DestinationWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Destination:
    _write(principal)
    destination_count = session.execute(
        select(func.count())
        .select_from(DESTINATIONS)
        .where(DESTINATIONS.c.org_id == str(principal.organization_id))
    ).scalar_one()
    if destination_count >= MAX_TENANT_DESTINATIONS:
        raise HTTPException(status_code=409, detail="Tenant destination limit reached")
    destination_id = uuid4()
    values = {
        "id": str(destination_id),
        "org_id": str(principal.organization_id),
        "destination_class": body.destination_class,
        "kind": body.kind,
        "pattern": _normalize(body),
    }
    try:
        session.execute(insert(DESTINATIONS).values(**values))
        record_admin_change(
            session,
            request,
            principal,
            resource="destination",
            resource_id=str(destination_id),
            operation="create",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Destination could not be created") from exc
    return _model(values)


@router.get("/{destination_id}", response_model=Destination)
def get_destination(
    destination_id: UUID, principal: CurrentPrincipal, session: SessionDependency
) -> Destination:
    _read(principal)
    row = (
        session.execute(
            select(DESTINATIONS).where(
                DESTINATIONS.c.id == str(destination_id),
                DESTINATIONS.c.org_id == str(principal.organization_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return _model(row)


@router.put("/{destination_id}", response_model=Destination)
def update_destination(
    destination_id: UUID,
    body: DestinationWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Destination:
    _write(principal)
    row = (
        session.execute(
            select(DESTINATIONS).where(
                DESTINATIONS.c.id == str(destination_id),
                DESTINATIONS.c.org_id == str(principal.organization_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    values = {
        "destination_class": body.destination_class,
        "kind": body.kind,
        "pattern": _normalize(body),
    }
    try:
        session.execute(
            update(DESTINATIONS)
            .where(
                DESTINATIONS.c.id == str(destination_id),
                DESTINATIONS.c.org_id == str(principal.organization_id),
            )
            .values(**values)
        )
        record_admin_change(
            session,
            request,
            principal,
            resource="destination",
            resource_id=str(destination_id),
            operation="update",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Destination could not be updated") from exc
    return _model({**dict(row), **values})


@router.delete("/{destination_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_destination(
    destination_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    _write(principal)
    result = cast(
        CursorResult[Any],
        session.execute(
            delete(DESTINATIONS).where(
                DESTINATIONS.c.id == str(destination_id),
                DESTINATIONS.c.org_id == str(principal.organization_id),
            )
        ),
    )
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="Destination not found")
    try:
        record_admin_change(
            session,
            request,
            principal,
            resource="destination",
            resource_id=str(destination_id),
            operation="delete",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=503, detail="Destination operation unavailable") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
