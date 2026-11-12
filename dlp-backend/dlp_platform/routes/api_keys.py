"""Create, list and revoke organization-scoped API keys."""

import hashlib
import secrets
from datetime import UTC, datetime
from typing import Annotated, Any, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import CursorResult, insert, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditPersistenceError, AuditService, context_from_request
from dlp_platform.auth.permissions import require_permission, validate_requested_scopes
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.database import get_session
from dlp_platform.tables import API_KEYS

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class CreateAPIKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=4)


class APIKeyMetadata(BaseModel):
    id: UUID
    name: str
    prefix: str
    scopes: tuple[str, ...]
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class CreatedAPIKey(APIKeyMetadata):
    key: str


SessionDependency = Annotated[Session, Depends(get_session)]


@router.post("", response_model=CreatedAPIKey, status_code=status.HTTP_201_CREATED)
def create_api_key(
    request: CreateAPIKeyRequest,
    http_request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> CreatedAPIKey:
    response.headers["Cache-Control"] = "no-store"
    require_permission(principal, Permission.API_KEYS_WRITE)
    scopes = validate_requested_scopes(request.scopes, principal)
    member = (
        session.execute(
            text(
                "SELECT id FROM members "
                "WHERE organization_id = :org_id AND auth_subject_id = :subject"
            ),
            {"org_id": str(principal.organization_id), "subject": principal.subject_id},
        )
        .mappings()
        .one_or_none()
    )
    if member is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    prefix = secrets.token_hex(6)
    plaintext = f"dlp_{prefix}.{secrets.token_urlsafe(32)}"
    key_id = uuid4()
    created_at = datetime.now(UTC)
    try:
        session.execute(
            insert(API_KEYS).values(
                id=str(key_id),
                org_id=str(principal.organization_id),
                name=request.name,
                prefix=prefix,
                key_hash=hashlib.sha256(plaintext.encode("utf-8")).hexdigest(),
                scopes=list(scopes),
                created_by=member["id"],
                created_at=created_at,
                last_used_at=None,
                revoked_at=None,
            )
        )
        AuditService().record_event(
            session,
            principal,
            action=AuditAction.API_KEY_CREATED,
            resource_type="api_key",
            resource_id=str(key_id),
            metadata={"scopes": list(scopes)},
            context=context_from_request(http_request),
        )
        session.commit()
    except (SQLAlchemyError, AuditPersistenceError, ValueError):
        session.rollback()
        raise HTTPException(status_code=503, detail="API key operation unavailable") from None
    return CreatedAPIKey(
        id=key_id,
        name=request.name,
        prefix=prefix,
        scopes=scopes,
        created_at=created_at,
        last_used_at=None,
        revoked_at=None,
        key=plaintext,
    )


@router.get("", response_model=list[APIKeyMetadata])
def list_api_keys(principal: CurrentPrincipal, session: SessionDependency) -> list[APIKeyMetadata]:
    require_permission(principal, Permission.API_KEYS_READ)
    rows = session.execute(
        select(API_KEYS)
        .where(API_KEYS.c.org_id == str(principal.organization_id))
        .order_by(API_KEYS.c.created_at.desc())
    ).mappings()
    return [
        APIKeyMetadata(
            id=row["id"],
            name=row["name"],
            prefix=row["prefix"],
            scopes=tuple(row["scopes"]),
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            revoked_at=row["revoked_at"],
        )
        for row in rows
    ]


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    key_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    require_permission(principal, Permission.API_KEYS_WRITE)
    existing = (
        session.execute(
            select(API_KEYS.c.id, API_KEYS.c.org_id, API_KEYS.c.revoked_at).where(
                API_KEYS.c.id == str(key_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    if existing["org_id"] != str(principal.organization_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    result = cast(
        CursorResult[Any],
        session.execute(
            update(API_KEYS)
            .where(
                API_KEYS.c.id == str(key_id),
                API_KEYS.c.org_id == str(principal.organization_id),
                API_KEYS.c.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        ),
    )
    if result.rowcount != 1:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="API key cannot be revoked"
        )
    try:
        AuditService().record_event(
            session,
            principal,
            action=AuditAction.API_KEY_REVOKED,
            resource_type="api_key",
            resource_id=str(key_id),
            context=context_from_request(request),
        )
        session.commit()
    except (SQLAlchemyError, AuditPersistenceError, ValueError):
        session.rollback()
        raise HTTPException(status_code=503, detail="API key operation unavailable") from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
