"""Tenant-bound SCIM 2.0 provisioning endpoints and credential administration."""

import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from dlp_platform.audit.service import AuditContext, AuditService, context_from_request
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.tables import (
    MEMBERS,
    SCIM_CREDENTIALS,
    SCIM_GROUP_MEMBERS,
    SCIM_GROUPS,
    SCIM_USERS,
)

router = APIRouter(tags=["scim"])
SessionDependency = Annotated[Session, Depends(get_session)]
_audit = AuditService()
_TOKEN = re.compile(r"^scim_([a-f0-9]{12})\.([A-Za-z0-9_-]{40,})$")
_FILTER = re.compile(
    r'^(userName|externalId|displayName)\s+eq\s+"([^"\\\\]{1,512})"$', re.I
)
_USER_FIELDS = {
    "schemas",
    "externalId",
    "userName",
    "displayName",
    "name",
    "active",
    "emails",
}
_GROUP_FIELDS = {"schemas", "externalId", "displayName", "members"}
_MAX_BODY = 256_000
_SCIM_JSON = "application/scim+json"


class SCIMError(Exception):
    def __init__(
        self, code: int, detail: str, headers: dict[str, str] | None = None
    ) -> None:
        self.code = code
        self.detail = detail
        self.headers = headers or {}


def scim_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, SCIMError):
        raise exc
    return JSONResponse(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(exc.code),
            "detail": exc.detail,
        },
        status_code=exc.code,
        media_type=_SCIM_JSON,
        headers={"Cache-Control": "no-store", **exc.headers},
    )


def _admin(principal: Principal, permission: Permission) -> None:
    require_permission(principal, permission)
    if principal.role not in {Role.OWNER, Role.ADMIN}:
        raise HTTPException(status_code=403, detail="Forbidden")


def _record(
    session: Session,
    org_id: UUID,
    *,
    action: AuditAction,
    resource_type: str,
    resource_id: str,
    credential_id: str | None = None,
    request: Request | None = None,
    operation: str,
) -> None:
    principal = Principal(
        organization_id=org_id,
        subject_id=f"scim:{credential_id or 'administrator'}",
        actor_type=ActorType.SERVICE if credential_id else ActorType.USER,
        role=Role.VIEWER if credential_id else Role.ADMIN,
        scopes=(),
        auth_method=AuthMethod.INTERNAL if credential_id else AuthMethod.JWT,
    )
    context = context_from_request(request) if request is not None else AuditContext()
    if credential_id:
        context = AuditContext(
            correlation_id=context.correlation_id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            actor_id=credential_id,
        )
    _audit.record_event(
        session,
        principal,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata={"operation": operation},
        context=context,
    )


@router.post("/api/scim/credentials", status_code=201)
def create_credential(
    body: dict[str, Any],
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, object]:
    _admin(principal, Permission.SCIM_CREDENTIALS_WRITE)
    name = body.get("name") if set(body) == {"name"} else None
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        raise HTTPException(status_code=422, detail="Invalid credential name")
    secret_part = secrets.token_urlsafe(32)
    prefix = secrets.token_hex(6)
    token = f"scim_{prefix}.{secret_part}"
    credential_id = uuid4()
    now = datetime.now(UTC)
    try:
        session.execute(
            insert(SCIM_CREDENTIALS).values(
                id=str(credential_id),
                org_id=str(principal.organization_id),
                name=name.strip(),
                prefix=prefix,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                created_by=str(
                    session.execute(
                        select(MEMBERS.c.id).where(
                            MEMBERS.c.organization_id == str(principal.organization_id),
                            MEMBERS.c.auth_subject_id == principal.subject_id,
                        )
                    ).scalar_one()
                ),
                created_at=now,
            )
        )
        _record(
            session,
            principal.organization_id,
            action=AuditAction.SCIM_CREDENTIAL_CREATED,
            resource_type="scim_credential",
            resource_id=str(credential_id),
            request=request,
            operation="create",
        )
        session.commit()
    except (SQLAlchemyError, IntegrityError):
        session.rollback()
        raise HTTPException(
            status_code=503, detail="SCIM credential could not be created"
        ) from None
    return {
        "id": str(credential_id),
        "name": name.strip(),
        "prefix": prefix,
        "created_at": now.isoformat(),
        "token": token,
    }


@router.get("/api/scim/credentials")
def list_credentials(
    principal: CurrentPrincipal, session: SessionDependency
) -> list[dict[str, object]]:
    _admin(principal, Permission.SCIM_CREDENTIALS_READ)
    rows = (
        session.execute(
            select(
                SCIM_CREDENTIALS.c.id,
                SCIM_CREDENTIALS.c.name,
                SCIM_CREDENTIALS.c.prefix,
                SCIM_CREDENTIALS.c.created_at,
                SCIM_CREDENTIALS.c.last_used_at,
                SCIM_CREDENTIALS.c.revoked_at,
            )
            .where(SCIM_CREDENTIALS.c.org_id == str(principal.organization_id))
            .order_by(SCIM_CREDENTIALS.c.created_at.desc())
        )
        .mappings()
        .all()
    )
    return [dict(row) for row in rows]


@router.delete("/api/scim/credentials/{credential_id}", status_code=204)
def revoke_credential(
    credential_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    _admin(principal, Permission.SCIM_CREDENTIALS_WRITE)
    result = session.execute(
        update(SCIM_CREDENTIALS)
        .where(
            SCIM_CREDENTIALS.c.id == str(credential_id),
            SCIM_CREDENTIALS.c.org_id == str(principal.organization_id),
            SCIM_CREDENTIALS.c.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(UTC))
    )
    if getattr(result, "rowcount", 0) != 1:
        session.rollback()
        raise HTTPException(status_code=404, detail="Credential not found")
    _record(
        session,
        principal.organization_id,
        action=AuditAction.SCIM_CREDENTIAL_REVOKED,
        resource_type="scim_credential",
        resource_id=str(credential_id),
        request=request,
        operation="revoke",
    )
    session.commit()
    return Response(status_code=204)


def _tenant(request: Request, session: Session) -> tuple[UUID, str]:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise SCIMError(401, "A valid SCIM bearer credential is required")
    token = header[7:].strip()
    match = _TOKEN.fullmatch(token)
    if match is None:
        raise SCIMError(401, "A valid SCIM bearer credential is required")
    row = (
        session.execute(
            select(
                SCIM_CREDENTIALS.c.id,
                SCIM_CREDENTIALS.c.org_id,
                SCIM_CREDENTIALS.c.token_hash,
            ).where(
                SCIM_CREDENTIALS.c.prefix == match.group(1),
                SCIM_CREDENTIALS.c.revoked_at.is_(None),
            )
        )
        .mappings()
        .one_or_none()
    )
    digest = hashlib.sha256(token.encode()).hexdigest()
    if row is None or not hmac.compare_digest(digest, str(row["token_hash"])):
        raise SCIMError(401, "A valid SCIM bearer credential is required")
    organization_id = UUID(str(row["org_id"]))
    credential_id = str(row["id"])
    limit = get_rate_limiter().check(credential_id, str(organization_id))
    if not limit.allowed:
        raise SCIMError(
            429,
            "SCIM rate limit exceeded",
            {"Retry-After": str(limit.retry_after)},
        )
    session.execute(
        update(SCIM_CREDENTIALS)
        .where(
            SCIM_CREDENTIALS.c.id == credential_id,
            SCIM_CREDENTIALS.c.revoked_at.is_(None),
        )
        .values(last_used_at=datetime.now(UTC))
    )
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SET LOCAL ROLE authenticated"))
        session.execute(
            text("SELECT set_config('request.jwt.claims', :claims, true)"),
            {
                "claims": json.dumps(
                    {
                        "role": "authenticated",
                        "aud": "authenticated",
                        "org_id": str(organization_id),
                        "app_role": "scim",
                    }
                )
            },
        )
    request.state.scim_credential_id = credential_id
    return organization_id, credential_id


def _json_response(value: object, code: int = 200) -> JSONResponse:
    return JSONResponse(
        value,
        status_code=code,
        media_type=_SCIM_JSON,
        headers={"Cache-Control": "no-store"},
    )


async def _payload(request: Request) -> dict[str, Any]:
    content_type = (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    )
    if content_type not in {_SCIM_JSON, "application/json"}:
        raise SCIMError(
            415, "Content-Type must be application/scim+json or application/json"
        )
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > _MAX_BODY:
            raise SCIMError(413, "SCIM request body is too large")
        chunks.append(chunk)
    body = b"".join(chunks)
    try:
        value = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise SCIMError(400, "Malformed JSON request") from None
    if not isinstance(value, dict):
        raise SCIMError(400, "SCIM resource must be a JSON object")
    return value


def _str(
    value: object, field: str, maximum: int, *, required: bool = False
) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise SCIMError(400, f"Invalid {field}")
    return value.strip()


def _user_row(session: Session, org_id: UUID, resource_id: str) -> Any:
    row = (
        session.execute(
            select(SCIM_USERS, MEMBERS.c.email, MEMBERS.c.active)
            .join(
                MEMBERS,
                (MEMBERS.c.id == SCIM_USERS.c.member_id)
                & (MEMBERS.c.organization_id == SCIM_USERS.c.org_id),
            )
            .where(SCIM_USERS.c.id == resource_id, SCIM_USERS.c.org_id == str(org_id))
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise SCIMError(404, "Resource not found")
    return row


def _user_rep(session: Session, org_id: UUID, row: Any) -> dict[str, object]:
    schemas = ["urn:ietf:params:scim:schemas:core:2.0:User"]
    result: dict[str, object] = {
        "schemas": schemas,
        "id": str(row["id"]),
        "userName": str(row["user_name"]),
        "active": bool(row["active"]),
        "meta": {
            "resourceType": "User",
            "created": row["created_at"].isoformat(),
            "lastModified": row["updated_at"].isoformat(),
            "location": f"/scim/v2/Users/{row['id']}",
        },
    }
    if row["external_id"] is not None:
        result["externalId"] = row["external_id"]
    if row["display_name"] is not None:
        result["displayName"] = row["display_name"]
        result["name"] = {"formatted": row["display_name"]}
    if row["email"]:
        result["emails"] = [{"value": row["email"], "type": "work", "primary": True}]
    return result


def _joined_user(session: Session, org_id: UUID, resource_id: str) -> Any:
    return (
        session.execute(
            select(SCIM_USERS, MEMBERS.c.email, MEMBERS.c.active)
            .join(
                MEMBERS,
                (MEMBERS.c.id == SCIM_USERS.c.member_id)
                & (MEMBERS.c.organization_id == SCIM_USERS.c.org_id),
            )
            .where(SCIM_USERS.c.org_id == str(org_id), SCIM_USERS.c.id == resource_id)
        )
        .mappings()
        .one()
    )


def _filter(query: str | None, field_map: dict[str, Any]) -> Any:
    if query is None:
        return None
    if len(query) > 600:
        raise SCIMError(400, "Unsupported filter")
    match = _FILTER.fullmatch(query.strip())
    if match is None:
        raise SCIMError(400, "Unsupported filter")
    field = next(
        (key for key in field_map if key.lower() == match.group(1).lower()), None
    )
    if field is None:
        raise SCIMError(400, "Unsupported filter")
    return field_map[field] == match.group(2)


def _page(start_index: str | int, count: str | int) -> tuple[int, int]:
    try:
        start_index, count = int(start_index), int(count)
    except (TypeError, ValueError):
        raise SCIMError(400, "Invalid pagination parameters") from None
    if start_index < 1 or count < 0:
        raise SCIMError(400, "Invalid pagination parameters")
    return start_index, min(count, 200)


def _list_response(
    resources: list[dict[str, object]], total: int, start: int
) -> dict[str, object]:
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.get("/scim/v2/Users")
def list_users(
    request: Request,
    session: SessionDependency,
    filter: str | None = None,
    startIndex: str = "1",
    count: str = "100",
) -> JSONResponse:
    org_id, _credential_id = _tenant(request, session)
    start, size = _page(startIndex, count)
    query = select(SCIM_USERS.c.id).where(SCIM_USERS.c.org_id == str(org_id))
    predicate = _filter(
        filter,
        {"userName": SCIM_USERS.c.user_name, "externalId": SCIM_USERS.c.external_id},
    )
    if predicate is not None:
        query = query.where(predicate)
    ids_query = query.order_by(SCIM_USERS.c.user_name, SCIM_USERS.c.id)
    from sqlalchemy import func

    total = int(
        session.execute(
            select(func.count())
            .select_from(SCIM_USERS)
            .where(
                SCIM_USERS.c.org_id == str(org_id),
                *([predicate] if predicate is not None else []),
            )
        ).scalar_one()
    )
    ids = session.execute(ids_query.offset(start - 1).limit(size)).scalars().all()
    reps = [
        _user_rep(session, org_id, _joined_user(session, org_id, str(resource_id)))
        for resource_id in ids
    ]
    return _json_response(_list_response(reps, total, start))


@router.get("/scim/v2/Users/{resource_id}")
def get_user(
    resource_id: UUID, request: Request, session: SessionDependency
) -> JSONResponse:
    org_id, _credential_id = _tenant(request, session)
    return _json_response(
        _user_rep(session, org_id, _user_row(session, org_id, str(resource_id)))
    )


def _extract_email(payload: dict[str, Any]) -> str | None:
    emails = payload.get("emails")
    if emails is None:
        return None
    if not isinstance(emails, list) or len(emails) > 8:
        raise SCIMError(400, "Invalid emails")
    for entry in emails:
        if not isinstance(entry, dict) or set(entry) - {
            "value",
            "type",
            "primary",
            "display",
        }:
            raise SCIMError(400, "Invalid email entry")
        if entry.get("primary") is True or entry.get("type") == "work":
            email = _str(entry.get("value"), "email", 320, required=True)
            assert email is not None
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise SCIMError(400, "Invalid email")
            return email.lower()
    return None


def _validate_user_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) - _USER_FIELDS:
        raise SCIMError(400, "Unsupported or protected user attribute")
    username = _str(payload.get("userName"), "userName", 320, required=True)
    external_id = _str(payload.get("externalId"), "externalId", 512)
    display_name = _str(payload.get("displayName"), "displayName", 256)
    active = payload.get("active", True)
    if not isinstance(active, bool):
        raise SCIMError(400, "Invalid active value")
    if payload.get("schemas") is not None and payload["schemas"] != [
        "urn:ietf:params:scim:schemas:core:2.0:User"
    ]:
        raise SCIMError(400, "Unsupported User schema")
    name = payload.get("name")
    if name is not None:
        allowed_name = {
            "formatted",
            "givenName",
            "familyName",
            "middleName",
            "honorificPrefix",
            "honorificSuffix",
        }
        if not isinstance(name, dict) or set(name) - allowed_name:
            raise SCIMError(400, "Invalid name")
        normalized = {
            key: _str(value, f"name.{key}", 128) for key, value in name.items()
        }
        if display_name is None:
            candidate = normalized.get("formatted") or " ".join(
                part
                for part in (
                    normalized.get("givenName"),
                    normalized.get("middleName"),
                    normalized.get("familyName"),
                )
                if part
            )
            display_name = _str(candidate, "displayName", 256)
    return {
        "user_name": username,
        "external_id": external_id,
        "display_name": display_name,
        "active": active,
        "email": _extract_email(payload),
    }


@router.post("/scim/v2/Users", status_code=201)
async def create_user(request: Request, session: SessionDependency) -> JSONResponse:
    org_id, credential_id = _tenant(request, session)
    fields = _validate_user_payload(await _payload(request))
    now = datetime.now(UTC)
    member_id = uuid4()
    resource_id = uuid4()
    try:
        existing_member = None
        if fields["email"]:
            existing_member = (
                session.execute(
                    select(MEMBERS.c.id, MEMBERS.c.auth_subject_id).where(
                        MEMBERS.c.organization_id == str(org_id),
                        MEMBERS.c.email.is_not(None),
                        text("lower(email) = :email"),
                    ),
                    {"email": fields["email"]},
                )
                .mappings()
                .one_or_none()
            )
        if existing_member is not None:
            member_id = UUID(str(existing_member["id"]))
            session.execute(
                update(MEMBERS)
                .where(MEMBERS.c.id == str(member_id))
                .values(active=fields["active"])
            )
        else:
            session.execute(
                insert(MEMBERS).values(
                    id=str(member_id),
                    organization_id=str(org_id),
                    auth_subject_id=f"scim:{uuid4()}",
                    role=Role.VIEWER.value,
                    email=fields["email"],
                    active=fields["active"],
                    created_at=now,
                )
            )
        session.execute(
            insert(SCIM_USERS).values(
                id=str(resource_id),
                org_id=str(org_id),
                member_id=str(member_id),
                external_id=fields["external_id"],
                user_name=fields["user_name"],
                display_name=fields["display_name"],
                created_at=now,
                updated_at=now,
            )
        )
        _record(
            session,
            org_id,
            action=AuditAction.SCIM_USER_PROVISIONED,
            resource_type="scim_user",
            resource_id=str(resource_id),
            credential_id=credential_id,
            request=request,
            operation="create",
        )
        response_body = _user_rep(
            session, org_id, _user_row(session, org_id, str(resource_id))
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise SCIMError(
            409, "A user with this userName, externalId, or email already exists"
        ) from None
    except SQLAlchemyError:
        session.rollback()
        raise SCIMError(503, "SCIM provisioning is temporarily unavailable") from None
    return _json_response(response_body, 201)


def _set_user_fields(
    session: Session,
    org_id: UUID,
    resource_id: UUID,
    fields: dict[str, Any],
    *,
    replace: bool,
) -> Any:
    row = _user_row(session, org_id, str(resource_id))
    now = datetime.now(UTC)
    user_values: dict[str, object] = {"updated_at": now}
    member_values: dict[str, object] = {}
    if "user_name" in fields:
        user_values["user_name"] = fields["user_name"]
    if "external_id" in fields:
        user_values["external_id"] = fields["external_id"]
    if "display_name" in fields:
        user_values["display_name"] = fields["display_name"]
    if "active" in fields:
        member_values["active"] = fields["active"]
    if "email" in fields:
        member_values["email"] = fields["email"]
    if user_values:
        session.execute(
            update(SCIM_USERS)
            .where(
                SCIM_USERS.c.id == str(resource_id), SCIM_USERS.c.org_id == str(org_id)
            )
            .values(**user_values)
        )
    if member_values:
        session.execute(
            update(MEMBERS)
            .where(
                MEMBERS.c.id == row["member_id"],
                MEMBERS.c.organization_id == str(org_id),
            )
            .values(**member_values)
        )
    return _joined_user(session, org_id, str(resource_id))


@router.put("/scim/v2/Users/{resource_id}")
async def replace_user(
    resource_id: UUID, request: Request, session: SessionDependency
) -> JSONResponse:
    org_id, credential_id = _tenant(request, session)
    payload = _validate_user_payload(await _payload(request))
    row = _user_row(session, org_id, str(resource_id))
    if payload["email"] is None:
        payload["email"] = row["email"]
    try:
        result = _set_user_fields(session, org_id, resource_id, payload, replace=True)
        action = (
            AuditAction.SCIM_USER_DEACTIVATED
            if payload["active"] is False
            else AuditAction.SCIM_USER_UPDATED
        )
        _record(
            session,
            org_id,
            action=action,
            resource_type="scim_user",
            resource_id=str(resource_id),
            credential_id=credential_id,
            request=request,
            operation="replace",
        )
        response_body = _user_rep(session, org_id, result)
        session.commit()
    except IntegrityError:
        session.rollback()
        raise SCIMError(
            409, "User attributes conflict with an existing resource"
        ) from None
    return _json_response(response_body)


@router.patch("/scim/v2/Users/{resource_id}")
async def patch_user(
    resource_id: UUID, request: Request, session: SessionDependency
) -> JSONResponse:
    org_id, credential_id = _tenant(request, session)
    payload = await _payload(request)
    if payload.get("schemas") != ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]:
        raise SCIMError(400, "Invalid PATCH schema")
    operations = payload.get("Operations")
    if not isinstance(operations, list) or not operations or len(operations) > 20:
        raise SCIMError(400, "Invalid PATCH operations")
    allowed = {"active", "displayName", "userName", "externalId", "emails"}
    row = _user_row(session, org_id, str(resource_id))
    member_values: dict[str, object] = {}
    scim_values: dict[str, object] = {}
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) - {"op", "path", "value"}:
            raise SCIMError(400, "Invalid PATCH operation")
        op_name = operation.get("op")
        if not isinstance(op_name, str) or op_name.lower() not in {
            "add",
            "replace",
            "remove",
        }:
            raise SCIMError(400, "Unsupported PATCH operation")
        path = operation.get("path")
        value = operation.get("value")
        if path is None:
            if not isinstance(value, dict) or set(value) - allowed:
                raise SCIMError(400, "Invalid PATCH value")
            patch_fields = value
        else:
            if not isinstance(path, str) or path not in allowed:
                raise SCIMError(400, "Unsupported or protected PATCH path")
            patch_fields = {path: value}
        for key, item in patch_fields.items():
            normalized = key[0].lower() + key[1:]
            if op_name.lower() == "remove":
                if normalized == "emails":
                    member_values["email"] = None
                    continue
                if normalized not in {"displayName", "externalId"}:
                    raise SCIMError(400, "Attribute cannot be removed")
                scim_values[
                    "display_name" if normalized == "displayName" else "external_id"
                ] = None
            elif normalized == "active":
                if not isinstance(item, bool):
                    raise SCIMError(400, "Invalid active value")
                member_values["active"] = item
            elif normalized == "emails":
                member_values["email"] = _extract_email(
                    {"emails": item if isinstance(item, list) else [item]}
                )
            elif normalized in {"displayName", "externalId", "userName"}:
                parsed = _str(
                    item,
                    normalized,
                    512
                    if normalized == "externalId"
                    else 320
                    if normalized == "userName"
                    else 256,
                    required=normalized == "userName",
                )
                scim_values[
                    {
                        "displayName": "display_name",
                        "externalId": "external_id",
                        "userName": "user_name",
                    }[normalized]
                ] = parsed
    try:
        if scim_values:
            session.execute(
                update(SCIM_USERS)
                .where(
                    SCIM_USERS.c.id == str(resource_id),
                    SCIM_USERS.c.org_id == str(org_id),
                )
                .values(**scim_values, updated_at=datetime.now(UTC))
            )
        if member_values:
            session.execute(
                update(MEMBERS)
                .where(
                    MEMBERS.c.id == row["member_id"],
                    MEMBERS.c.organization_id == str(org_id),
                )
                .values(**member_values)
            )
        action = (
            AuditAction.SCIM_USER_DEACTIVATED
            if member_values.get("active") is False
            else AuditAction.SCIM_USER_UPDATED
        )
        response_body = _user_rep(
            session, org_id, _joined_user(session, org_id, str(resource_id))
        )
        _record(
            session,
            org_id,
            action=action,
            resource_type="scim_user",
            resource_id=str(resource_id),
            credential_id=credential_id,
            request=request,
            operation="patch",
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise SCIMError(
            409, "User attributes conflict with an existing resource"
        ) from None
    return _json_response(response_body)


@router.delete("/scim/v2/Users/{resource_id}", status_code=204)
def delete_user(
    resource_id: UUID, request: Request, session: SessionDependency
) -> Response:
    org_id, credential_id = _tenant(request, session)
    row = _user_row(session, org_id, str(resource_id))
    session.execute(
        update(MEMBERS)
        .where(
            MEMBERS.c.id == row["member_id"], MEMBERS.c.organization_id == str(org_id)
        )
        .values(active=False)
    )
    session.execute(
        update(SCIM_USERS)
        .where(SCIM_USERS.c.id == str(resource_id), SCIM_USERS.c.org_id == str(org_id))
        .values(updated_at=datetime.now(UTC))
    )
    _record(
        session,
        org_id,
        action=AuditAction.SCIM_USER_DEACTIVATED,
        resource_type="scim_user",
        resource_id=str(resource_id),
        credential_id=credential_id,
        request=request,
        operation="delete_deactivate",
    )
    session.commit()
    return Response(status_code=204)


def _group_members(
    session: Session, org_id: UUID, group_id: str
) -> list[dict[str, object]]:
    rows = session.execute(
        select(SCIM_USERS.c.id, SCIM_USERS.c.user_name)
        .join(
            SCIM_GROUP_MEMBERS,
            (SCIM_GROUP_MEMBERS.c.member_id == SCIM_USERS.c.member_id)
            & (SCIM_GROUP_MEMBERS.c.org_id == SCIM_USERS.c.org_id),
        )
        .where(
            SCIM_GROUP_MEMBERS.c.org_id == str(org_id),
            SCIM_GROUP_MEMBERS.c.group_id == group_id,
        )
        .order_by(SCIM_USERS.c.user_name)
    ).all()
    return [
        {
            "value": str(row.id),
            "display": str(row.user_name),
            "type": "User",
            "$ref": f"/scim/v2/Users/{row.id}",
        }
        for row in rows
    ]


def _group_rep(session: Session, org_id: UUID, row: Any) -> dict[str, object]:
    result: dict[str, object] = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": str(row["id"]),
        "displayName": str(row["display_name"]),
        "members": _group_members(session, org_id, str(row["id"])),
        "meta": {
            "resourceType": "Group",
            "created": row["created_at"].isoformat(),
            "lastModified": row["updated_at"].isoformat(),
            "location": f"/scim/v2/Groups/{row['id']}",
        },
    }
    if row["external_id"] is not None:
        result["externalId"] = row["external_id"]
    return result


def _get_group(session: Session, org_id: UUID, group_id: UUID) -> Any:
    row = (
        session.execute(
            select(SCIM_GROUPS).where(
                SCIM_GROUPS.c.org_id == str(org_id), SCIM_GROUPS.c.id == str(group_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise SCIMError(404, "Resource not found")
    return row


def _group_fields(payload: dict[str, Any]) -> tuple[str, str | None, list[str]]:
    if set(payload) - _GROUP_FIELDS:
        raise SCIMError(400, "Unsupported group attribute")
    if payload.get("schemas") is not None and payload["schemas"] != [
        "urn:ietf:params:scim:schemas:core:2.0:Group"
    ]:
        raise SCIMError(400, "Unsupported Group schema")
    name = _str(payload.get("displayName"), "displayName", 256, required=True)
    assert name is not None
    external_id = _str(payload.get("externalId"), "externalId", 512)
    members = payload.get("members", [])
    if not isinstance(members, list) or len(members) > 1000:
        raise SCIMError(400, "Invalid members")
    member_ids: list[str] = []
    for value in members:
        if not isinstance(value, dict) or set(value) - {
            "value",
            "display",
            "type",
            "$ref",
        }:
            raise SCIMError(400, "Invalid group member")
        member_id = _str(value.get("value"), "member value", 36, required=True)
        try:
            member_ids.append(str(UUID(member_id)))
        except ValueError:
            raise SCIMError(400, "Invalid group member") from None
    if len(set(member_ids)) != len(member_ids):
        raise SCIMError(400, "Duplicate group member")
    return name, external_id, member_ids


def _replace_group_members(
    session: Session, org_id: UUID, group_id: str, member_ids: list[str]
) -> bool:
    existing = {
        str(value)
        for value in session.execute(
            select(SCIM_GROUP_MEMBERS.c.member_id).where(
                SCIM_GROUP_MEMBERS.c.org_id == str(org_id),
                SCIM_GROUP_MEMBERS.c.group_id == group_id,
            )
        ).scalars()
    }
    if member_ids:
        rows = (
            session.execute(
                select(SCIM_USERS.c.member_id)
                .join(MEMBERS, MEMBERS.c.id == SCIM_USERS.c.member_id)
                .where(
                    SCIM_USERS.c.org_id == str(org_id),
                    SCIM_USERS.c.id.in_(member_ids),
                    MEMBERS.c.active.is_(True),
                )
            )
            .scalars()
            .all()
        )
        if len(rows) != len(member_ids):
            raise SCIMError(
                400,
                "Group members must reference provisioned users in this organization",
            )
    session.execute(
        delete(SCIM_GROUP_MEMBERS).where(
            SCIM_GROUP_MEMBERS.c.org_id == str(org_id),
            SCIM_GROUP_MEMBERS.c.group_id == group_id,
        )
    )
    now = datetime.now(UTC)
    for member_id in rows if member_ids else []:
        session.execute(
            insert(SCIM_GROUP_MEMBERS).values(
                org_id=str(org_id),
                group_id=group_id,
                member_id=str(member_id),
                created_at=now,
            )
        )
    new_members = {str(value) for value in rows} if member_ids else set()
    return existing != new_members


@router.get("/scim/v2/Groups")
def list_groups(
    request: Request,
    session: SessionDependency,
    filter: str | None = None,
    startIndex: str = "1",
    count: str = "100",
) -> JSONResponse:
    org_id, _credential_id = _tenant(request, session)
    start, size = _page(startIndex, count)
    query = select(SCIM_GROUPS).where(SCIM_GROUPS.c.org_id == str(org_id))
    predicate = _filter(
        filter,
        {
            "displayName": SCIM_GROUPS.c.display_name,
            "externalId": SCIM_GROUPS.c.external_id,
        },
    )
    if predicate is not None:
        query = query.where(predicate)
    from sqlalchemy import func

    total_query = (
        select(func.count())
        .select_from(SCIM_GROUPS)
        .where(SCIM_GROUPS.c.org_id == str(org_id))
    )
    if predicate is not None:
        total_query = total_query.where(predicate)
    total = int(session.execute(total_query).scalar_one())
    selected = (
        session.execute(
            query.order_by(SCIM_GROUPS.c.display_name, SCIM_GROUPS.c.id)
            .offset(start - 1)
            .limit(size)
        )
        .mappings()
        .all()
    )
    return _json_response(
        _list_response(
            [_group_rep(session, org_id, row) for row in selected], total, start
        )
    )


@router.get("/scim/v2/Groups/{group_id}")
def get_group(
    group_id: UUID, request: Request, session: SessionDependency
) -> JSONResponse:
    org_id, _credential_id = _tenant(request, session)
    return _json_response(
        _group_rep(session, org_id, _get_group(session, org_id, group_id))
    )


@router.post("/scim/v2/Groups", status_code=201)
async def create_group(request: Request, session: SessionDependency) -> JSONResponse:
    org_id, credential_id = _tenant(request, session)
    name, external_id, members = _group_fields(await _payload(request))
    now, group_id = datetime.now(UTC), uuid4()
    try:
        session.execute(
            insert(SCIM_GROUPS).values(
                id=str(group_id),
                org_id=str(org_id),
                external_id=external_id,
                display_name=name,
                created_at=now,
                updated_at=now,
            )
        )
        _replace_group_members(session, org_id, str(group_id), members)
        _record(
            session,
            org_id,
            action=AuditAction.SCIM_GROUP_CREATED,
            resource_type="scim_group",
            resource_id=str(group_id),
            credential_id=credential_id,
            request=request,
            operation="create",
        )
        if members:
            _record(
                session,
                org_id,
                action=AuditAction.SCIM_MEMBERSHIP_CHANGED,
                resource_type="scim_group",
                resource_id=str(group_id),
                credential_id=credential_id,
                request=request,
                operation="add_members",
            )
        response_body = _group_rep(
            session, org_id, _get_group(session, org_id, group_id)
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise SCIMError(
            409, "A group with this displayName or externalId already exists"
        ) from None
    return _json_response(response_body, 201)


@router.put("/scim/v2/Groups/{group_id}")
async def replace_group(
    group_id: UUID, request: Request, session: SessionDependency
) -> JSONResponse:
    org_id, credential_id = _tenant(request, session)
    _get_group(session, org_id, group_id)
    name, external_id, members = _group_fields(await _payload(request))
    try:
        session.execute(
            update(SCIM_GROUPS)
            .where(
                SCIM_GROUPS.c.id == str(group_id), SCIM_GROUPS.c.org_id == str(org_id)
            )
            .values(
                display_name=name, external_id=external_id, updated_at=datetime.now(UTC)
            )
        )
        membership_changed = _replace_group_members(
            session, org_id, str(group_id), members
        )
        _record(
            session,
            org_id,
            action=AuditAction.SCIM_GROUP_UPDATED,
            resource_type="scim_group",
            resource_id=str(group_id),
            credential_id=credential_id,
            request=request,
            operation="replace",
        )
        if membership_changed:
            _record(
                session,
                org_id,
                action=AuditAction.SCIM_MEMBERSHIP_CHANGED,
                resource_type="scim_group",
                resource_id=str(group_id),
                credential_id=credential_id,
                request=request,
                operation="replace_members",
            )
        response_body = _group_rep(
            session, org_id, _get_group(session, org_id, group_id)
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise SCIMError(
            409, "Group attributes conflict with an existing resource"
        ) from None
    return _json_response(response_body)


@router.patch("/scim/v2/Groups/{group_id}")
async def patch_group(
    group_id: UUID, request: Request, session: SessionDependency
) -> JSONResponse:
    org_id, credential_id = _tenant(request, session)
    row = _get_group(session, org_id, group_id)
    payload = await _payload(request)
    if payload.get("schemas") != ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]:
        raise SCIMError(400, "Invalid PATCH schema")
    operations = payload.get("Operations")
    if not isinstance(operations, list) or not operations or len(operations) > 20:
        raise SCIMError(400, "Invalid PATCH operations")
    name, external_id = str(row["display_name"]), row["external_id"]
    member_ids: list[str] = [
        str(item["value"]) for item in _group_members(session, org_id, str(group_id))
    ]
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) - {"op", "path", "value"}:
            raise SCIMError(400, "Invalid PATCH operation")
        op_name, path, value = (
            operation.get("op"),
            operation.get("path"),
            operation.get("value"),
        )
        if not isinstance(op_name, str) or op_name.lower() not in {
            "add",
            "replace",
            "remove",
        }:
            raise SCIMError(400, "Unsupported PATCH operation")
        if path is None and isinstance(value, dict):
            if set(value) - {"displayName", "externalId", "members"}:
                raise SCIMError(400, "Unsupported or protected PATCH path")
            if "displayName" in value:
                name = (
                    _str(value["displayName"], "displayName", 256, required=True)
                    or name
                )
            if "externalId" in value:
                external_id = _str(value["externalId"], "externalId", 512)
            if "members" in value:
                _n, _e, member_ids = _group_fields(
                    {"displayName": name, "members": value["members"]}
                )
        elif path == "displayName" and op_name.lower() != "remove":
            name = _str(value, "displayName", 256, required=True) or name
        elif path == "externalId":
            external_id = (
                None if op_name.lower() == "remove" else _str(value, "externalId", 512)
            )
        elif isinstance(path, str) and path.startswith("members["):
            member_filter = re.fullmatch(
                r'members\[value eq "([^"\\\\]{1,36})"\]', path
            )
            if member_filter is None:
                raise SCIMError(400, "Unsupported group member path")
            try:
                target = str(UUID(member_filter.group(1)))
            except ValueError:
                raise SCIMError(400, "Invalid group member path") from None
            if op_name.lower() == "remove":
                member_ids = [value for value in member_ids if value != target]
            else:
                parsed_member = {"value": target} if isinstance(value, str) else value
                _n, _e, incoming = _group_fields(
                    {"displayName": name, "members": [parsed_member]}
                )
                member_ids = (
                    list(dict.fromkeys(member_ids + incoming))
                    if op_name.lower() == "add"
                    else incoming
                )
        elif path == "members":
            if op_name.lower() == "remove":
                member_ids = []
            else:
                if not isinstance(value, list) or len(value) > 1000:
                    raise SCIMError(400, "Invalid members")
                parsed = [
                    {"value": item} if isinstance(item, str) else item for item in value
                ]
                _n, _e, incoming = _group_fields(
                    {"displayName": name, "members": parsed}
                )
                member_ids = list(
                    dict.fromkeys(
                        member_ids + incoming if op_name.lower() == "add" else incoming
                    )
                )
        else:
            raise SCIMError(400, "Unsupported or protected PATCH path")
    try:
        session.execute(
            update(SCIM_GROUPS)
            .where(
                SCIM_GROUPS.c.id == str(group_id), SCIM_GROUPS.c.org_id == str(org_id)
            )
            .values(
                display_name=name, external_id=external_id, updated_at=datetime.now(UTC)
            )
        )
        membership_changed = _replace_group_members(
            session, org_id, str(group_id), member_ids
        )
        _record(
            session,
            org_id,
            action=AuditAction.SCIM_GROUP_UPDATED,
            resource_type="scim_group",
            resource_id=str(group_id),
            credential_id=credential_id,
            request=request,
            operation="patch",
        )
        if membership_changed:
            _record(
                session,
                org_id,
                action=AuditAction.SCIM_MEMBERSHIP_CHANGED,
                resource_type="scim_group",
                resource_id=str(group_id),
                credential_id=credential_id,
                request=request,
                operation="patch_members",
            )
        response_body = _group_rep(
            session, org_id, _get_group(session, org_id, group_id)
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise SCIMError(
            409, "Group attributes conflict with an existing resource"
        ) from None
    return _json_response(response_body)


@router.delete("/scim/v2/Groups/{group_id}", status_code=204)
def delete_group(
    group_id: UUID, request: Request, session: SessionDependency
) -> Response:
    org_id, credential_id = _tenant(request, session)
    _get_group(session, org_id, group_id)
    session.execute(
        delete(SCIM_GROUPS).where(
            SCIM_GROUPS.c.org_id == str(org_id), SCIM_GROUPS.c.id == str(group_id)
        )
    )
    _record(
        session,
        org_id,
        action=AuditAction.SCIM_GROUP_DELETED,
        resource_type="scim_group",
        resource_id=str(group_id),
        credential_id=credential_id,
        request=request,
        operation="delete",
    )
    session.commit()
    return Response(status_code=204)
