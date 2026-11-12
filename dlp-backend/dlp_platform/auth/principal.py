"""Resolve every protected request to a trusted, organization-scoped Principal."""

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import insert, select, text, update
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditService, context_from_request, sanitize_metadata
from dlp_platform.auth.jwt import TokenRejected, decode_access_token, decode_sso_access_token
from dlp_platform.auth.roles import ROLE_PERMISSIONS
from dlp_platform.auth.settings import AuthSettings
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.identity.network import NetworkConfigurationError, client_ip, is_allowed
from dlp_platform.tables import (
    API_KEYS,
    APP_SESSIONS,
    IP_ALLOWLIST_ENTRIES,
    IP_ALLOWLIST_SETTINGS,
    ORG_DELETION_REQUESTS,
)

bearer_scheme = HTTPBearer(auto_error=False)
_API_KEY_FORMAT = re.compile(r"^dlp_([a-f0-9]{12})\.([A-Za-z0-9_-]{40,})$")


def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[Session, Depends(get_session)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    if token.startswith("dlp_"):
        principal = _principal_from_api_key(token, session, request)
    else:
        principal = _principal_from_jwt(token, session, AuthSettings.from_env(), request)
    request.state.rate_limit_identity = getattr(request.state, "api_key_id", principal.subject_id)
    deletion_state = session.execute(
        select(ORG_DELETION_REQUESTS.c.status).where(
            ORG_DELETION_REQUESTS.c.org_id == str(principal.organization_id)
        )
    ).scalar_one_or_none()
    if deletion_state in {"in_progress", "completed"}:
        allowed = (
            principal.actor_type is ActorType.USER
            and request.method == "POST"
            and request.url.path == "/organizations/current/deletion/execute"
            and deletion_state == "in_progress"
        ) or (
            principal.actor_type is ActorType.USER
            and request.method == "GET"
            and request.url.path == "/organizations/current/deletion"
        )
        if not allowed:
            raise HTTPException(status_code=423, detail="Organization deletion is in progress")
    request.state.principal = principal
    request.state.audit_session = session
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        # Claims are minted only after JWT/API-key and membership verification. They
        # are transaction-local and consumed by Supabase auth.jwt() policies.
        session.execute(text("SET LOCAL ROLE authenticated"))
        session.execute(
            text("SELECT set_config('request.jwt.claims', :claims, true)"),
            {
                "claims": json.dumps(
                    {
                        "sub": principal.subject_id,
                        "role": "authenticated",
                        "aud": "authenticated",
                        "org_id": str(principal.organization_id),
                        "app_role": principal.role.value,
                        "member_id": str(principal.member_id) if principal.member_id else None,
                        "session_id": str(principal.session_id) if principal.session_id else None,
                    }
                )
            },
        )
    return principal


def _principal_from_jwt(
    token: str, session: Session, settings: AuthSettings, request: Request
) -> Principal:
    try:
        auth_method = AuthMethod.JWT
        try:
            claims = decode_access_token(token, settings)
        except TokenRejected:
            claims = decode_sso_access_token(token, settings)
            auth_method = AuthMethod.SSO
        subject = claims.get("sub")
        org_value = claims.get("org_id") or claims.get("organization_id")
        if not isinstance(subject, str) or not subject:
            raise TokenRejected("required identity claims are missing")
        if org_value is not None and not isinstance(org_value, str):
            raise TokenRejected("invalid organization claim")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        session_row = (
            session.execute(select(APP_SESSIONS).where(APP_SESSIONS.c.token_hash == token_hash))
            .mappings()
            .one_or_none()
        )
        if session_row is not None:
            expiry = session_row["expires_at"]
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if session_row["revoked_at"] is not None or expiry <= datetime.now(UTC):
                raise TokenRejected("session is unavailable")
            org_value = str(session_row["org_id"])
            member_id = str(session_row["member_id"])
            member = (
                session.execute(
                    text(
                        "SELECT id, organization_id, auth_subject_id, role, active "
                        "FROM members WHERE id=:member_id AND organization_id=:org_id "
                        "AND auth_subject_id=:subject"
                    ),
                    {"member_id": member_id, "org_id": org_value, "subject": subject},
                )
                .mappings()
                .one_or_none()
            )
        elif isinstance(org_value, str):
            organization_id = UUID(org_value)
            member = (
                session.execute(
                    text(
                        "SELECT id, organization_id, auth_subject_id, role, active FROM members "
                        "WHERE organization_id = :org_id AND auth_subject_id = :subject"
                    ),
                    {"org_id": str(organization_id), "subject": subject},
                )
                .mappings()
                .one_or_none()
            )
        else:
            matches = (
                session.execute(
                    text(
                        "SELECT id, organization_id, auth_subject_id, role, active FROM members "
                        "WHERE auth_subject_id = :subject"
                    ),
                    {"subject": subject},
                )
                .mappings()
                .all()
            )
            member = matches[0] if len(matches) == 1 else None
        if member is None or not member["active"]:
            raise TokenRejected("membership not found")
        member_id = str(member["id"])
        organization_id = UUID(str(member["organization_id"]))

        if session_row is None:
            _enforce_ip_allowlist(
                session,
                request,
                organization_id,
                subject,
                member_id,
                Role(member["role"]),
                auth_method,
            )
            expires = claims.get("exp")
            if isinstance(expires, bool) or not isinstance(expires, (int, float)):
                raise TokenRejected("token expiration is invalid")
            now = datetime.now(UTC)
            expiry = datetime.fromtimestamp(expires + settings.jwt_leeway_seconds, UTC)
            if expiry <= now:
                raise TokenRejected("token is expired")
            source_ip = _resolved_ip(request)
            user_agent = request.headers.get("user-agent", "")[:512] or None
            if user_agent is not None:
                safe_ua = sanitize_metadata({"user_agent": user_agent}).get("user_agent")
                user_agent = safe_ua if isinstance(safe_ua, str) else None
            session_id = str(uuid4())
            session.execute(
                insert(APP_SESSIONS).values(
                    id=session_id,
                    org_id=str(organization_id),
                    member_id=member_id,
                    token_hash=token_hash,
                    auth_method=auth_method.value,
                    created_at=now,
                    last_seen_at=now,
                    expires_at=expiry,
                    source_ip=source_ip,
                    user_agent=user_agent,
                )
            )
            principal = _user_principal(
                subject, organization_id, member_id, Role(member["role"]), auth_method, session_id
            )
            request.state.principal = principal
            request.state.audit_session = session
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.IDENTITY_SESSION_ESTABLISHED,
                resource_type="session",
                resource_id=session_id,
                metadata={"operation": "established"},
                context=context_from_request(request),
            )
            session.commit()
        else:
            session_id = str(session_row["id"])
            principal = _user_principal(
                subject, organization_id, member_id, Role(member["role"]), auth_method, session_id
            )
            _enforce_ip_allowlist(
                session,
                request,
                organization_id,
                subject,
                member_id,
                Role(member["role"]),
                auth_method,
            )
            session.execute(
                update(APP_SESSIONS)
                .where(APP_SESSIONS.c.id == session_id)
                .values(last_seen_at=datetime.now(UTC))
            )
            session.commit()
        return principal
    except (TokenRejected, ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        ) from exc


def _user_principal(
    subject: str,
    organization_id: UUID,
    member_id: str,
    role: Role,
    auth_method: AuthMethod,
    session_id: str,
) -> Principal:
    scopes = tuple(sorted(permission.value for permission in ROLE_PERMISSIONS[role]))
    return Principal(
        organization_id=organization_id,
        subject_id=subject,
        actor_type=ActorType.USER,
        role=role,
        scopes=scopes,
        auth_method=auth_method,
        member_id=UUID(member_id),
        session_id=UUID(session_id),
    )


def _resolved_ip(request: Request) -> str | None:
    try:
        return client_ip(request)
    except NetworkConfigurationError:
        return None


def _enforce_ip_allowlist(
    session: Session,
    request: Request,
    organization_id: UUID,
    subject: str,
    member_id: str,
    role: Role,
    auth_method: AuthMethod,
) -> None:
    setting = session.execute(
        select(IP_ALLOWLIST_SETTINGS.c.enabled).where(
            IP_ALLOWLIST_SETTINGS.c.org_id == str(organization_id)
        )
    ).scalar_one_or_none()
    if not setting:
        return
    networks = [
        str(value)
        for value in (
            session.execute(
                select(IP_ALLOWLIST_ENTRIES.c.network).where(
                    IP_ALLOWLIST_ENTRIES.c.org_id == str(organization_id)
                )
            ).scalars()
        )
    ]
    try:
        address = client_ip(request)
    except NetworkConfigurationError:
        address = None
    if is_allowed(address, networks):
        return
    principal = _user_principal(
        subject,
        organization_id,
        member_id,
        role,
        auth_method,
        str(uuid4()),
    )
    request.state.principal = principal
    request.state.audit_session = session
    AuditService().record_event(
        session,
        principal,
        action=AuditAction.IDENTITY_IP_ALLOWLIST_BLOCKED,
        resource_type="ip_allowlist",
        resource_id=str(organization_id),
        outcome=AuditOutcome.DENIED,
        metadata={"operation": "blocked"},
        context=context_from_request(request),
    )
    session.commit()
    raise HTTPException(status_code=403, detail="Access is not allowed from this network")


def _principal_from_api_key(token: str, session: Session, request: Request) -> Principal:
    match = _API_KEY_FORMAT.fullmatch(token)
    if match is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    prefix, _secret = match.groups()
    row = (
        session.execute(select(API_KEYS).where(API_KEYS.c.prefix == prefix))
        .mappings()
        .one_or_none()
    )
    if row is None or row["revoked_at"] is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    calculated = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(calculated, row["key_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    member = (
        session.execute(
            text(
                "SELECT auth_subject_id, role, active FROM members "
                "WHERE id = :member_id AND organization_id = :org_id"
            ),
            {"member_id": row["created_by"], "org_id": row["org_id"]},
        )
        .mappings()
        .one_or_none()
    )
    if member is None or not member["active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    session.execute(
        update(API_KEYS)
        .where(API_KEYS.c.id == row["id"], API_KEYS.c.revoked_at.is_(None))
        .values(last_used_at=datetime.now(UTC))
    )
    session.commit()
    request.state.api_key_id = row["id"]
    return Principal(
        organization_id=UUID(row["org_id"]),
        subject_id=member["auth_subject_id"],
        actor_type=ActorType.SERVICE,
        role=Role(member["role"]),
        scopes=tuple(row["scopes"]),
        auth_method=AuthMethod.API_KEY,
    )


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
