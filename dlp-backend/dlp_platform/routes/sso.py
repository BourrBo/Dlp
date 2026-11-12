"""Tenant-scoped SSO configuration, OIDC callbacks, and SAML ACS routes."""

import base64
import hashlib
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, cast
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import delete, insert, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from dlp_platform.audit.service import AuditContext, AuditService, context_from_request
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.auth.settings import AuthSettings
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.identity.mapping import issue_access_token, map_identity
from dlp_platform.identity.models import (
    IdentityLinkWrite,
    SSOConfigView,
    SSOConfigWrite,
    SSOProtocol,
)
from dlp_platform.identity.oidc import (
    OIDCDiscovery,
    OIDCError,
    OIDCIdentity,
    authorization_url,
    discover,
    exchange_and_validate,
    validate_provider_url,
)
from dlp_platform.identity.saml_adapter import SAMLAdapter
from dlp_platform.identity.state import StateError, cookie_name, digest, new_secret, open_cookie, seal
from dlp_platform.tables import (
    MEMBERS,
    SSO_CONFIGS,
    SSO_IDENTITIES,
    SSO_REPLAYS,
    SSO_TRANSACTIONS,
    VAULT_SECRETS,
)
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault, VaultOperationFailed

router = APIRouter(tags=["sso"])
SessionDependency = Annotated[Session, Depends(get_session)]
_sso = AuditService()
_TRANSACTION_TTL = 300
_MAX_SAML_BODY = 1_000_000


def _sso_admin(principal: Principal) -> None:
    require_permission(principal, Permission.SSO_CONFIG_WRITE)


def _base_url() -> str:
    value = os.getenv("DLP_SSO_BASE_URL", "").rstrip("/")
    parsed = urlsplit(value)
    local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
    try:
        port = parsed.port
    except ValueError as exc:
        raise OIDCError("SSO is not configured") from exc
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.scheme != "https" and not local_http)
        or port not in (None, 443 if parsed.scheme == "https" else 80)
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise OIDCError("SSO is not configured")
    return value


def _frontend_url() -> str:
    value = os.getenv("DLP_SSO_FRONTEND_URL", "")
    parsed = urlsplit(value)
    local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
    try:
        port = parsed.port
    except ValueError as exc:
        raise OIDCError("SSO is not configured") from exc
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.scheme != "https" and not local_http)
        or port not in (None, 443 if parsed.scheme == "https" else 80)
        or parsed.query
        or parsed.fragment
    ):
        raise OIDCError("SSO is not configured")
    return value


def _system_principal(org_id: UUID) -> Principal:
    return Principal(
        organization_id=org_id,
        subject_id="sso-provider",
        actor_type=ActorType.SERVICE,
        role=Role.VIEWER,
        scopes=(),
        auth_method=AuthMethod.INTERNAL,
    )


def _config(
    session: Session, org_id: UUID, protocol: SSOProtocol, *, enabled: bool = True
) -> dict[str, Any] | None:
    row = (
        session.execute(
            select(SSO_CONFIGS).where(
                SSO_CONFIGS.c.org_id == str(org_id),
                SSO_CONFIGS.c.protocol == protocol.value,
                SSO_CONFIGS.c.enabled.is_(enabled),
            )
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else None


def _config_id(
    session: Session, config_id: UUID, org_id: UUID | None = None
) -> dict[str, Any] | None:
    query = select(SSO_CONFIGS).where(SSO_CONFIGS.c.id == str(config_id))
    if org_id is not None:
        query = query.where(SSO_CONFIGS.c.org_id == str(org_id))
    row = session.execute(query).mappings().one_or_none()
    return dict(row) if row is not None else None


def _view(row: dict[str, Any]) -> SSOConfigView:
    settings = row["settings"]
    return SSOConfigView(
        config_id=UUID(str(row["id"])),
        organization_id=UUID(str(row["org_id"])),
        protocol=SSOProtocol(str(row["protocol"])),
        issuer=str(row["issuer"]),
        client_id=row["client_id"],
        secret_configured=row["secret_ref"] is not None,
        certificate_configured=row["certificate_ref"] is not None,
        claimed_domains=settings["claimed_domains"],
        attributes=settings.get("attributes", {}),
        scopes=settings.get("scopes", []),
        enabled=bool(row["enabled"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _settings_for(body: SSOConfigWrite) -> dict[str, Any]:
    settings: dict[str, Any] = {
        "claimed_domains": body.claimed_domains,
        "attributes": body.attributes,
        "scopes": body.scopes,
    }
    if body.protocol is SSOProtocol.OIDC:
        discovery = discover(body.issuer)
        settings.update(
            authorization_endpoint=discovery.authorization_endpoint,
            token_endpoint=discovery.token_endpoint,
            jwks_uri=discovery.jwks_uri,
            token_auth_method=discovery.token_auth_method,
        )
    else:
        if body.sso_url is None or body.certificate_ref is None:
            raise OIDCError("SSO configuration is invalid")
        validate_provider_url(body.sso_url)
        settings["sso_url"] = body.sso_url
    return settings


def _validate_secret_reference(
    session: Session,
    org_id: UUID,
    secret_ref: UUID | None,
    expected_type: SecretType,
) -> None:
    if secret_ref is None:
        raise HTTPException(status_code=422, detail="SSO configuration is invalid")
    row = session.execute(
        select(VAULT_SECRETS.c.secret_type, VAULT_SECRETS.c.enabled).where(
            VAULT_SECRETS.c.id == str(secret_ref),
            VAULT_SECRETS.c.org_id == str(org_id),
        )
    ).one_or_none()
    if row is None or not row.enabled or row.secret_type != expected_type.value:
        raise HTTPException(status_code=422, detail="SSO vault reference is invalid")


def _member_id(session: Session, principal: Principal) -> str:
    row = session.execute(
        select(MEMBERS.c.id).where(
            MEMBERS.c.organization_id == str(principal.organization_id),
            MEMBERS.c.auth_subject_id == principal.subject_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=403, detail="SSO configuration is not allowed")
    return str(row)


def _record_config(
    session: Session,
    principal: Principal,
    request: Request,
    action: AuditAction,
    identifier: str,
) -> None:
    _sso.record_event(
        session,
        principal,
        action=action,
        resource_type="sso_config",
        resource_id=identifier,
        context=context_from_request(request),
    )


@router.get("/sso/configs", response_model=list[SSOConfigView])
def list_configs(
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> list[SSOConfigView]:
    require_permission(principal, Permission.SSO_CONFIG_READ)
    rows = (
        session.execute(
            select(SSO_CONFIGS).where(SSO_CONFIGS.c.org_id == str(principal.organization_id))
        )
        .mappings()
        .all()
    )
    return [_view(dict(row)) for row in rows]


@router.post("/sso/configs", response_model=SSOConfigView, status_code=status.HTTP_201_CREATED)
def create_config(
    body: SSOConfigWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> SSOConfigView:
    _sso_admin(principal)
    org_id = principal.organization_id
    if body.protocol is SSOProtocol.OIDC:
        _validate_secret_reference(session, org_id, body.secret_ref, SecretType.OAUTH_CLIENT_SECRET)
    else:
        _validate_secret_reference(session, org_id, body.certificate_ref, SecretType.GENERIC_SECRET)
    try:
        settings = _settings_for(body)
        identifier = uuid4()
        now = datetime.now(UTC)
        session.execute(
            insert(SSO_CONFIGS).values(
                id=str(identifier),
                org_id=str(org_id),
                protocol=body.protocol.value,
                issuer=body.issuer.rstrip("/")
                if body.protocol is SSOProtocol.OIDC
                else body.issuer,
                client_id=body.client_id,
                secret_ref=str(body.secret_ref) if body.secret_ref else None,
                certificate_ref=str(body.certificate_ref) if body.certificate_ref else None,
                settings=settings,
                enabled=False,
                created_by=_member_id(session, principal),
                created_at=now,
                updated_at=now,
            )
        )
        _record_config(
            session, principal, request, AuditAction.SSO_CONFIGURATION_CREATED, str(identifier)
        )
        session.commit()
        current = _config_id(session, identifier, org_id)
        assert current is not None
        return _view(current)
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="SSO provider already exists") from None
    except OIDCError:
        session.rollback()
        raise HTTPException(
            status_code=422, detail="SSO provider configuration is invalid"
        ) from None


@router.put("/sso/configs/{config_id}", response_model=SSOConfigView)
def update_config(
    config_id: UUID,
    body: SSOConfigWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> SSOConfigView:
    _sso_admin(principal)
    old = _config_id(session, config_id, principal.organization_id)
    if old is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    if body.protocol is not SSOProtocol(str(old["protocol"])):
        raise HTTPException(status_code=422, detail="SSO provider type cannot be changed")
    if body.protocol is SSOProtocol.OIDC:
        _validate_secret_reference(
            session, principal.organization_id, body.secret_ref, SecretType.OAUTH_CLIENT_SECRET
        )
    else:
        _validate_secret_reference(
            session, principal.organization_id, body.certificate_ref, SecretType.GENERIC_SECRET
        )
    try:
        settings = _settings_for(body)
        session.execute(
            update(SSO_CONFIGS)
            .where(
                SSO_CONFIGS.c.id == str(config_id),
                SSO_CONFIGS.c.org_id == str(principal.organization_id),
            )
            .values(
                issuer=body.issuer.rstrip("/")
                if body.protocol is SSOProtocol.OIDC
                else body.issuer,
                client_id=body.client_id,
                secret_ref=str(body.secret_ref) if body.secret_ref else None,
                certificate_ref=str(body.certificate_ref) if body.certificate_ref else None,
                settings=settings,
                updated_at=datetime.now(UTC),
            )
        )
        _record_config(
            session, principal, request, AuditAction.SSO_CONFIGURATION_UPDATED, str(config_id)
        )
        session.commit()
        current = _config_id(session, config_id, principal.organization_id)
        assert current is not None
        return _view(current)
    except OIDCError:
        session.rollback()
        raise HTTPException(
            status_code=422, detail="SSO provider configuration is invalid"
        ) from None


@router.post("/sso/configs/{config_id}/enable", response_model=SSOConfigView)
def enable_config(
    config_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> SSOConfigView:
    _sso_admin(principal)
    row = _config_id(session, config_id, principal.organization_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    reference = row["secret_ref"] if row["protocol"] == "oidc" else row["certificate_ref"]
    expected_type = (
        SecretType.OAUTH_CLIENT_SECRET if row["protocol"] == "oidc" else SecretType.GENERIC_SECRET
    )
    _validate_secret_reference(session, principal.organization_id, UUID(reference), expected_type)
    session.execute(
        update(SSO_CONFIGS)
        .where(
            SSO_CONFIGS.c.id == str(config_id),
            SSO_CONFIGS.c.org_id == str(principal.organization_id),
        )
        .values(enabled=True, updated_at=datetime.now(UTC))
    )
    _record_config(
        session, principal, request, AuditAction.SSO_CONFIGURATION_ENABLED, str(config_id)
    )
    session.commit()
    current = _config_id(session, config_id, principal.organization_id)
    assert current is not None
    return _view(current)


@router.post("/sso/configs/{config_id}/disable", response_model=SSOConfigView)
def disable_config(
    config_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> SSOConfigView:
    _sso_admin(principal)
    row = _config_id(session, config_id, principal.organization_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    session.execute(
        update(SSO_CONFIGS)
        .where(
            SSO_CONFIGS.c.id == str(config_id),
            SSO_CONFIGS.c.org_id == str(principal.organization_id),
        )
        .values(enabled=False, updated_at=datetime.now(UTC))
    )
    _record_config(
        session, principal, request, AuditAction.SSO_CONFIGURATION_DISABLED, str(config_id)
    )
    session.commit()
    current = _config_id(session, config_id, principal.organization_id)
    assert current is not None
    return _view(current)


@router.delete("/sso/configs/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_config(
    config_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    _sso_admin(principal)
    row = _config_id(session, config_id, principal.organization_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    _record_config(
        session, principal, request, AuditAction.SSO_CONFIGURATION_DELETED, str(config_id)
    )
    session.execute(
        delete(SSO_CONFIGS).where(
            SSO_CONFIGS.c.id == str(config_id),
            SSO_CONFIGS.c.org_id == str(principal.organization_id),
        )
    )
    session.commit()
    return Response(status_code=204)


@router.post("/sso/configs/{config_id}/identity-links", status_code=status.HTTP_201_CREATED)
def link_identity(
    config_id: UUID,
    body: IdentityLinkWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> dict[str, str]:
    _sso_admin(principal)
    row = _config_id(session, config_id, principal.organization_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    if body.issuer != row["issuer"]:
        raise HTTPException(status_code=422, detail="Identity issuer does not match the provider")
    member = session.execute(
        select(MEMBERS.c.id).where(
            MEMBERS.c.id == str(body.member_id),
            MEMBERS.c.organization_id == str(principal.organization_id),
        )
    ).scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    try:
        session.execute(
            insert(SSO_IDENTITIES).values(
                id=str(uuid4()),
                org_id=str(principal.organization_id),
                config_id=str(config_id),
                member_id=str(body.member_id),
                issuer=body.issuer,
                subject=body.subject,
                email=None,
                created_at=datetime.now(UTC),
            )
        )
        _record_config(
            session,
            principal,
            request,
            AuditAction.SSO_IDENTITY_MAPPING_CREATED,
            str(body.member_id),
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Identity link already exists") from None
    return {"status": "linked"}


def _transaction_cookie(
    response: Response,
    *,
    state: str,
    payload: dict[str, Any],
    protocol: SSOProtocol,
) -> None:
    response.set_cookie(
        cookie_name(state),
        seal(payload),
        max_age=_TRANSACTION_TTL,
        path="/",
        secure=True,
        httponly=True,
        samesite="none" if protocol is SSOProtocol.SAML else "lax",
    )


def _insert_transaction(
    session: Session,
    *,
    org_id: UUID,
    config_id: UUID,
    protocol: SSOProtocol,
    state: str,
    nonce: str,
    request_id: str | None = None,
) -> UUID:
    identifier = uuid4()
    session.execute(
        insert(SSO_TRANSACTIONS).values(
            id=str(identifier),
            org_id=str(org_id),
            config_id=str(config_id),
            protocol=protocol.value,
            state_hash=digest(state),
            nonce_hash=digest(nonce),
            request_id=request_id,
            expires_at=datetime.now(UTC) + timedelta(seconds=_TRANSACTION_TTL),
            consumed_at=None,
        )
    )
    session.commit()
    return identifier


def _consume_transaction(
    session: Session,
    *,
    state: str,
    protocol: SSOProtocol,
    org_id: UUID,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    row = (
        session.execute(
            select(SSO_TRANSACTIONS).where(
                SSO_TRANSACTIONS.c.state_hash == digest(state),
                SSO_TRANSACTIONS.c.protocol == protocol.value,
                SSO_TRANSACTIONS.c.org_id == str(org_id),
                SSO_TRANSACTIONS.c.expires_at > now,
                SSO_TRANSACTIONS.c.consumed_at.is_(None),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise StateError("SSO transaction is invalid")
    result = dict(row)
    changed_result = session.execute(
        update(SSO_TRANSACTIONS)
        .where(
            SSO_TRANSACTIONS.c.id == result["id"],
            SSO_TRANSACTIONS.c.consumed_at.is_(None),
            SSO_TRANSACTIONS.c.expires_at > now,
        )
        .values(consumed_at=now)
    )
    changed = cast(CursorResult[Any], changed_result).rowcount
    if changed != 1:
        session.rollback()
        raise StateError("SSO transaction is invalid")
    session.commit()
    return result


def _record_login(
    session: Session,
    *,
    org_id: UUID,
    action: AuditAction,
    config_id: UUID,
    context: AuditContext | None = None,
    principal: Principal | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
) -> None:
    _sso.record_event(
        session,
        principal or _system_principal(org_id),
        action=action,
        resource_type="sso_config",
        resource_id=str(config_id),
        outcome=outcome,
        metadata={"result": "success" if outcome is AuditOutcome.SUCCESS else "failed"},
        context=context,
    )


@router.get("/auth/sso/{organization_id}/login")
def start_login(
    organization_id: UUID,
    response: Response,
    session: SessionDependency,
    protocol: Annotated[SSOProtocol, Query()] = SSOProtocol.OIDC,
) -> Response:
    row = _config(session, organization_id, protocol)
    if row is None:
        raise HTTPException(status_code=404, detail="SSO is not configured")
    try:
        base = _base_url()
        state, nonce = new_secret(), new_secret()
        verifier = new_secret(48)
        state_payload = {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "config_id": row["id"],
            "org_id": str(organization_id),
            "exp": int(time.time()) + _TRANSACTION_TTL,
        }
        if protocol is SSOProtocol.OIDC:
            settings = row["settings"]
            discovery = OIDCDiscovery(
                str(row["issuer"]),
                settings["authorization_endpoint"],
                settings["token_endpoint"],
                settings["jwks_uri"],
                settings.get("token_auth_method", "client_secret_basic"),
            )
            redirect_uri = f"{base}/auth/sso/{organization_id}/oidc/callback"
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )
            target = authorization_url(
                discovery,
                client_id=str(row["client_id"]),
                redirect_uri=redirect_uri,
                scopes=settings["scopes"],
                state=state,
                nonce=nonce,
                challenge=challenge,
            )
            _insert_transaction(
                session,
                org_id=organization_id,
                config_id=UUID(row["id"]),
                protocol=protocol,
                state=state,
                nonce=nonce,
            )
        else:
            cert_ref = UUID(row["certificate_ref"])
            certificate = (
                SecretVault.from_environment()
                .get_for_trusted_service(
                    session,
                    organization_id,
                    cert_ref,
                    allowed_types=frozenset({SecretType.GENERIC_SECRET}),
                )
                .get_secret_value()
            )
            adapter = SAMLAdapter(base_url=base, organization_id=str(organization_id))
            target, request_id = adapter.start(
                issuer=str(row["issuer"]),
                sso_url=row["settings"]["sso_url"],
                certificate=certificate,
                relay_state=state,
            )
            _insert_transaction(
                session,
                org_id=organization_id,
                config_id=UUID(row["id"]),
                protocol=protocol,
                state=state,
                nonce=nonce,
                request_id=request_id,
            )
        _record_login(
            session,
            org_id=organization_id,
            action=AuditAction.SSO_LOGIN_STARTED,
            config_id=UUID(row["id"]),
        )
        session.commit()
        result = RedirectResponse(
            target,
            status_code=302,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
        _transaction_cookie(result, state=state, payload=state_payload, protocol=protocol)
        return result
    except (OIDCError, StateError, VaultOperationFailed, ValueError):
        session.rollback()
        raise HTTPException(status_code=503, detail="SSO is unavailable") from None


def _state_payload(request: Request, state: str) -> dict[str, Any]:
    if not state or len(state) > 256:
        raise StateError("SSO transaction is invalid")
    value = request.cookies.get(cookie_name(state))
    if value is None:
        raise StateError("SSO transaction is invalid")
    payload = open_cookie(value, state=state)
    if digest(str(payload["nonce"])) == digest(""):
        raise StateError("SSO transaction is invalid")
    return payload


def _validated_payload(
    request: Request, state: str, org_id: UUID, protocol: SSOProtocol
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _state_payload(request, state)
    if payload["org_id"] != str(org_id):
        raise StateError("SSO transaction is invalid")
    transaction = _consume_transaction(
        request.state.sso_session,
        state=state,
        protocol=protocol,
        org_id=org_id,
    )
    if (
        transaction["config_id"] != payload["config_id"]
        or digest(payload["nonce"]) != transaction["nonce_hash"]
    ):
        raise StateError("SSO transaction is invalid")
    return payload, transaction


def _success_redirect(
    *,
    session: Session,
    org_id: UUID,
    config: dict[str, Any],
    protocol: SSOProtocol,
    identity: OIDCIdentity,
    context: AuditContext,
    assertion_id: str | None = None,
    assertion_expiry: datetime | None = None,
) -> RedirectResponse:
    if assertion_id is not None:
        session.execute(
            insert(SSO_REPLAYS).values(
                org_id=str(org_id),
                config_id=config["id"],
                assertion_id=assertion_id,
                expires_at=assertion_expiry or datetime.now(UTC) + timedelta(minutes=5),
            )
        )
    settings = config["settings"]
    subject_id, role, _created = map_identity(
        session,
        organization_id=org_id,
        config_id=UUID(config["id"]),
        protocol=protocol,
        identity=identity,
        claimed_domains=settings["claimed_domains"],
    )
    principal = Principal(
        organization_id=org_id,
        subject_id=subject_id,
        actor_type=ActorType.USER,
        role=role,
        scopes=(),
        auth_method=AuthMethod.SSO,
    )
    _record_login(
        session,
        org_id=org_id,
        action=AuditAction.SSO_LOGIN_SUCCESS,
        config_id=UUID(config["id"]),
        context=context,
        principal=principal,
    )
    auth_settings = AuthSettings.from_env()
    secret = auth_settings.sso_token_secret
    if secret is None or len(secret.encode()) < 32:
        raise OIDCError("SSO access token is not configured")
    token = issue_access_token(
        subject_id,
        org_id,
        secret=secret,
        issuer=auth_settings.sso_token_issuer,
        audience=auth_settings.sso_token_audience,
    )
    session.commit()
    frontend = _frontend_url()
    return RedirectResponse(
        f"{frontend}#sso_token={token}",
        status_code=303,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        },
    )


def _clear_state_cookie(response: Response, state: str, protocol: SSOProtocol) -> None:
    response.delete_cookie(
        cookie_name(state),
        path="/",
        secure=True,
        httponly=True,
        samesite="none" if protocol is SSOProtocol.SAML else "lax",
    )


def _record_login_failure(session: Session, org_id: UUID, protocol: SSOProtocol) -> None:
    """Record a safe callback failure when the tenant has an enabled provider."""
    try:
        row = _config(session, org_id, protocol)
        if row is not None:
            _record_login(
                session,
                org_id=org_id,
                action=AuditAction.SSO_LOGIN_FAILED,
                config_id=UUID(row["id"]),
                outcome=AuditOutcome.FAILURE,
            )
            session.commit()
    except Exception:
        session.rollback()


@router.get("/auth/sso/{organization_id}/oidc/callback")
def oidc_callback(
    organization_id: UUID,
    request: Request,
    session: SessionDependency,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    state: Annotated[str | None, Query(max_length=256)] = None,
    error: Annotated[str | None, Query(max_length=64)] = None,
) -> Response:
    request.state.sso_session = session
    try:
        if error is not None or code is None or state is None:
            raise StateError("SSO response is invalid")
        payload, _transaction = _validated_payload(
            request, state, organization_id, SSOProtocol.OIDC
        )
        config = _config(session, organization_id, SSOProtocol.OIDC)
        if config is None or config["id"] != payload["config_id"]:
            raise StateError("SSO transaction is invalid")
        secret = (
            SecretVault.from_environment()
            .get_for_trusted_service(
                session,
                organization_id,
                UUID(config["secret_ref"]),
                allowed_types=frozenset({SecretType.OAUTH_CLIENT_SECRET}),
            )
            .get_secret_value()
        )
        settings = config["settings"]
        discovery = OIDCDiscovery(
            config["issuer"],
            settings["authorization_endpoint"],
            settings["token_endpoint"],
            settings["jwks_uri"],
            settings.get("token_auth_method", "client_secret_basic"),
        )
        identity = exchange_and_validate(
            discovery,
            code=code,
            client_id=config["client_id"],
            client_secret=secret,
            redirect_uri=f"{_base_url()}/auth/sso/{organization_id}/oidc/callback",
            verifier=payload["verifier"],
            expected_nonce=payload["nonce"],
        )
        response = _success_redirect(
            session=session,
            org_id=organization_id,
            config=config,
            protocol=SSOProtocol.OIDC,
            identity=identity,
            context=context_from_request(request),
        )
        _clear_state_cookie(response, state, SSOProtocol.OIDC)
        return response
    except Exception:
        session.rollback()
        _record_login_failure(session, organization_id, SSOProtocol.OIDC)
        response = RedirectResponse(
            f"{_frontend_url()}#sso_error=authentication_failed",
            status_code=303,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
        if state:
            _clear_state_cookie(response, state, SSOProtocol.OIDC)
        return response


async def _read_saml_form(request: Request) -> dict[str, str]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].lower()
        != "application/x-www-form-urlencoded"
    ):
        raise HTTPException(status_code=415, detail="SSO response is invalid")
    parts: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > _MAX_SAML_BODY:
            raise HTTPException(status_code=413, detail="SSO response is invalid")
        parts.append(chunk)
    try:
        parsed = parse_qs(b"".join(parts).decode("ascii"), keep_blank_values=True, max_num_fields=8)
        if any(len(values) != 1 for values in parsed.values()):
            raise ValueError
        values = {key: value[0] for key, value in parsed.items() if value}
        if not values.get("SAMLResponse") or len(values["SAMLResponse"]) > _MAX_SAML_BODY:
            raise ValueError
        return values
    except Exception:
        raise HTTPException(status_code=400, detail="SSO response is invalid") from None


@router.post("/auth/sso/{organization_id}/saml/acs")
async def saml_acs(
    organization_id: UUID,
    request: Request,
    session: SessionDependency,
) -> Response:
    request.state.sso_session = session
    form = await _read_saml_form(request)
    state = form.get("RelayState")
    try:
        if not state:
            raise StateError("SSO response is invalid")
        payload, transaction = _validated_payload(request, state, organization_id, SSOProtocol.SAML)
        config = _config(session, organization_id, SSOProtocol.SAML)
        if config is None or config["id"] != payload["config_id"]:
            raise StateError("SSO transaction is invalid")
        settings = config["settings"]
        attributes = settings.get("attributes", {})
        certificate = (
            SecretVault.from_environment()
            .get_for_trusted_service(
                session,
                organization_id,
                UUID(config["certificate_ref"]),
                allowed_types=frozenset({SecretType.GENERIC_SECRET}),
            )
            .get_secret_value()
        )
        adapter = SAMLAdapter(base_url=_base_url(), organization_id=str(organization_id))
        identity, assertion_id, expiry = adapter.validate_response(
            issuer=config["issuer"],
            sso_url=settings["sso_url"],
            certificate=certificate,
            response=form["SAMLResponse"],
            relay_state=state,
            request_id=str(transaction["request_id"]),
            email_attribute=attributes.get("email", "email"),
            verified_attribute=attributes.get("email_verified", "email_verified"),
            name_attribute=attributes.get("display_name"),
        )
        response = _success_redirect(
            session=session,
            org_id=organization_id,
            config=config,
            protocol=SSOProtocol.SAML,
            identity=identity,
            context=context_from_request(request),
            assertion_id=assertion_id,
            assertion_expiry=expiry,
        )
        _clear_state_cookie(response, state, SSOProtocol.SAML)
        return response
    except Exception:
        session.rollback()
        _record_login_failure(session, organization_id, SSOProtocol.SAML)
        response = RedirectResponse(
            f"{_frontend_url()}#sso_error=authentication_failed",
            status_code=303,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
        if state:
            _clear_state_cookie(response, state, SSOProtocol.SAML)
        return response


@router.get("/auth/sso/saml/{organization_id}/metadata")
def saml_metadata(
    organization_id: UUID,
    session: SessionDependency,
) -> Response:
    config = _config(session, organization_id, SSOProtocol.SAML)
    if config is None:
        raise HTTPException(status_code=404, detail="SSO is not configured")
    try:
        cert = (
            SecretVault.from_environment()
            .get_for_trusted_service(
                session,
                organization_id,
                UUID(config["certificate_ref"]),
                allowed_types=frozenset({SecretType.GENERIC_SECRET}),
            )
            .get_secret_value()
        )
        xml = SAMLAdapter(base_url=_base_url(), organization_id=str(organization_id)).metadata(
            issuer=config["issuer"], sso_url=config["settings"]["sso_url"], certificate=cert
        )
    except Exception:
        raise HTTPException(status_code=503, detail="SSO metadata is unavailable") from None
    return Response(
        xml, media_type="application/samlmetadata+xml", headers={"Cache-Control": "no-store"}
    )
