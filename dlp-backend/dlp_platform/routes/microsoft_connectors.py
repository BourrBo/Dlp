"""Microsoft OAuth and SharePoint library selection for P17 connectors."""

from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from dlp_platform.audit.service import AuditService, context_from_request
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.connectors.microsoft_graph import (
    MICROSOFT_LOGIN_HOSTS,
    MICROSOFT_SCOPES,
    MicrosoftGraphAPI,
    MicrosoftHTTPTransport,
    MicrosoftOAuthClient,
    MicrosoftOAuthSettings,
    MicrosoftProviderFailure,
)
from dlp_platform.connectors.oauth import (
    OAuthRejected,
    PersistentOAuthTransactions,
    authorization_url,
)
from dlp_platform.connectors.service import ConnectorOperationFailed, ConnectorService
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.common import ActorType
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter
from dlp_platform.routes.p06_support import rate_limit_p06
from dlp_platform.tables import APP_SESSIONS, DLP_CONNECTOR_STATE, DLP_CONNECTORS, MEMBERS
from dlp_platform.vault.config import VaultConfigurationError
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault, VaultOperationFailed

router = APIRouter(prefix="/connectors", tags=["connectors"])
SessionDependency = Annotated[Session, Depends(get_session)]
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]
_service = ConnectorService()
_transactions = PersistentOAuthTransactions()


class SiteSearch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=200)
    page_link: str | None = Field(default=None, max_length=8192)


class DriveList(BaseModel):
    model_config = ConfigDict(extra="forbid")
    site_id: str = Field(min_length=1, max_length=1024)
    page_link: str | None = Field(default=None, max_length=8192)


class LibrarySelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    site_id: str = Field(min_length=1, max_length=1024)
    drive_id: str = Field(min_length=1, max_length=1024)


def _interactive(principal: Principal, permission: Permission) -> None:
    require_permission(principal, permission)
    if principal.actor_type is not ActorType.USER:
        raise HTTPException(status_code=403, detail="Interactive user session required")


def _settings() -> tuple[MicrosoftOAuthSettings, MicrosoftOAuthClient]:
    try:
        settings = MicrosoftOAuthSettings.from_environment()
    except MicrosoftProviderFailure:
        raise HTTPException(status_code=503, detail="Microsoft Graph is not configured") from None
    return settings, MicrosoftOAuthClient(settings, MicrosoftHTTPTransport())


def _api(session: Session, principal: Principal, connector_id: UUID) -> MicrosoftGraphAPI:
    secret_id, _, _ = _service.sync_inputs(session, principal, connector_id)
    config = _service.configuration(session, principal, connector_id)
    tenant_id = config.get("microsoft_tenant_id")
    if not isinstance(tenant_id, str):
        raise HTTPException(status_code=409, detail="Microsoft connector configuration is invalid")
    try:
        refresh_token = (
            SecretVault.from_environment()
            .get_for_trusted_service(
                session,
                principal.organization_id,
                secret_id,
                allowed_types=frozenset({SecretType.REFRESH_TOKEN}),
            )
            .get_secret_value()
        )
        _, oauth = _settings()
        token = oauth.refresh(refresh_token, tenant_id)
    except (VaultConfigurationError, VaultOperationFailed, MicrosoftProviderFailure):
        raise HTTPException(status_code=503, detail="Microsoft connector unavailable") from None
    access_token = token.get("access_token")
    if not isinstance(access_token, str):
        raise HTTPException(status_code=503, detail="Microsoft connector unavailable")
    api = MicrosoftGraphAPI(access_token, tenant_id)
    if api.organization_tenant_id() != str(UUID(tenant_id)):
        raise HTTPException(status_code=403, detail="Microsoft tenant verification failed")
    return api


@router.post(
    "/{connector_id}/microsoft/oauth/start",
    status_code=status.HTTP_303_SEE_OTHER,
    dependencies=[Depends(rate_limit_p06)],
)
def start_microsoft_oauth(
    connector_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> RedirectResponse:
    _interactive(principal, Permission.CONNECTORS_WRITE)
    if principal.member_id is None or principal.session_id is None:
        raise HTTPException(status_code=403, detail="Interactive user session required")
    connector = _service.get(session, principal, connector_id)
    if connector.identity.provider not in {"microsoft_onedrive", "microsoft_sharepoint"}:
        raise HTTPException(status_code=404, detail="Connector not found")
    config = _service.configuration(session, principal, connector_id)
    tenant_id = config.get("microsoft_tenant_id")
    if not isinstance(tenant_id, str):
        raise HTTPException(status_code=409, detail="Microsoft tenant configuration is invalid")
    settings, _ = _settings()
    scopes = (
        MICROSOFT_SCOPES
        if connector.identity.provider == "microsoft_sharepoint"
        else tuple(scope for scope in MICROSOFT_SCOPES if scope != "Sites.ReadWrite.All")
    )
    try:
        transaction, challenge = _transactions.create(
            session,
            organization_id=principal.organization_id,
            principal_id=principal.subject_id,
            binding_id=str(connector_id),
            role=principal.role,
            member_id=principal.member_id,
            session_id=principal.session_id,
            scopes=principal.scopes,
            auth_method=principal.auth_method,
            provider="microsoft_graph",
            redirect_uri=settings.redirect_uri,
        )
        url = authorization_url(
            endpoint=f"{MicrosoftOAuthSettings.authority(tenant_id)}/authorize",
            allowed_hosts=MICROSOFT_LOGIN_HOSTS,
            client_id=settings.client_id,
            redirect_uri=settings.redirect_uri,
            scopes=scopes,
            state=transaction.state,
            challenge=challenge,
        )
        _service.begin_connect(session, principal, connector_id)
    except (OAuthRejected, MicrosoftProviderFailure):
        raise HTTPException(status_code=503, detail="Microsoft OAuth is unavailable") from None
    return RedirectResponse(url, status_code=303, headers={"Cache-Control": "no-store"})


@router.get("/oauth/microsoft/callback", name="microsoft_graph_oauth_callback")
def microsoft_oauth_callback(
    request: Request,
    response: Response,
    session: SessionDependency,
    limiter: LimiterDependency,
    state: str,
    code: str | None = None,
    error: str | None = None,
) -> object:
    response.headers["Cache-Control"] = "no-store"
    ip = request.client.host if request.client is not None else "unknown"
    outcome = limiter.check(f"oauth-microsoft:{ip}", "oauth-microsoft-callback")
    if not outcome.allowed:
        raise HTTPException(
            429, "Rate limit exceeded", headers={"Retry-After": str(outcome.retry_after)}
        )
    try:
        transaction = _transactions.consume_callback(session, state, provider="microsoft_graph")
    except OAuthRejected:
        raise HTTPException(status_code=400, detail="OAuth state is invalid or expired") from None
    if any(
        value is None
        for value in (
            transaction.binding_id,
            transaction.role,
            transaction.member_id,
            transaction.session_id,
            transaction.auth_method,
        )
    ):
        raise HTTPException(status_code=400, detail="OAuth state is invalid or expired")
    assert transaction.role is not None
    assert transaction.member_id is not None
    assert transaction.session_id is not None
    assert transaction.auth_method is not None
    principal = Principal(
        organization_id=transaction.organization_id,
        subject_id=transaction.principal_id,
        actor_type=ActorType.USER,
        role=transaction.role,
        scopes=transaction.scopes,
        auth_method=transaction.auth_method,
        member_id=transaction.member_id,
        session_id=transaction.session_id,
    )
    connector_id = UUID(transaction.binding_id)
    valid = session.execute(
        select(MEMBERS.c.id)
        .join(APP_SESSIONS, APP_SESSIONS.c.member_id == MEMBERS.c.id)
        .where(
            MEMBERS.c.id == str(principal.member_id),
            MEMBERS.c.organization_id == str(principal.organization_id),
            MEMBERS.c.auth_subject_id == principal.subject_id,
            MEMBERS.c.role == principal.role.value,
            MEMBERS.c.active.is_(True),
            APP_SESSIONS.c.id == str(principal.session_id),
            APP_SESSIONS.c.org_id == str(principal.organization_id),
            APP_SESSIONS.c.revoked_at.is_(None),
            APP_SESSIONS.c.expires_at > datetime.now(UTC),
        )
    ).scalar_one_or_none()
    if valid is None:
        raise HTTPException(status_code=401, detail="OAuth initiator session is no longer active")
    try:
        connector = _service.get(session, principal, connector_id)
    except HTTPException:
        raise HTTPException(status_code=400, detail="OAuth state is invalid or expired") from None
    if connector.identity.provider not in {"microsoft_onedrive", "microsoft_sharepoint"}:
        raise HTTPException(status_code=400, detail="OAuth state is invalid or expired")
    if error or not code:
        _service.mark_connect_failed(
            session, principal, connector_id, context_from_request(request)
        )
        raise HTTPException(status_code=400, detail="Microsoft authorization was not completed")
    secret_id: UUID | None = None
    try:
        config = _service.configuration(session, principal, connector_id)
        tenant_id = config.get("microsoft_tenant_id")
        if not isinstance(tenant_id, str):
            raise MicrosoftProviderFailure("invalid_provider_configuration")
        _, oauth = _settings()
        token = oauth.exchange(code, transaction.verifier, transaction.redirect_uri, tenant_id)
        refresh = token.get("refresh_token")
        access = token.get("access_token")
        token_type = token.get("token_type")
        scopes = set(str(token.get("scope", "")).split())
        if (
            not isinstance(refresh, str)
            or not isinstance(access, str)
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
            or not {"User.Read", "Files.ReadWrite.All"}.issubset(scopes)
            or (
                connector.identity.provider == "microsoft_sharepoint"
                and "Sites.ReadWrite.All" not in scopes
            )
        ):
            raise MicrosoftProviderFailure("invalid_oauth_response")
        api = MicrosoftGraphAPI(access, tenant_id)
        if api.organization_tenant_id() != str(UUID(tenant_id)):
            raise MicrosoftProviderFailure("tenant_mismatch")
        drive_id: str | None = None
        state_json: dict[str, object]
        if _service.get(session, principal, connector_id).identity.provider == "microsoft_onedrive":
            drive_id = api.onedrive_id()
            state_json = {
                "drive_id": drive_id,
                "delta_link": None,
                "initial_inventory_pending": False,
            }
        else:
            state_json = {"library_selection_required": True, "delta_link": None}
        vault = SecretVault.from_environment()
        secret = vault.set(
            session,
            principal,
            name=f"microsoft-drive-{connector_id}",
            secret_type=SecretType.REFRESH_TOKEN,
            value=SecretStr(refresh),
            expires_at=None,
            audit_context=context_from_request(request),
        )
        secret_id = secret.secret_id
        _service.set_connection(
            session,
            principal,
            connector_id,
            secret_id=secret.secret_id,
            checkpoint="microsoft_graph_delta_v1",
            state_json=state_json,
            audit_context=context_from_request(request),
        )
        response.status_code = 303
        response.headers["Location"] = "/settings/connectors?connected=microsoft"
        return {
            "status": "connected",
            "provider": "microsoft_graph",
            "connector_id": str(connector_id),
        }
    except (
        MicrosoftProviderFailure,
        VaultConfigurationError,
        VaultOperationFailed,
        ConnectorOperationFailed,
    ):
        session.rollback()
        if secret_id:
            with suppress(Exception):
                vault.disable(
                    session, principal, secret_id, audit_context=context_from_request(request)
                )
        with suppress(Exception):
            _service.mark_connect_failed(
                session, principal, connector_id, context_from_request(request)
            )
        raise HTTPException(
            status_code=400, detail="Microsoft connection could not be completed"
        ) from None


@router.post("/{connector_id}/microsoft/sites/search", dependencies=[Depends(rate_limit_p06)])
def search_sharepoint_sites(
    connector_id: UUID,
    body: SiteSearch,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal, Permission.CONNECTORS_WRITE)
    response.headers["Cache-Control"] = "no-store"
    if _service.get(session, principal, connector_id).identity.provider != "microsoft_sharepoint":
        raise HTTPException(status_code=404, detail="Connector not found")
    try:
        sites, next_link = _api(session, principal, connector_id).search_sites(
            body.query, page_link=body.page_link
        )
        return {"sites": sites, "next_link": next_link}
    except MicrosoftProviderFailure:
        raise HTTPException(status_code=502, detail="Microsoft site search failed") from None


@router.post("/{connector_id}/microsoft/sites/drives", dependencies=[Depends(rate_limit_p06)])
def list_sharepoint_drives(
    connector_id: UUID,
    body: DriveList,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal, Permission.CONNECTORS_WRITE)
    response.headers["Cache-Control"] = "no-store"
    if _service.get(session, principal, connector_id).identity.provider != "microsoft_sharepoint":
        raise HTTPException(status_code=404, detail="Connector not found")
    try:
        drives, next_link = _api(session, principal, connector_id).list_site_drives(
            body.site_id, page_link=body.page_link
        )
        return {"drives": drives, "next_link": next_link}
    except MicrosoftProviderFailure:
        raise HTTPException(status_code=502, detail="Microsoft library listing failed") from None


@router.put("/{connector_id}/microsoft/library", dependencies=[Depends(rate_limit_p06)])
def select_sharepoint_library(
    connector_id: UUID,
    body: LibrarySelection,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal, Permission.CONNECTORS_WRITE)
    response.headers["Cache-Control"] = "no-store"
    if _service.get(session, principal, connector_id).identity.provider != "microsoft_sharepoint":
        raise HTTPException(status_code=404, detail="Connector not found")
    api = _api(session, principal, connector_id)
    try:
        page_link: str | None = None
        seen_links: set[str] = set()
        selected = False
        for _ in range(10):
            drives, next_link = api.list_site_drives(body.site_id, page_link=page_link)
            if any(row["id"] == body.drive_id for row in drives):
                selected = True
                break
            if next_link is None:
                break
            if next_link in seen_links:
                raise HTTPException(status_code=502, detail="Microsoft library listing failed")
            seen_links.add(next_link)
            page_link = next_link
        # Do not accept a caller-selected drive unless the tenant API returned it.
        if not selected:
            raise HTTPException(status_code=422, detail="Select a library from the returned list")
        config = _service.configuration(session, principal, connector_id)
        config.update({"sharepoint_site_id": body.site_id, "sharepoint_drive_id": body.drive_id})
        _service._rls(session, principal)
        updated = session.execute(
            update(DLP_CONNECTORS)
            .where(
                DLP_CONNECTORS.c.id == str(connector_id),
                DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                DLP_CONNECTORS.c.provider == "microsoft_sharepoint",
            )
            .values(config_json=config, updated_at=datetime.now(UTC))
        )
        if getattr(updated, "rowcount", 0) != 1:
            session.rollback()
            raise HTTPException(status_code=404, detail="Connector not found")
        state_update = session.execute(
            update(DLP_CONNECTOR_STATE)
            .where(
                DLP_CONNECTOR_STATE.c.connector_id == str(connector_id),
                DLP_CONNECTOR_STATE.c.org_id == str(principal.organization_id),
                DLP_CONNECTOR_STATE.c.provider == "microsoft_sharepoint",
            )
            .values(
                checkpoint="microsoft_graph_delta_v1",
                state_json={
                    "library_selection_required": False,
                    "site_id": body.site_id,
                    "drive_id": body.drive_id,
                    "delta_link": None,
                },
                updated_at=datetime.now(UTC),
            )
        )
        if getattr(state_update, "rowcount", 0) != 1:
            session.rollback()
            raise HTTPException(status_code=404, detail="Connector not found")
        AuditService().record_event(
            session,
            principal,
            action=AuditAction.CONNECTOR_MICROSOFT_LIBRARY_SELECTED,
            resource_type="connector",
            resource_id=str(connector_id),
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "provider": "microsoft_sharepoint",
                "site_id": body.site_id,
                "drive_id": body.drive_id,
            },
            context=context_from_request(request),
        )
        session.commit()
        return {
            "connector_id": str(connector_id),
            "site_id": body.site_id,
            "drive_id": body.drive_id,
        }
    except HTTPException:
        raise
    except MicrosoftProviderFailure:
        session.rollback()
        raise HTTPException(status_code=502, detail="Microsoft library validation failed") from None
