"""Minimal tenant-scoped P16 connector management and Google OAuth callback."""

import json
from contextlib import suppress
from datetime import UTC, datetime
from typing import Annotated, NoReturn
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from dlp_platform.audit.service import AuditService, context_from_request
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.connectors.google_drive import (
    GOOGLE_AUTHORIZATION_ENDPOINT,
    GOOGLE_DRIVE_SCOPE,
    GOOGLE_OAUTH_HOSTS,
    GoogleDriveAPI,
    GoogleOAuthClient,
    GoogleOAuthSettings,
    GoogleTransport,
    ProviderFailure,
)
from dlp_platform.connectors.models import ConnectorIdentity, DriveObject, SyncRequest
from dlp_platform.connectors.oauth import (
    OAuthRejected,
    PersistentOAuthTransactions,
    authorization_url,
)
from dlp_platform.connectors.service import ConnectorOperationFailed, ConnectorService
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.common import ActorType, DataChannel, PolicyAction
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter
from dlp_platform.routes.p06_support import rate_limit_p06
from dlp_platform.scan.pipeline import scan
from dlp_platform.tables import ACTIONS, APP_SESSIONS, DLP_CONNECTORS, MEMBERS
from dlp_platform.vault.config import VaultConfigurationError
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault, VaultOperationFailed

router = APIRouter(prefix="/connectors", tags=["connectors"])
SessionDependency = Annotated[Session, Depends(get_session)]
_oauth_transactions = PersistentOAuthTransactions()
_service = ConnectorService()
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]


class ConnectorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(pattern=r"^(google_drive|microsoft_onedrive|microsoft_sharepoint)$")
    name: str = Field(min_length=1, max_length=120)
    microsoft_tenant_id: UUID | None = None


class ShareRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    object_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,1024}$")
    permission_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,1024}$")


class QuarantineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    object_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,1024}$")


def _vault() -> SecretVault:
    try:
        return SecretVault.from_environment()
    except VaultConfigurationError:
        raise HTTPException(status_code=503, detail="Vault is not configured") from None


def _require_interactive_write(principal: Principal) -> None:
    require_permission(principal, Permission.CONNECTORS_WRITE)
    if principal.actor_type is not ActorType.USER:
        raise HTTPException(status_code=403, detail="Interactive user session required")


def _oauth() -> tuple[GoogleOAuthSettings, GoogleOAuthClient]:
    try:
        settings = GoogleOAuthSettings.from_environment()
    except ProviderFailure:
        raise HTTPException(status_code=503, detail="Google Drive is not configured") from None
    return settings, GoogleOAuthClient(settings, GoogleTransport())


def _fail(error: Exception) -> NoReturn:
    if isinstance(error, ConnectorOperationFailed):
        raise HTTPException(status_code=503, detail="Connector operation failed") from None
    if isinstance(error, VaultOperationFailed):
        raise HTTPException(status_code=503, detail="Vault operation failed") from None
    raise error


@router.get("", dependencies=[Depends(rate_limit_p06)])
def list_connectors(
    response: Response, principal: CurrentPrincipal, session: SessionDependency
) -> list[object]:
    response.headers["Cache-Control"] = "no-store"
    try:
        return [row.model_dump(mode="json") for row in _service.list(session, principal)]
    except Exception as exc:
        _fail(exc)


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit_p06)])
def create_connector(
    body: ConnectorCreate,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    response.headers["Cache-Control"] = "no-store"
    _require_interactive_write(principal)
    microsoft_provider = body.provider in {"microsoft_onedrive", "microsoft_sharepoint"}
    if microsoft_provider != (body.microsoft_tenant_id is not None):
        raise HTTPException(
            status_code=422,
            detail="Microsoft connectors require a Microsoft tenant ID; other providers forbid it",
        )
    config: dict[str, object] = (
        {"microsoft_tenant_id": str(body.microsoft_tenant_id)}
        if body.microsoft_tenant_id is not None
        else {}
    )
    try:
        result = _service.create(
            session,
            principal,
            provider=body.provider,
            name=body.name,
            config=config,
            audit_context=context_from_request(request),
        )
        return result.model_dump(mode="json")
    except Exception as exc:
        _fail(exc)


@router.get("/{connector_id}", dependencies=[Depends(rate_limit_p06)])
def connector_status(
    connector_id: UUID, response: Response, principal: CurrentPrincipal, session: SessionDependency
) -> object:
    response.headers["Cache-Control"] = "no-store"
    try:
        return _service.get(session, principal, connector_id).model_dump(mode="json")
    except Exception as exc:
        _fail(exc)


@router.post(
    "/{connector_id}/oauth/start",
    status_code=status.HTTP_303_SEE_OTHER,
    dependencies=[Depends(rate_limit_p06)],
)
def start_google_oauth(
    connector_id: UUID, principal: CurrentPrincipal, session: SessionDependency
) -> RedirectResponse:
    _require_interactive_write(principal)
    if (
        principal.actor_type is not ActorType.USER
        or principal.member_id is None
        or principal.session_id is None
    ):
        raise HTTPException(status_code=403, detail="Interactive user session required")
    connector = _service.get(session, principal, connector_id)
    if connector.identity.provider != "google_drive":
        raise HTTPException(status_code=404, detail="Connector not found")
    settings, _ = _oauth()
    transaction, challenge = _oauth_transactions.create(
        session,
        organization_id=principal.organization_id,
        principal_id=principal.subject_id,
        binding_id=str(connector_id),
        role=principal.role,
        member_id=principal.member_id,
        session_id=principal.session_id,
        scopes=principal.scopes,
        auth_method=principal.auth_method,
        provider="google_drive",
        redirect_uri=settings.redirect_uri,
    )
    url = authorization_url(
        endpoint=GOOGLE_AUTHORIZATION_ENDPOINT,
        allowed_hosts=GOOGLE_OAUTH_HOSTS,
        client_id=settings.client_id,
        redirect_uri=settings.redirect_uri,
        scopes=(GOOGLE_DRIVE_SCOPE,),
        state=transaction.state,
        challenge=challenge,
    )
    _service.begin_connect(session, principal, connector_id)
    return RedirectResponse(
        url, status_code=status.HTTP_303_SEE_OTHER, headers={"Cache-Control": "no-store"}
    )


@router.get("/oauth/google/callback", name="google_drive_oauth_callback")
def google_oauth_callback(
    request: Request,
    response: Response,
    session: SessionDependency,
    vault: Annotated[SecretVault, Depends(_vault)],
    limiter: LimiterDependency,
    state: str,
    code: str | None = None,
    error: str | None = None,
) -> object:
    response.headers["Cache-Control"] = "no-store"
    client_ip = request.client.host if request.client is not None else "unknown"
    result = limiter.check(f"oauth-google:{client_ip}", "oauth-google-callback")
    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(result.retry_after)},
        )
    if not state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    # Browser provider redirects do not carry the application's Bearer header.
    # The one-time persistent OAuth state is the callback capability and binds
    # this request to its authenticated initiating tenant/principal/session.
    try:
        transaction = _oauth_transactions.consume_callback(session, state, provider="google_drive")
    except OAuthRejected:
        raise HTTPException(status_code=400, detail="OAuth state is invalid or expired") from None
    if (
        transaction.binding_id is None
        or transaction.role is None
        or transaction.member_id is None
        or transaction.session_id is None
        or transaction.auth_method is None
    ):
        raise HTTPException(status_code=400, detail="OAuth state is invalid or expired")
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
    session_valid = session.execute(
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
    if session_valid is None:
        raise HTTPException(status_code=401, detail="OAuth initiator session is no longer active")
    if error or not code:
        _service.mark_connect_failed(
            session, principal, connector_id, context_from_request(request)
        )
        raise HTTPException(status_code=400, detail="Google authorization was not completed")
    _, oauth = _oauth()
    secret_id: UUID | None = None
    try:
        token = oauth.exchange(code, transaction.verifier, transaction.redirect_uri)
        access_token, refresh_token = token.get("access_token"), token.get("refresh_token")
        scopes = set(str(token.get("scope", "")).split())
        token_type = token.get("token_type", "Bearer")
        if (
            not isinstance(token_type, str)
            or token_type.lower() != "bearer"
            or not isinstance(access_token, str)
            or not isinstance(refresh_token, str)
            or GOOGLE_DRIVE_SCOPE not in scopes
        ):
            raise ProviderFailure("invalid_oauth_response")
        checkpoint = GoogleDriveAPI(access_token).get_start_page_token()
        _service._rls(session, principal)
        secret = vault.set(
            session,
            principal,
            name=f"google-drive-{connector_id}",
            secret_type=SecretType.REFRESH_TOKEN,
            value=SecretStr(refresh_token),
            expires_at=None,
            audit_context=context_from_request(request),
        )
        secret_id = secret.secret_id
        _service.set_connection(
            session,
            principal,
            connector_id,
            secret_id=secret.secret_id,
            checkpoint=checkpoint,
            audit_context=context_from_request(request),
        )
        response.status_code = status.HTTP_303_SEE_OTHER
        response.headers["Location"] = "/settings/connectors?connected=google_drive"
        return {
            "status": "connected",
            "provider": "google_drive",
            "connector_id": str(connector_id),
        }
    except (
        ProviderFailure,
        VaultOperationFailed,
        ConnectorOperationFailed,
        VaultConfigurationError,
    ):
        session.rollback()
        if secret_id is not None:
            _service._rls(session, principal)
            with suppress(VaultOperationFailed):
                vault.disable(
                    session,
                    principal,
                    secret_id,
                    audit_context=context_from_request(request),
                )
        with suppress(ConnectorOperationFailed):
            _service.mark_connect_failed(
                session, principal, connector_id, context_from_request(request)
            )
        raise HTTPException(status_code=503, detail="Google Drive connection failed") from None


def _scan_drive_object(
    principal: Principal,
    connector_id: UUID,
    obj: DriveObject,
    *,
    session: Session | None = None,
    extra_context: dict[str, str] | None = None,
    request_id_suffix: str | None = None,
    provider: str = "google_drive",
    trusted_action_metadata: dict[str, str] | None = None,
) -> dict[str, object]:
    """Send normalized Drive metadata through the existing P04/P1/P05/P07 pipeline."""
    metadata = obj.model_dump(mode="json", exclude_none=True)
    content = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    request_id = uuid5(
        NAMESPACE_URL,
        (
            f"dlp-p16-drive:{principal.organization_id}:{connector_id}:"
            f"{obj.object_id}:{content}:{request_id_suffix or ''}"
        ),
    )
    safe_extra_context = {
        key: value
        for key, value in (extra_context or {}).items()
        if key in {"permission_id", "requested_action"} and isinstance(value, str)
    }
    request = ScanRequest(
        request_id=request_id,
        channel=DataChannel.CLOUD_STORAGE,
        destination=str(obj.web_view_link) if obj.web_view_link else None,
        content=SecretStr(content),
        context={
            "provider": provider,
            "organization_id": str(principal.organization_id),
            "connector_id": str(connector_id),
            "object_id": obj.object_id,
            "drive_object_id": obj.object_id,
            **safe_extra_context,
        },
    )
    if extra_context is not None:
        request._trusted_action_metadata = {
            "provider": provider,
            "connector_id": str(connector_id),
            "drive_object_id": obj.object_id,
            **(
                {"permission_id": extra_context["permission_id"]}
                if isinstance(extra_context.get("permission_id"), str)
                else {}
            ),
            **(trusted_action_metadata or {}),
        }
    result = scan(request, principal)
    action_status = "not_executed"
    if "P07 action status=" in result.reason:
        action_status = result.reason.rsplit("P07 action status=", 1)[1].split(".", 1)[0]
    normalized_result: dict[str, object] = {
        "object_id": obj.object_id,
        "decision": result.decision.value,
        "finding_count": len(result.findings),
        "action_status": action_status,
        "request_id": str(request_id),
    }
    if result.decision is PolicyAction.REVOKE_SHARE:
        action_id = uuid5(
            NAMESPACE_URL,
            f"dlp-p07:{principal.organization_id}:{request_id}:{PolicyAction.REVOKE_SHARE.value}",
        )
        if session is not None:
            _service._rls(session, principal)
            persisted_status = session.execute(
                select(ACTIONS.c.status).where(
                    ACTIONS.c.id == str(action_id),
                    ACTIONS.c.org_id == str(principal.organization_id),
                )
            ).scalar_one_or_none()
            if persisted_status is not None:
                action_status = str(persisted_status)
                normalized_result["action_status"] = action_status
        normalized_result["approval_id"] = str(
            uuid5(NAMESPACE_URL, f"dlp-p07-approval:{action_id}")
        )
    return normalized_result


def _audit_drive_action(
    session: Session,
    principal: Principal,
    request: Request,
    *,
    action: AuditAction,
    connector_id: UUID,
    object_id: str,
    outcome: AuditOutcome,
    permission_id: str | None = None,
) -> None:
    _service._rls(session, principal)
    AuditService().record_event(
        session,
        principal,
        action=action,
        resource_type="connector",
        resource_id=str(connector_id),
        outcome=outcome,
        metadata={
            "provider": "google_drive",
            "object_id": object_id,
            **({"permission_id": permission_id} if permission_id else {}),
        },
        context=context_from_request(request),
    )
    session.commit()


def _require_connector_actions_complete(decisions: list[dict[str, object]]) -> None:
    if any(
        item.get("decision") == PolicyAction.REVOKE_SHARE.value
        and item.get("action_status") != "succeeded"
        for item in decisions
    ):
        raise ProviderFailure("connector_action_incomplete")


def _trusted_action_context(obj: DriveObject) -> dict[str, str] | None:
    """Bind public/link revocation to a live Drive permission returned by Drive.

    Until policy decisions identify a specific direct-sharing target, avoid guessing
    which user/group/domain permission should be removed.
    """
    for permission in obj.permissions:
        permission_id = permission.get("id")
        if (
            permission.get("deleted") is not True
            and permission.get("type") == "anyone"
            and isinstance(permission_id, str)
            and permission_id
        ):
            return {"permission_id": permission_id}
    return None


def _microsoft_action_context(obj: DriveObject) -> dict[str, str] | None:
    """Only attach a live, direct, revocable Graph sharing link to P07."""
    for permission in obj.permissions:
        permission_id = permission.get("id")
        if (
            permission.get("deleted") is not True
            and permission.get("type") == "link"
            and permission.get("scope") in {"anonymous", "organization"}
            and permission.get("inherited") is not True
            and isinstance(permission_id, str)
            and permission_id
            and obj.drive_id
        ):
            return {"permission_id": permission_id}
    return None


def _sync_microsoft_drive(
    connector_id: UUID,
    request: Request,
    response: Response,
    principal: Principal,
    session: Session,
    vault: SecretVault,
    provider: str,
    secret_id: UUID,
    checkpoint: str | None,
    connector_state: dict[str, object],
) -> object:
    from dlp_platform.connectors.microsoft_graph import (
        MicrosoftGraphAPI,
        MicrosoftHTTPTransport,
        MicrosoftOAuthClient,
        MicrosoftOAuthSettings,
        MicrosoftProviderFailure,
    )

    try:
        if provider == "microsoft_sharepoint" and connector_state.get("library_selection_required"):
            raise HTTPException(
                status_code=409, detail="Select a SharePoint library before syncing"
            )
        config = _service.configuration(session, principal, connector_id)
        tenant_id = config.get("microsoft_tenant_id")
        if not isinstance(tenant_id, str):
            raise MicrosoftProviderFailure("invalid_provider_configuration")
        drive_id = (
            connector_state.get("drive_id")
            if provider == "microsoft_onedrive"
            else config.get("sharepoint_drive_id")
        )
        site_id = config.get("sharepoint_site_id") if provider == "microsoft_sharepoint" else None
        if not isinstance(drive_id, str) or (site_id is not None and not isinstance(site_id, str)):
            raise MicrosoftProviderFailure("missing_drive_selection")
        refresh_token = vault.get_for_trusted_service(
            session,
            principal.organization_id,
            secret_id,
            allowed_types=frozenset({SecretType.REFRESH_TOKEN}),
        ).get_secret_value()
        settings = MicrosoftOAuthSettings.from_environment()
        oauth = MicrosoftOAuthClient(settings, MicrosoftHTTPTransport())
        try:
            token = oauth.refresh(refresh_token, tenant_id)
        except MicrosoftProviderFailure as exc:
            if exc.code == "reauth_required":
                _service.mark_reauth_required(
                    session,
                    principal,
                    connector_id,
                    context_from_request(request),
                    provider=provider,
                )
                raise HTTPException(
                    status_code=409, detail="Microsoft reauthentication required"
                ) from None
            raise
        access_token = token.get("access_token")
        new_refresh = token.get("refresh_token")
        if not isinstance(access_token, str):
            raise MicrosoftProviderFailure("malformed_provider_response")
        api = MicrosoftGraphAPI(access_token, tenant_id)
        if api.organization_tenant_id() != str(UUID(tenant_id)):
            raise MicrosoftProviderFailure("tenant_mismatch")
        if isinstance(new_refresh, str) and new_refresh and new_refresh != refresh_token:
            vault.set(
                session,
                principal,
                name=f"microsoft-drive-{connector_id}",
                secret_type=SecretType.REFRESH_TOKEN,
                value=SecretStr(new_refresh),
                expires_at=None,
                secret_id=secret_id,
                audit_context=context_from_request(request),
            )
        prior_link = connector_state.get("next_link") or connector_state.get("delta_link")
        if prior_link is not None and not isinstance(prior_link, str):
            raise MicrosoftProviderFailure("invalid_delta_checkpoint")
        page = api.delta_page(
            provider,
            drive_id=drive_id,
            site_id=site_id,
            tenant_id=tenant_id,
            page_link=prior_link,
        )
        if prior_link is not None and (
            page.next_link == prior_link or page.delta_link == prior_link
        ):
            raise MicrosoftProviderFailure("repeated_page_link")
        scans: list[dict[str, object]] = []
        exposures = [
            exposure
            for change in page.changes
            for exposure in MicrosoftGraphAPI.detect_exposure(change.object)
            if exposure.kind.value not in {"private", "users"}
        ]
        for change in page.changes:
            if change.change_type == "deleted":
                continue
            permission = _microsoft_action_context(change.object)
            trusted: dict[str, str] = {}
            if permission is not None and change.object.drive_id is not None:
                trusted = {
                    **permission,
                    "drive_id": change.object.drive_id,
                    "tenant_id": tenant_id,
                    **({"site_id": site_id} if isinstance(site_id, str) else {}),
                }
            scans.append(
                _scan_drive_object(
                    principal,
                    connector_id,
                    change.object,
                    session=session,
                    extra_context=permission,
                    request_id_suffix=str(prior_link or "initial"),
                    provider=provider,
                    trusted_action_metadata=trusted,
                )
            )
        _require_connector_actions_complete(scans)
        state: dict[str, object] = {
            "drive_id": drive_id,
            "next_link": page.next_link,
            "delta_link": page.delta_link if page.next_link is None else prior_link,
        }
        if isinstance(site_id, str):
            state["site_id"] = site_id
        _service.complete_sync(
            session,
            principal,
            connector_id,
            checkpoint=checkpoint or "microsoft_graph_delta_v1",
            exposure_count=len(exposures),
            state_json=state,
            provider=provider,
            audit_context=context_from_request(request),
        )
        return {
            "connector_id": str(connector_id),
            "status": "connected",
            "provider": provider,
            "processed_changes": len(page.changes),
            "has_more": page.next_link is not None,
            "exposure_count": len(exposures),
            "scan_decisions": scans,
        }
    except HTTPException:
        raise
    except MicrosoftProviderFailure as exc:
        session.rollback()
        if exc.code in {"authorization_failed", "reauth_required", "tenant_mismatch"}:
            with suppress(Exception):
                _service.mark_reauth_required(
                    session,
                    principal,
                    connector_id,
                    context_from_request(request),
                    provider=provider,
                )
        else:
            with suppress(Exception):
                _service.mark_degraded(
                    session,
                    principal,
                    connector_id,
                    context_from_request(request),
                    provider=provider,
                )
        raise HTTPException(status_code=502, detail="Microsoft sync failed") from None
    except ProviderFailure:
        # A scan/P05/P07 failure must leave the Graph continuation uncommitted.
        session.rollback()
        with suppress(Exception):
            _service.mark_degraded(
                session,
                principal,
                connector_id,
                context_from_request(request),
                provider=provider,
            )
        raise HTTPException(status_code=503, detail="Microsoft scan/action is incomplete") from None
    except (VaultOperationFailed, VaultConfigurationError, ConnectorOperationFailed):
        session.rollback()
        raise HTTPException(status_code=503, detail="Microsoft sync failed") from None


@router.post("/{connector_id}/sync", dependencies=[Depends(rate_limit_p06)])
def sync_google_drive(
    connector_id: UUID,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: Annotated[SecretVault, Depends(_vault)],
) -> object:
    response.headers["Cache-Control"] = "no-store"
    _require_interactive_write(principal)
    try:
        secret_id, checkpoint, connector_state = _service.sync_inputs(
            session, principal, connector_id
        )
        connector_get = getattr(_service, "get", None)
        provider = (
            connector_get(session, principal, connector_id).identity.provider
            if callable(connector_get)
            else "google_drive"
        )
        if provider in {"microsoft_onedrive", "microsoft_sharepoint"}:
            return _sync_microsoft_drive(
                connector_id,
                request,
                response,
                principal,
                session,
                vault,
                provider,
                secret_id,
                checkpoint,
                connector_state,
            )
        refresh_token = vault.get_for_trusted_service(
            session,
            principal.organization_id,
            secret_id,
            allowed_types=frozenset({SecretType.REFRESH_TOKEN}),
        ).get_secret_value()
        _, oauth = _oauth()
        try:
            token = oauth.refresh(refresh_token)
        except ProviderFailure as exc:
            if exc.code == "reauth_required":
                _service.mark_reauth_required(
                    session, principal, connector_id, context_from_request(request)
                )
                raise HTTPException(
                    status_code=409, detail="Google Drive reauthentication required"
                ) from None
            raise
        access_token = token.get("access_token")
        if not isinstance(access_token, str):
            raise ProviderFailure("malformed_provider_response")
        identity = ConnectorIdentity(
            connector_id=connector_id,
            organization_id=principal.organization_id,
            provider="google_drive",
        )
        drive = GoogleDriveAPI(access_token)
        if connector_state.get("initial_inventory_pending") is True:
            if not checkpoint:
                raise ProviderFailure("missing_initial_checkpoint")
            page_token = connector_state.get("inventory_page_token")
            if page_token is not None and not isinstance(page_token, str):
                raise ProviderFailure("invalid_inventory_checkpoint")
            page = drive.list_inventory_page(page_token=page_token, page_size=100)
            exposures = [
                exposure
                for obj in page.objects
                if not obj.removed
                for exposure in GoogleDriveAPI.detect_exposure(obj)
                if exposure.kind.value not in {"private", "users"}
            ]
            scan_decisions = [
                _scan_drive_object(
                    principal,
                    connector_id,
                    obj,
                    session=session,
                    extra_context=_trusted_action_context(obj),
                )
                for obj in page.objects
                if not obj.removed
            ]
            _require_connector_actions_complete(scan_decisions)
            inventory_state: dict[str, object] = {
                "initial_inventory_pending": page.next_page_token is not None,
                "inventory_page_token": page.next_page_token,
            }
            if page.next_page_token is None:
                inventory_state["initial_inventory_complete"] = True
            _service.complete_sync(
                session,
                principal,
                connector_id,
                checkpoint=checkpoint,
                exposure_count=len(exposures),
                state_json=inventory_state,
                audit_context=context_from_request(request),
            )
            return {
                "connector_id": str(connector_id),
                "status": "connected",
                "sync_mode": "initial_inventory",
                "processed_files": len(page.objects),
                "has_more": page.next_page_token is not None,
                "exposure_count": len(exposures),
                "scan_decisions": scan_decisions,
            }
        result = drive.list_changes(
            SyncRequest(identity=identity, checkpoint=checkpoint, max_changes=100)
        )
        exposures = [
            exposure
            for change in result.changes
            for exposure in GoogleDriveAPI.detect_exposure(change.object)
            if exposure.kind.value not in {"private", "users"}
        ]
        scan_decisions = [
            _scan_drive_object(
                principal,
                connector_id,
                change.object,
                session=session,
                extra_context=_trusted_action_context(change.object),
            )
            for change in result.changes
            if change.change_type != "deleted"
        ]
        _require_connector_actions_complete(scan_decisions)
        if result.next_checkpoint is None:
            raise ProviderFailure("missing_checkpoint")
        _service.complete_sync(
            session,
            principal,
            connector_id,
            checkpoint=result.next_checkpoint,
            exposure_count=len(exposures),
            audit_context=context_from_request(request),
        )
        return {
            "connector_id": str(connector_id),
            "status": "connected",
            "processed_changes": len(result.changes),
            "has_more": result.has_more,
            "exposure_count": len(exposures),
            "scan_decisions": scan_decisions,
        }
    except HTTPException:
        raise
    except ProviderFailure as exc:
        session.rollback()
        try:
            if exc.code in {"authorization_failed", "reauth_required"}:
                _service.mark_reauth_required(
                    session, principal, connector_id, context_from_request(request)
                )
            else:
                _service.mark_degraded(
                    session, principal, connector_id, context_from_request(request)
                )
        except ConnectorOperationFailed:
            pass
        raise HTTPException(status_code=503, detail="Google Drive synchronization failed") from None
    except (VaultOperationFailed, ConnectorOperationFailed, VaultConfigurationError):
        session.rollback()
        raise HTTPException(status_code=503, detail="Google Drive synchronization failed") from None


@router.post("/{connector_id}/revoke-share", dependencies=[Depends(rate_limit_p06)])
def revoke_google_share(
    connector_id: UUID,
    body: ShareRevokeRequest,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: Annotated[SecretVault, Depends(_vault)],
) -> object:
    response.headers["Cache-Control"] = "no-store"
    _require_interactive_write(principal)
    connector = _service.get(session, principal, connector_id)
    if connector.identity.provider != "google_drive":
        raise HTTPException(status_code=404, detail="Connector not found")
    try:
        secret_id, _, _ = _service.sync_inputs(session, principal, connector_id)
        refresh_token = vault.get_for_trusted_service(
            session,
            principal.organization_id,
            secret_id,
            allowed_types=frozenset({SecretType.REFRESH_TOKEN}),
        ).get_secret_value()
        _, oauth = _oauth()
        token = oauth.refresh(refresh_token)
        access_token = token.get("access_token")
        if not isinstance(access_token, str):
            raise ProviderFailure("malformed_provider_response")
        drive = GoogleDriveAPI(access_token)
        obj = drive.get_file(body.object_id)
        _audit_drive_action(
            session,
            principal,
            request,
            action=AuditAction.CONNECTOR_SHARE_REVOKE_REQUESTED,
            connector_id=connector_id,
            object_id=body.object_id,
            permission_id=body.permission_id,
            outcome=AuditOutcome.SUCCESS,
        )
        result = _scan_drive_object(
            principal,
            connector_id,
            obj,
            extra_context={
                "permission_id": body.permission_id,
                "requested_action": PolicyAction.REVOKE_SHARE.value,
            },
            request_id_suffix=body.permission_id,
        )
        if result["decision"] != PolicyAction.REVOKE_SHARE.value:
            _audit_drive_action(
                session,
                principal,
                request,
                action=AuditAction.CONNECTOR_SHARE_REVOKE_FAILED,
                connector_id=connector_id,
                object_id=body.object_id,
                permission_id=body.permission_id,
                outcome=AuditOutcome.DENIED,
            )
            raise HTTPException(status_code=409, detail="Policy did not authorize share revocation")
        if result["action_status"] == "pending_approval":
            response.status_code = status.HTTP_202_ACCEPTED
            return {"status": "pending_approval", **result}
        if result["action_status"] != "succeeded":
            _audit_drive_action(
                session,
                principal,
                request,
                action=AuditAction.CONNECTOR_SHARE_REVOKE_FAILED,
                connector_id=connector_id,
                object_id=body.object_id,
                permission_id=body.permission_id,
                outcome=AuditOutcome.FAILURE,
            )
            raise HTTPException(status_code=503, detail="Google Drive share revocation failed")
        _audit_drive_action(
            session,
            principal,
            request,
            action=AuditAction.CONNECTOR_SHARE_REVOKED,
            connector_id=connector_id,
            object_id=body.object_id,
            permission_id=body.permission_id,
            outcome=AuditOutcome.SUCCESS,
        )
        return {"status": "revoked", "outcome": "success", **result}
    except HTTPException:
        raise
    except ProviderFailure:
        session.rollback()
        _audit_drive_action(
            session,
            principal,
            request,
            action=AuditAction.CONNECTOR_SHARE_REVOKE_FAILED,
            connector_id=connector_id,
            object_id=body.object_id,
            permission_id=body.permission_id,
            outcome=AuditOutcome.FAILURE,
        )
        raise HTTPException(
            status_code=503, detail="Google Drive share revocation failed"
        ) from None
    except (VaultOperationFailed, ConnectorOperationFailed, VaultConfigurationError):
        session.rollback()
        raise HTTPException(
            status_code=503, detail="Google Drive share revocation failed"
        ) from None


@router.post("/{connector_id}/quarantine", dependencies=[Depends(rate_limit_p06)])
def quarantine_google_file(
    connector_id: UUID,
    body: QuarantineRequest,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    response.headers["Cache-Control"] = "no-store"
    _require_interactive_write(principal)
    connector = _service.get(session, principal, connector_id)
    if connector.identity.provider != "google_drive":
        raise HTTPException(status_code=404, detail="Connector not found")
    _audit_drive_action(
        session,
        principal,
        request,
        action=AuditAction.CONNECTOR_QUARANTINE_REQUESTED,
        connector_id=connector_id,
        object_id=body.object_id,
        outcome=AuditOutcome.SUCCESS,
    )
    _audit_drive_action(
        session,
        principal,
        request,
        action=AuditAction.CONNECTOR_QUARANTINE_FAILED,
        connector_id=connector_id,
        object_id=body.object_id,
        outcome=AuditOutcome.FAILURE,
    )
    raise HTTPException(status_code=501, detail="Google Drive quarantine is not configured")


@router.post("/{connector_id}/disconnect", dependencies=[Depends(rate_limit_p06)])
def disconnect_google(
    connector_id: UUID,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: Annotated[SecretVault, Depends(_vault)],
) -> object:
    _require_interactive_write(principal)
    row = session.execute(
        select(DLP_CONNECTORS.c.credential_secret_id).where(
            DLP_CONNECTORS.c.id == str(connector_id),
            DLP_CONNECTORS.c.org_id == str(principal.organization_id),
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    secret_id = UUID(row) if row else None
    if secret_id:
        settings, oauth = _oauth()
        del settings
        refresh_token = vault.get_for_trusted_service(
            session,
            principal.organization_id,
            secret_id,
            allowed_types=frozenset({SecretType.REFRESH_TOKEN}),
        ).get_secret_value()
        try:
            oauth.revoke(refresh_token)
        except ProviderFailure:
            raise HTTPException(status_code=503, detail="Google Drive revocation failed") from None
        try:
            vault.disable(
                session, principal, secret_id, audit_context=context_from_request(request)
            )
        except Exception as exc:
            session.rollback()
            with suppress(ConnectorOperationFailed):
                _service.mark_reauth_required(
                    session, principal, connector_id, context_from_request(request)
                )
            _fail(exc)
    try:
        result = _service.disconnect(
            session, principal, connector_id, context_from_request(request)
        )
        response.headers["Cache-Control"] = "no-store"
        return result.model_dump(mode="json")
    except Exception as exc:
        session.rollback()
        if secret_id is not None:
            with suppress(ConnectorOperationFailed):
                _service.mark_reauth_required(
                    session, principal, connector_id, context_from_request(request)
                )
        _fail(exc)
