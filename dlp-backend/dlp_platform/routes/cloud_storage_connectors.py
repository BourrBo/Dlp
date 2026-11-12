"""Tenant-scoped S3 and GCS connection and bounded sync routes."""

import hashlib
import json
import re
from contextlib import suppress
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationInfo, field_validator
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditContext, context_from_request
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.connectors.cloud_storage import (
    MAX_EVENTS,
    PAGE_SIZE,
    CloudProviderFailure,
    CloudStorageObject,
    GCSStorageAdapter,
    S3StorageAdapter,
)
from dlp_platform.connectors.models import ConnectorHealth
from dlp_platform.connectors.service import ConnectorOperationFailed, ConnectorService
from dlp_platform.contracts.common import ActorType, DataChannel, PolicyAction
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter
from dlp_platform.routes.connectors import _fail, _vault
from dlp_platform.routes.p06_support import rate_limit_p06
from dlp_platform.scan.pipeline import scan
from dlp_platform.vault.config import VaultConfigurationError
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault, VaultOperationFailed

router = APIRouter(prefix="/connectors", tags=["cloud-storage-connectors"])
SessionDependency = Annotated[Session, Depends(get_session)]
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]
_service = ConnectorService()


class S3Create(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    bucket: str = Field(min_length=3, max_length=63)
    region: str = Field(pattern=r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$", max_length=32)
    aws_account_id: str = Field(pattern=r"^\d{12}$")
    requester_pays: bool = False
    sqs_queue_name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")


class GCSCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    bucket: str = Field(min_length=3, max_length=222)
    project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
    pubsub_subscription: str = Field(min_length=1, max_length=512)

    @field_validator("pubsub_subscription")
    @classmethod
    def valid_subscription(cls, value: str, info: ValidationInfo) -> str:
        project = info.data.get("project_id")
        if project and not re.fullmatch(
            rf"projects/{re.escape(project)}/subscriptions/[A-Za-z0-9_-]{{1,255}}", value
        ):
            raise ValueError("Subscription must belong to the configured project")
        return value


class S3Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_key_id: str = Field(min_length=16, max_length=128, pattern=r"^[A-Z0-9]+$")
    secret_access_key: SecretStr = Field(min_length=16, max_length=128)
    session_token: SecretStr | None = Field(default=None, max_length=4096)
    role_arn: str = Field(min_length=30, max_length=2048)
    external_id: SecretStr = Field(min_length=2, max_length=1224)


class GCSCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_account_json: SecretStr = Field(min_length=2, max_length=65_536)


def _interactive(principal: Principal) -> None:
    require_permission(principal, Permission.CONNECTORS_WRITE)
    if principal.actor_type is not ActorType.USER:
        raise HTTPException(status_code=403, detail="Interactive user session required")


def _connector_for_provider(
    session: Session, principal: Principal, connector_id: UUID, expected: str
) -> ConnectorHealth:
    health = _service.get(session, principal, connector_id)
    if health.identity.provider != expected:
        raise HTTPException(status_code=404, detail="Connector not found")
    return health


@router.post("/s3", status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit_p06)])
def create_s3_connector(
    body: S3Create,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal)
    response.headers["Cache-Control"] = "no-store"
    config = {
        "bucket": body.bucket,
        "region": body.region,
        "aws_account_id": body.aws_account_id,
        "requester_pays": body.requester_pays,
        "sqs_queue_name": body.sqs_queue_name,
        "inventory_page_size": PAGE_SIZE,
    }
    try:
        created = _service.create(
            session,
            principal,
            provider="aws_s3",
            name=body.name,
            config=config,
            audit_context=_audit_context(request),
        )
        return created.model_dump(mode="json")
    except Exception as exc:
        _fail(exc)


@router.post("/gcs", status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit_p06)])
def create_gcs_connector(
    body: GCSCreate,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal)
    response.headers["Cache-Control"] = "no-store"
    config = {
        "bucket": body.bucket,
        "project_id": body.project_id,
        "pubsub_subscription": body.pubsub_subscription,
        "inventory_page_size": PAGE_SIZE,
    }
    try:
        created = _service.create(
            session,
            principal,
            provider="google_cloud_storage",
            name=body.name,
            config=config,
            audit_context=_audit_context(request),
        )
        return created.model_dump(mode="json")
    except Exception as exc:
        _fail(exc)


@router.post("/s3/{connector_id}/connect", dependencies=[Depends(rate_limit_p06)])
def connect_s3(
    connector_id: UUID,
    body: S3Credentials,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal)
    response.headers["Cache-Control"] = "no-store"
    try:
        _connector_for_provider(session, principal, connector_id, "aws_s3")
        _service.begin_connect(session, principal, connector_id)
        config = _service.configuration(session, principal, connector_id)
        credential = json.dumps(
            {
                "access_key_id": body.access_key_id,
                "secret_access_key": body.secret_access_key.get_secret_value(),
                "session_token": body.session_token.get_secret_value()
                if body.session_token is not None
                else None,
                "role_arn": body.role_arn,
                "external_id": body.external_id.get_secret_value(),
            },
            separators=(",", ":"),
        )
        adapter = S3StorageAdapter(config, credential)
        adapter.verify()
        vault = SecretVault.from_environment()
        metadata = vault.set(
            session,
            principal,
            name=f"cloud-s3-{connector_id}",
            secret_type=SecretType.API_CREDENTIAL,
            value=SecretStr(credential),
            expires_at=None,
            audit_context=_audit_context(request),
        )
        connected = _service.set_connection(
            session,
            principal,
            connector_id,
            secret_id=metadata.secret_id,
            checkpoint="p18_s3_inventory_v1",
            state_json={
                "initial_inventory_pending": True,
                "page_token": None,
                "event_receipts": [],
            },
            audit_context=_audit_context(request),
        )
        return {**connected.model_dump(mode="json"), "bucket": config["bucket"]}
    except (
        CloudProviderFailure,
        VaultConfigurationError,
        VaultOperationFailed,
        ConnectorOperationFailed,
    ):
        with suppress(Exception):
            _service.mark_connect_failed(session, principal, connector_id, _audit_context(request))
        raise HTTPException(status_code=503, detail="S3 connection failed") from None
    except Exception as exc:
        _fail(exc)


@router.post("/gcs/{connector_id}/connect", dependencies=[Depends(rate_limit_p06)])
def connect_gcs(
    connector_id: UUID,
    body: GCSCredentials,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal)
    response.headers["Cache-Control"] = "no-store"
    try:
        _connector_for_provider(session, principal, connector_id, "google_cloud_storage")
        _service.begin_connect(session, principal, connector_id)
        config = _service.configuration(session, principal, connector_id)
        credential = body.service_account_json.get_secret_value()
        adapter = GCSStorageAdapter(config, credential)
        adapter.verify()
        metadata = SecretVault.from_environment().set(
            session,
            principal,
            name=f"cloud-gcs-{connector_id}",
            secret_type=SecretType.PRIVATE_KEY,
            value=SecretStr(credential),
            expires_at=None,
            audit_context=_audit_context(request),
        )
        connected = _service.set_connection(
            session,
            principal,
            connector_id,
            secret_id=metadata.secret_id,
            checkpoint="p18_gcs_inventory_v1",
            state_json={
                "initial_inventory_pending": True,
                "page_token": None,
                "event_receipts": [],
            },
            audit_context=_audit_context(request),
        )
        return {**connected.model_dump(mode="json"), "bucket": config["bucket"]}
    except (
        CloudProviderFailure,
        VaultConfigurationError,
        VaultOperationFailed,
        ConnectorOperationFailed,
    ):
        with suppress(Exception):
            _service.mark_connect_failed(session, principal, connector_id, _audit_context(request))
        raise HTTPException(status_code=503, detail="GCS connection failed") from None
    except Exception as exc:
        _fail(exc)


@router.get("/{provider}/{connector_id}/status", dependencies=[Depends(rate_limit_p06)])
def cloud_status(
    provider: Literal["s3", "gcs"],
    connector_id: UUID,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    response.headers["Cache-Control"] = "no-store"
    name = "aws_s3" if provider == "s3" else "google_cloud_storage"
    try:
        health = _connector_for_provider(session, principal, connector_id, name)
        config = _service.configuration(session, principal, connector_id)
        return {
            **health.model_dump(mode="json"),
            "bucket": config.get("bucket"),
            "region": config.get("region"),
            "aws_account_id": config.get("aws_account_id"),
            "project_id": config.get("project_id"),
            "requester_pays": config.get("requester_pays", False),
        }
    except Exception as exc:
        _fail(exc)


@router.post("/{provider}/{connector_id}/disconnect", dependencies=[Depends(rate_limit_p06)])
def cloud_disconnect(
    provider: Literal["s3", "gcs"],
    connector_id: UUID,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> object:
    _interactive(principal)
    response.headers["Cache-Control"] = "no-store"
    name = "aws_s3" if provider == "s3" else "google_cloud_storage"
    try:
        _connector_for_provider(session, principal, connector_id, name)
        return _service.disconnect(
            session, principal, connector_id, _audit_context(request)
        ).model_dump(mode="json")
    except Exception as exc:
        _fail(exc)


@router.post("/{provider}/{connector_id}/sync", dependencies=[Depends(rate_limit_p06)])
def sync_cloud_storage(
    provider: Literal["s3", "gcs"],
    connector_id: UUID,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: Annotated[SecretVault, Depends(_vault)],
) -> object:
    _interactive(principal)
    response.headers["Cache-Control"] = "no-store"
    provider_name = "aws_s3" if provider == "s3" else "google_cloud_storage"
    try:
        secret_id, checkpoint, raw_state = _service.sync_inputs(session, principal, connector_id)
        _connector_for_provider(session, principal, connector_id, provider_name)
        config = _service.configuration(session, principal, connector_id)
        state = dict(raw_state)
        secret_type = SecretType.API_CREDENTIAL if provider == "s3" else SecretType.PRIVATE_KEY
        credential = vault.get_for_trusted_service(
            session,
            principal.organization_id,
            secret_id,
            allowed_types=frozenset({secret_type}),
        ).get_secret_value()
        adapter = (
            S3StorageAdapter(config, credential)
            if provider == "s3"
            else GCSStorageAdapter(config, credential)
        )

        if state.get("initial_inventory_pending") is True:
            incoming = state.get("page_token")
            if incoming is not None and not isinstance(incoming, str):
                raise CloudProviderFailure("invalid_inventory_checkpoint")
            page = adapter.list_page(incoming, PAGE_SIZE)
            objects = page.objects
            next_state = {
                **state,
                "page_token": page.next_page_token,
                "initial_inventory_pending": page.next_page_token is not None,
            }
            if page.next_page_token is None:
                next_state["initial_inventory_complete"] = True
            mode = "initial_inventory"
            acknowledgements: tuple[str, ...] = ()
            receipts = state.get("event_receipts", [])
        else:
            batch = adapter.poll_notifications(limit=10)
            receipts = state.get("event_receipts", [])
            if not isinstance(receipts, list) or any(
                not isinstance(item, str) for item in receipts
            ):
                raise CloudProviderFailure("invalid_event_checkpoint")
            seen = set(receipts)
            unique = [
                event
                for event in batch.events
                if hashlib.sha256(event.event_id.encode()).hexdigest() not in seen
            ]
            if len(unique) > MAX_EVENTS:
                raise CloudProviderFailure("notification_batch_too_large")
            objects = tuple(
                adapter.get_event_object(event.object_name, event.version, deleted=event.deleted)
                for event in unique
            )
            acknowledgements = batch.acknowledgement_tokens
            next_state = {
                **state,
                "event_receipts": (
                    receipts
                    + [hashlib.sha256(event.event_id.encode()).hexdigest() for event in unique]
                )[-1000:],
            }
            mode = "event_notifications"

        scans: list[dict[str, object]] = []
        exposures: list[object] = []
        for obj in objects:
            if obj.deleted:
                continue
            object_exposures = adapter.detect_exposure(obj)
            exposures.extend(
                exposure
                for exposure in object_exposures
                if exposure.kind.value not in {"private", "users"}
            )
            scans.append(
                _scan_cloud_object(
                    principal,
                    connector_id,
                    obj,
                    exposure_kinds=tuple(exposure.kind.value for exposure in object_exposures),
                )
            )
        if any(
            item.get("decision") in {PolicyAction.REVOKE_SHARE.value, PolicyAction.QUARANTINE.value}
            and item.get("action_status") == "failed"
            for item in scans
        ):
            raise CloudProviderFailure("unsupported_provider_action")
        _service.complete_sync(
            session,
            principal,
            connector_id,
            checkpoint=checkpoint or f"p18_{provider}_inventory_v1",
            exposure_count=len(exposures),
            provider=provider_name,
            state_json=next_state,
            audit_context=_audit_context(request),
        )
        if acknowledgements:
            adapter.acknowledge(acknowledgements)
        return {
            "connector_id": str(connector_id),
            "provider": provider_name,
            "status": "connected",
            "sync_mode": mode,
            "processed_objects": len(objects),
            "deleted_objects": sum(1 for obj in objects if obj.deleted),
            "exposure_count": len(exposures),
            "scan_decisions": scans,
            "has_more": next_state.get("initial_inventory_pending") is True,
        }
    except HTTPException:
        raise
    except (
        CloudProviderFailure,
        VaultOperationFailed,
        VaultConfigurationError,
        ConnectorOperationFailed,
    ):
        session.rollback()
        raise HTTPException(status_code=503, detail="Cloud storage sync failed") from None
    except Exception:
        session.rollback()
        raise HTTPException(status_code=503, detail="Cloud storage sync failed") from None


def _scan_cloud_object(
    principal: Principal,
    connector_id: UUID,
    obj: CloudStorageObject,
    *,
    exposure_kinds: tuple[str, ...] = (),
) -> dict[str, object]:
    serialized = {
        **obj.model_dump(mode="json"),
        "exposure_kinds": list(exposure_kinds),
    }
    content = json.dumps(serialized, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(content.encode()).hexdigest()
    request_id = uuid5(
        NAMESPACE_URL,
        f"dlp-p18:{principal.organization_id}:{connector_id}:{obj.provider}:{digest}",
    )
    request = ScanRequest(
        request_id=request_id,
        channel=DataChannel.CLOUD_STORAGE,
        content=SecretStr(content),
        context={
            "provider": obj.provider,
            "connector_id": str(connector_id),
            "bucket": obj.bucket,
            "object_name": obj.object_name,
            "version": obj.version or "",
            "exposure_kinds": ",".join(exposure_kinds),
        },
    )
    request._trusted_action_metadata = {
        "provider": obj.provider,
        "connector_id": str(connector_id),
        "organization_id": str(principal.organization_id),
        "bucket": obj.bucket,
        "object_name": obj.object_name,
        "object_version": obj.version or "",
    }
    result = scan(request, principal)
    action_status = "not_executed"
    if "P07 action status=" in result.reason:
        action_status = result.reason.rsplit("P07 action status=", 1)[1].split(".", 1)[0]
    return {
        "object_id": obj.object_id,
        "decision": result.decision.value,
        "finding_count": len(result.findings),
        "action_status": action_status,
        "request_id": str(request_id),
    }


def _audit_context(request: Request) -> AuditContext:
    return context_from_request(request)
