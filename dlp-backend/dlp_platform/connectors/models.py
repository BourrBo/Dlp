"""Validated, provider-neutral connector models."""

from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ConnectorStatus(StrEnum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DEGRADED = "degraded"
    REAUTH_REQUIRED = "reauth_required"
    ERROR = "error"
    DISCONNECTING = "disconnecting"


_STATUS_TRANSITIONS: dict[ConnectorStatus, frozenset[ConnectorStatus]] = {
    ConnectorStatus.DISCONNECTED: frozenset({ConnectorStatus.CONNECTING}),
    ConnectorStatus.CONNECTING: frozenset(
        {
            ConnectorStatus.CONNECTED,
            ConnectorStatus.DISCONNECTED,
            ConnectorStatus.ERROR,
            ConnectorStatus.REAUTH_REQUIRED,
            ConnectorStatus.DISCONNECTING,
        }
    ),
    ConnectorStatus.CONNECTED: frozenset(
        {
            ConnectorStatus.DEGRADED,
            ConnectorStatus.REAUTH_REQUIRED,
            ConnectorStatus.DISCONNECTING,
            ConnectorStatus.DISCONNECTED,
        }
    ),
    ConnectorStatus.DEGRADED: frozenset(
        {
            ConnectorStatus.CONNECTED,
            ConnectorStatus.REAUTH_REQUIRED,
            ConnectorStatus.DISCONNECTING,
            ConnectorStatus.DISCONNECTED,
        }
    ),
    ConnectorStatus.REAUTH_REQUIRED: frozenset(
        {ConnectorStatus.CONNECTING, ConnectorStatus.DISCONNECTED}
    ),
    ConnectorStatus.ERROR: frozenset({ConnectorStatus.CONNECTING, ConnectorStatus.DISCONNECTED}),
    ConnectorStatus.DISCONNECTING: frozenset({ConnectorStatus.DISCONNECTED, ConnectorStatus.ERROR}),
}


def validate_status_transition(current: ConnectorStatus, target: ConnectorStatus) -> None:
    """Reject impossible lifecycle jumps instead of treating status as a free-form label."""
    if target not in _STATUS_TRANSITIONS[current]:
        raise ValueError(f"Invalid connector transition: {current.value} -> {target.value}")


class ConnectorCapability(StrEnum):
    SYNC = "sync"
    EXPOSURE_DETECTION = "exposure_detection"
    REVOKE_SHARE = "revoke_share"
    QUARANTINE = "quarantine"


class ConnectorIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    connector_id: UUID
    organization_id: UUID
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")


class ConnectorHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    identity: ConnectorIdentity
    status: ConnectorStatus
    last_sync_at: datetime | None = None
    last_error_code: str | None = Field(default=None, max_length=64)


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    identity: ConnectorIdentity
    checkpoint: str | None = Field(default=None, max_length=2048)
    max_changes: int = Field(default=100, ge=1, le=1000)


class DriveObject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    object_id: str = Field(min_length=1, max_length=1024)
    name: str = Field(max_length=1024)
    mime_type: str = Field(max_length=256)
    size_bytes: int | None = Field(default=None, ge=0)
    modified_at: datetime | None = None
    web_view_link: HttpUrl | None = None
    shared_drive_id: str | None = Field(default=None, max_length=1024)
    # Microsoft identifiers stay distinct: tenant, SharePoint site, document
    # library (Graph drive), and item are not interchangeable IDs.
    tenant_id: str | None = Field(default=None, max_length=128)
    site_id: str | None = Field(default=None, max_length=1024)
    drive_id: str | None = Field(default=None, max_length=1024)
    is_shortcut: bool = False
    shortcut_target_id: str | None = Field(default=None, max_length=1024)
    removed: bool = False
    permissions: tuple[dict[str, str | bool | None], ...] = ()


class NormalizedChange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    object: DriveObject
    change_type: str = Field(pattern=r"^(created|modified|deleted|restored|permission_changed)$")


class SyncResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    changes: tuple[NormalizedChange, ...]
    next_checkpoint: str | None = Field(default=None, max_length=2048)
    has_more: bool


class InventoryPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    objects: tuple[DriveObject, ...]
    next_page_token: str | None = Field(default=None, max_length=2048)


class ExposureKind(StrEnum):
    PRIVATE = "private"
    USERS = "users"
    DOMAIN = "domain"
    LINK = "link"
    PUBLIC = "public"
    ORGANIZATION = "organization"
    GROUPS = "groups"
    AUTHENTICATED = "authenticated"
    UNKNOWN = "unknown"


class Exposure(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    object_id: str = Field(min_length=1, max_length=1024)
    kind: ExposureKind
    principals: tuple[str, ...] = ()
    permission_ids: tuple[str, ...] = ()
    inherited: bool = False


class ShareRevocation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    object_id: str = Field(min_length=1, max_length=1024)
    permission_id: str = Field(min_length=1, max_length=1024)
    drive_id: str | None = Field(default=None, max_length=1024)


class ActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    succeeded: bool
    outcome: str = Field(max_length=64)


@runtime_checkable
class Connector(Protocol):
    def connect(self, identity: ConnectorIdentity) -> ConnectorHealth: ...
    def status(self, identity: ConnectorIdentity) -> ConnectorHealth: ...
    def sync(self, request: SyncRequest) -> SyncResult: ...
    def detect_exposure(self, obj: DriveObject) -> tuple[Exposure, ...]: ...
    def revoke_share(self, action: ShareRevocation) -> ActionResult: ...
    def quarantine(self, object_id: str) -> ActionResult: ...
    def disconnect(self, identity: ConnectorIdentity) -> ConnectorHealth: ...
