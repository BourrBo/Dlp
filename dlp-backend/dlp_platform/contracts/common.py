"""Shared contract enums and base model.

Underspecified field details are recommendations tracked in docs/decisions.md.
Contracts remain PROPOSED until approved.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ContractModel(BaseModel):
    """Strict immutable base for contract models."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DataChannel(StrEnum):
    BROWSER = "browser"
    FILE = "file"
    REPOSITORY = "repository"
    EMAIL = "email"
    CLOUD_STORAGE = "cloud_storage"
    CHAT = "chat"
    DATABASE = "database"
    API = "api"
    NETWORK = "network"
    ENDPOINT = "endpoint"


class ClassificationLevel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    HIGHLY_RESTRICTED = "highly_restricted"


class SeverityLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    LOG = "log"
    REDACT = "redact"
    QUARANTINE = "quarantine"
    REVOKE_SHARE = "revoke_share"
    REQUIRE_APPROVAL = "require_approval"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDITOR = "auditor"


class ActorType(StrEnum):
    USER = "user"
    SERVICE = "service"


class AuthMethod(StrEnum):
    JWT = "jwt"
    API_KEY = "api_key"
    SSO = "sso"
    INTERNAL = "internal"


class FindingLocation(ContractModel):
    """Optional source coordinates; unset coordinates are omitted by producers."""

    path: str | None = Field(default=None, max_length=2048)
    page: int | None = Field(default=None, ge=1)
    sheet: str | None = Field(default=None, max_length=255)
    cell: str | None = Field(default=None, max_length=64)
    line: int | None = Field(default=None, ge=1)
    commit: str | None = Field(default=None, max_length=128)
