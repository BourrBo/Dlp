"""Public metadata models and input validation for vault operations."""

import re
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,119}$")


class SecretType(StrEnum):
    OAUTH_CLIENT_SECRET = "oauth_client_secret"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    API_CREDENTIAL = "api_credential"
    PRIVATE_KEY = "private_key"
    GENERIC_SECRET = "generic_secret"


class SetSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    secret_type: SecretType
    value: SecretStr = Field(min_length=1, max_length=65_536)
    expires_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def safe_logical_name(cls, value: str) -> str:
        if not _NAME_PATTERN.fullmatch(value):
            raise ValueError(
                "Name must start with a lowercase letter and use lowercase letters, digits, "
                "dots, underscores, or hyphens"
            )
        return value

    @field_validator("value")
    @classmethod
    def validate_secret_value(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if "\x00" in raw:
            raise ValueError("Secret value contains an unsupported character")
        if not raw.encode("utf-8"):
            raise ValueError("Secret value cannot be empty")
        if len(raw.encode("utf-8")) > 65_536:
            raise ValueError("Secret value exceeds the supported size")
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expiration(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Expiration must include a timezone")
        if value <= datetime.now(UTC):
            raise ValueError("Expiration must be in the future")
        return value


class SecretMetadata(BaseModel):
    secret_id: UUID
    name: str
    secret_type: SecretType
    key_version: int
    expires_at: datetime | None
    enabled: bool
    expired: bool
    created_at: datetime
    updated_at: datetime
