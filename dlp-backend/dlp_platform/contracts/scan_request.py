"""Ephemeral scan input contract. Content must not be persisted or logged."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import Field, PrivateAttr, SecretStr

from .common import ContractModel, DataChannel


class ScanRequest(ContractModel):
    _trusted_action_metadata: dict[str, str] = PrivateAttr(default_factory=dict)

    request_id: UUID = Field(default_factory=uuid4)
    channel: DataChannel
    destination: str | None = Field(default=None, max_length=2048)
    content: SecretStr
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    context: dict[str, str | int | bool] = Field(default_factory=dict)
