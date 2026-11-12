"""Safe P05 policy and destination types; no expression language is accepted."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from dlp_platform.contracts.common import PolicyAction

type ConditionValue = str | int | float | bool | None | list[str] | list[int]
DESTINATION_CLASSES = frozenset({"internal", "public", "personal", "partner"})
MAX_CONDITION_VALUES = 100
SUPPORTED_CONDITIONS = frozenset(
    {
        "channel",
        "destination_class",
        "user_group",
        "data_type",
        "classification",
        "volume",
        "file_type",
    }
)
P05_ACTIONS = frozenset(
    {
        PolicyAction.ALLOW,
        PolicyAction.WARN,
        PolicyAction.BLOCK,
        PolicyAction.LOG,
        PolicyAction.REDACT,
        PolicyAction.QUARANTINE,
        PolicyAction.REVOKE_SHARE,
        PolicyAction.REQUIRE_APPROVAL,
    }
)


class DestinationClass:
    INTERNAL = "internal"
    PUBLIC = "public"
    PERSONAL = "personal"
    PARTNER = "partner"


class DestinationKind:
    DOMAIN = "domain"
    REPOSITORY = "repo"
    EMAIL_DOMAIN = "email_domain"


class Destination(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    destination_id: UUID
    organization_id: UUID
    destination_class: str = Field(pattern=r"^(internal|public|personal|partner)$")
    kind: str = Field(pattern=r"^(domain|repo|email_domain)$")
    pattern: str = Field(min_length=1, max_length=255)


@dataclass(frozen=True)
class PolicyMatch:
    policy_id: UUID
    action: PolicyAction
    priority: int
    version: int
    matched_conditions: tuple[str, ...]


def validate_conditions(conditions: Mapping[str, object]) -> dict[str, ConditionValue]:
    """Validate condition keys and values using explicit allowlisted logic."""
    from dlp_platform.contracts.common import ClassificationLevel, DataChannel, Role

    if not isinstance(conditions, Mapping):
        raise ValueError("conditions must be an object")
    normalized: dict[str, ConditionValue] = {}
    for key, value in conditions.items():
        if key not in SUPPORTED_CONDITIONS:
            raise ValueError(f"unsupported condition: {key}")
        values: list[object]
        if isinstance(value, list):
            if not value:
                raise ValueError(f"condition {key} must not be an empty list")
            if len(value) > MAX_CONDITION_VALUES:
                raise ValueError(f"condition {key} has too many values")
            values = value
        else:
            values = [value]
        if any(item is None for item in values):
            raise ValueError(f"condition {key} must not be null")
        if key == "channel":
            valid = {item.value for item in DataChannel}
            if any(not isinstance(item, str) or item not in valid for item in values):
                raise ValueError("channel must use a supported data channel")
        elif key == "destination_class":
            if any(not isinstance(item, str) or item not in DESTINATION_CLASSES for item in values):
                raise ValueError("destination_class must be internal, public, personal, or partner")
        elif key == "user_group":
            valid = {item.value for item in Role}
            if any(not isinstance(item, str) or item not in valid for item in values):
                raise ValueError("user_group must use a supported Principal role")
        elif key == "classification":
            valid = {item.value for item in ClassificationLevel}
            if any(not isinstance(item, str) or item not in valid for item in values):
                raise ValueError("classification must use a supported classification")
        elif key in {"data_type", "file_type"}:
            if any(not isinstance(item, str) or not item or len(item) > 128 for item in values):
                raise ValueError(
                    f"{key} values must be non-empty strings of at most 128 characters"
                )
        elif key == "volume":
            if any(
                not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in values
            ):
                raise ValueError("volume must be a non-negative integer byte count")
        normalized[key] = cast(ConditionValue, value)
    return normalized
