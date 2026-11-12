"""Audit contract and metadata boundary tests."""

import pytest
from pydantic import ValidationError

from dlp_platform.audit.service import MAX_METADATA_BYTES, sanitize_metadata
from dlp_platform.contracts.audit_event import AuditAction, AuditEvent, AuditOutcome


@pytest.mark.parametrize(
    "field",
    [
        "password",
        "passwd",
        "client_secret",
        "secret_value",
        "access_token",
        "refresh_token",
        "api_key",
        "authorization",
        "cookie",
        "private_key",
        "credential",
        "ciphertext",
        "master_key",
    ],
)
def test_sensitive_field_names_are_redacted(field: str) -> None:
    sanitized = sanitize_metadata({field: "synthetic-sensitive-canary", "resource_id": "safe-id"})
    assert sanitized[field] == "[REDACTED]"
    assert "synthetic-sensitive-canary" not in str(sanitized)
    assert sanitized["resource_id"] == "safe-id"


@pytest.mark.parametrize(
    "value",
    [
        "Bearer synthetic-token-canary",
        "dlp_123456abcdef.synthetic-api-key-canary-01234567890123456789",
        "-----BEGIN PRIVATE KEY-----\nsynthetic-private-key-canary",
        "eyJsyntheticjwtpayload.eyJsyntheticclaims.c2lnbmF0dXJl",
        "ghp_1234567890123456789012345678901234567890",
        "sk_live_12345678901234567890",
    ],
)
def test_credential_shaped_values_under_generic_keys_are_redacted(value: str) -> None:
    sanitized = sanitize_metadata({"context": value})
    assert sanitized["context"] == "[REDACTED]"
    assert value not in str(sanitized)


def test_user_agent_is_bounded_and_credential_patterns_are_redacted() -> None:
    assert (
        sanitize_metadata({"user_agent": "ExampleBrowser/1.0"})["user_agent"]
        == "ExampleBrowser/1.0"
    )
    assert (
        sanitize_metadata({"user_agent": "Bearer synthetic-header-token"})["user_agent"]
        == "[REDACTED]"
    )


def test_metadata_is_bounded_json_only_and_depth_limited() -> None:
    with pytest.raises(ValueError):
        sanitize_metadata({"details": "x" * MAX_METADATA_BYTES})
    with pytest.raises(ValueError):
        sanitize_metadata({"details": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}})
    with pytest.raises(ValueError):
        sanitize_metadata({"details": b"binary"})
    with pytest.raises(ValueError):
        sanitize_metadata({"details": float("nan")})
    assert (
        sanitize_metadata({"unapproved_context": "arbitrary-user-controlled-value"})[
            "unapproved_context"
        ]
        == "[REDACTED]"
    )


def test_audit_contract_rejects_unknown_event_and_outcome() -> None:
    values = {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "organization_id": "22222222-2222-4222-8222-222222222222",
        "occurred_at": "2026-10-23T00:00:00Z",
        "actor_id": "member-1",
        "actor_type": "user",
        "auth_method": "jwt",
        "actor_role": "owner",
        "action": AuditAction.POLICY_CREATED,
        "resource_type": "policy",
        "resource_id": "policy-1",
        "outcome": AuditOutcome.SUCCESS,
        "metadata": {},
        "sequence_number": 1,
        "previous_hash": "0" * 64,
        "event_hash": "1" * 64,
    }
    AuditEvent(**values)
    with pytest.raises(ValidationError):
        AuditEvent(**{**values, "action": "unsupported.event"})
    with pytest.raises(ValidationError):
        AuditEvent(**{**values, "outcome": "maybe"})
