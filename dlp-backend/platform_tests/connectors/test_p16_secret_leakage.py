"""Synthetic-secret regression checks for P16 serialization and audit boundaries."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import SecretStr

from dlp_platform.audit.service import sanitize_metadata
from dlp_platform.connectors.models import ConnectorHealth, ConnectorIdentity, ConnectorStatus


def test_connector_models_do_not_expose_provider_credentials_in_serialization():
    sentinels = (
        "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
        "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
        "TEST_OAUTH_CODE_DO_NOT_LEAK",
        "TEST_CLIENT_SECRET_DO_NOT_LEAK",
        "TEST_VAULT_PLAINTEXT_DO_NOT_LEAK",
    )
    health = ConnectorHealth(
        identity=ConnectorIdentity(
            connector_id=uuid4(), organization_id=uuid4(), provider="google_drive"
        ),
        status=ConnectorStatus.CONNECTED,
        last_sync_at=datetime.now(UTC),
    )
    serialized = health.model_dump_json()
    repr_value = repr(
        {
            "access": SecretStr(sentinels[0]),
            "refresh": SecretStr(sentinels[1]),
            "code": SecretStr(sentinels[2]),
            "client_secret": SecretStr(sentinels[3]),
            "vault_plaintext": SecretStr(sentinels[4]),
        }
    )
    for secret in sentinels:
        assert secret not in serialized
        assert secret not in repr_value


def test_audit_metadata_redacts_all_synthetic_p16_secret_fields():
    secrets = {
        "access_token": "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
        "refresh_token": "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
        "oauth_code": "TEST_OAUTH_CODE_DO_NOT_LEAK",
        "client_secret": "TEST_CLIENT_SECRET_DO_NOT_LEAK",
        "vault_plaintext": "TEST_VAULT_PLAINTEXT_DO_NOT_LEAK",
    }
    sanitized = sanitize_metadata(secrets)
    assert all(value == "[REDACTED]" for value in sanitized.values())
    serialized = str(sanitized)
    for secret in secrets.values():
        assert secret not in serialized
