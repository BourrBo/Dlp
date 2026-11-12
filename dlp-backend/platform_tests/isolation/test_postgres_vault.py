"""Real PostgreSQL RLS and encrypted persistence checks for the P09 vault."""

import base64
import json
import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.vault.crypto import EnvironmentKeyProvider
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretNotFound, SecretVault

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _set_tenant(connection, organization_id: str | None) -> None:
    connection.execute(text("SET LOCAL ROLE authenticated"))
    claims: dict[str, str] = {"role": "authenticated", "aud": "authenticated", "app_role": "owner"}
    if organization_id is not None:
        claims["org_id"] = organization_id
    connection.execute(
        text("SELECT set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def _principal(org_id: str, *, role: Role = Role.OWNER) -> Principal:
    return Principal(
        organization_id=org_id,
        subject_id="p09-test",
        actor_type=ActorType.USER,
        role=role,
        scopes=tuple(
            permission.value
            for permission in __import__(
                "dlp_platform.auth.roles", fromlist=["ROLE_PERMISSIONS"]
            ).ROLE_PERMISSIONS[role]
        ),
        auth_method=AuthMethod.INTERNAL,
    )


def test_postgres_vault_ciphertext_rls_permissions_and_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert DATABASE_URL is not None
    key_v1, key_v2 = b"1" * 32, b"2" * 32
    monkeypatch.setenv("DLP_VAULT_ENABLED", "true")
    monkeypatch.setenv("DLP_VAULT_ACTIVE_KEY_VERSION", "1")
    monkeypatch.setenv("DLP_VAULT_MASTER_KEY", base64.b64encode(key_v1).decode())
    monkeypatch.setenv("DLP_VAULT_PREVIOUS_KEYS", "")
    org_a, org_b, secret_a, secret_b = (str(uuid4()) for _ in range(4))
    engine = create_engine(DATABASE_URL)
    try:
        config = Config("alembic.ini")
        config.set_main_option("sqlalchemy.url", DATABASE_URL)
        command.upgrade(config, "head")
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO organizations(id,name) VALUES (:a,'P09 A'),(:b,'P09 B')"),
                {"a": org_a, "b": org_b},
            )
            for org, identifier, name in (
                (org_a, secret_a, "tenant-a-secret"),
                (org_b, secret_b, "tenant-b-secret"),
            ):
                _set_tenant(connection, org)
                connection.execute(
                    text(
                        "INSERT INTO dlp_vault_secrets "
                        "(id,org_id,name,secret_type,ciphertext,nonce,key_version,enabled) "
                        "VALUES (:id,:org,:name,'generic_secret',:ciphertext,:nonce,1,true)"
                    ),
                    {
                        "id": identifier,
                        "org": org,
                        "name": name,
                        "ciphertext": b"x" * 16,
                        "nonce": b"n" * 12,
                    },
                )
                connection.execute(text("RESET ROLE"))
                connection.execute(text("SELECT set_config('request.jwt.claims', '{}', true)"))

        with engine.begin() as connection:
            _set_tenant(connection, org_a)
            assert connection.execute(
                text("SELECT id FROM dlp_vault_secrets ORDER BY id")
            ).scalars().all() == [secret_a]
            assert (
                connection.execute(
                    text("UPDATE dlp_vault_secrets SET enabled=false WHERE id=:id"),
                    {"id": secret_b},
                ).rowcount
                == 0
            )
            assert (
                connection.execute(
                    text("DELETE FROM dlp_vault_secrets WHERE id=:id"), {"id": secret_b}
                ).rowcount
                == 0
            )
            with pytest.raises(DBAPIError), connection.begin_nested():
                connection.execute(
                    text(
                        "INSERT INTO dlp_vault_secrets "
                        "(id,org_id,name,secret_type,ciphertext,nonce,key_version,enabled) "
                        "VALUES (:id,:org,'forged','generic_secret',:ciphertext,:nonce,1,true)"
                    ),
                    {"id": str(uuid4()), "org": org_b, "ciphertext": b"x" * 16, "nonce": b"n" * 12},
                )

        with engine.begin() as connection:
            _set_tenant(connection, None)
            assert (
                connection.execute(text("SELECT id FROM dlp_vault_secrets")).scalars().all() == []
            )

        monkeypatch.setenv(
            "DLP_VAULT_PREVIOUS_KEYS", '{"1":"' + base64.b64encode(key_v1).decode() + '"}'
        )
        monkeypatch.setenv("DLP_VAULT_ACTIVE_KEY_VERSION", "2")
        monkeypatch.setenv("DLP_VAULT_MASTER_KEY", base64.b64encode(key_v2).decode())
        vault = SecretVault(EnvironmentKeyProvider.from_env())
        principal_a = _principal(org_a)
        with Session(engine) as session:
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_a}
                    )
                },
            )
            created = vault.set(
                session,
                principal_a,
                name="fresh-secret",
                secret_type=SecretType.GENERIC_SECRET,
                value=SecretStr("P09-plaintext-canary"),
                expires_at=None,
            )
            assert created.key_version == 2
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_a}
                    )
                },
            )
            plaintext = vault.get(session, principal_a, created.secret_id)
            assert plaintext.get_secret_value() == "P09-plaintext-canary"
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_a}
                    )
                },
            )
            assert vault.list_metadata(session, principal_a)[0].secret_id == created.secret_id

        with engine.connect() as connection:
            raw = connection.execute(
                text("SELECT ciphertext,nonce,key_version FROM dlp_vault_secrets WHERE id=:id"),
                {"id": str(created.secret_id)},
            ).one()
            assert b"P09-plaintext-canary" not in raw.ciphertext
            assert len(raw.nonce) == 12
            assert raw.key_version == 2

        # Tenant B cannot retrieve A's metadata or decrypt A's secret through the service.
        principal_b = _principal(org_b)
        with Session(engine) as session:
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_b}
                    )
                },
            )
            with pytest.raises(SecretNotFound):
                vault.metadata(session, principal_b, created.secret_id)
            with pytest.raises(SecretNotFound):
                vault.get(session, principal_b, created.secret_id)

        # Analyst has no vault capability, even with database visibility to own-tenant rows.
        analyst = _principal(org_a, role=Role.ANALYST)
        with Session(engine) as session, pytest.raises(Exception) as denied:
            vault.list_metadata(session, analyst)
        assert getattr(denied.value, "status_code", None) == 403

        # Exercise update, expiry, soft-disable and re-encryption with retained v1 key.
        with Session(engine) as session:
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_a}
                    )
                },
            )
            older = vault.set(
                session,
                principal_a,
                name="rotation-secret",
                secret_type=SecretType.GENERIC_SECRET,
                value=SecretStr("rotate-canary"),
                expires_at=None,
            )
        monkeypatch.setenv("DLP_VAULT_ACTIVE_KEY_VERSION", "1")
        monkeypatch.setenv("DLP_VAULT_MASTER_KEY", base64.b64encode(key_v1).decode())
        monkeypatch.setenv("DLP_VAULT_PREVIOUS_KEYS", "")
        v1_vault = SecretVault(EnvironmentKeyProvider.from_env())
        with Session(engine) as session:
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_a}
                    )
                },
            )
            older = v1_vault.set(
                session,
                principal_a,
                name="rotation-secret",
                secret_type=SecretType.GENERIC_SECRET,
                value=SecretStr("rotate-canary"),
                expires_at=None,
                secret_id=older.secret_id,
            )
        monkeypatch.setenv("DLP_VAULT_ACTIVE_KEY_VERSION", "2")
        monkeypatch.setenv("DLP_VAULT_MASTER_KEY", base64.b64encode(key_v2).decode())
        monkeypatch.setenv(
            "DLP_VAULT_PREVIOUS_KEYS", '{"1":"' + base64.b64encode(key_v1).decode() + '"}'
        )
        v2_vault = SecretVault(EnvironmentKeyProvider.from_env())
        with Session(engine) as session:
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_a}
                    )
                },
            )
            assert v2_vault.rotate(session, principal_a, older.secret_id).key_version == 2
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {"role": "authenticated", "aud": "authenticated", "org_id": org_a}
                    )
                },
            )
            assert v2_vault.exists(session, principal_a, "rotation-secret")
            v2_vault.disable(session, principal_a, older.secret_id)
            assert not v2_vault.exists(session, principal_a, "rotation-secret")
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("DELETE FROM audit_events WHERE organization_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            connection.execute(
                text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("DELETE FROM dlp_vault_secrets WHERE org_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            connection.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()
