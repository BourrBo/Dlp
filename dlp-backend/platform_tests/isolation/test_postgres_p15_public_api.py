"""PostgreSQL P15 tenant-bound API-key and Vault-backed webhook integration tests."""

import hashlib
import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from dlp_platform.auth.roles import ROLE_PERMISSIONS
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.main import app
from dlp_platform.public_api.webhooks import InMemoryReplayStore, WebhookSigner
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import InMemoryRateLimiter
from dlp_platform.tables import API_KEYS, AUDIT_EVENTS, ORGANIZATIONS, POLICIES, VAULT_SECRETS
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


class TestKeyProvider:
    active_key_version = 1

    def key_for_version(self, version: int) -> bytes:
        if version != 1:
            raise ValueError("unknown synthetic test key")
        return bytes(range(32))


def _seed_tenant(session: Session, *, subject: str) -> tuple[UUID, UUID]:
    org_id, member_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    session.execute(
        ORGANIZATIONS.insert().values(
            id=str(org_id),
            name=f"P15 synthetic {org_id.hex[:8]}",
            settings_json={},
            created_at=now,
            updated_at=now,
        )
    )
    session.execute(
        text(
            "INSERT INTO members "
            "(id,organization_id,auth_subject_id,role,email,active,created_at) "
            "VALUES (:id,:org,:subject,'owner',NULL,true,:now)"
        ),
        {"id": str(member_id), "org": str(org_id), "subject": subject, "now": now},
    )
    return org_id, member_id


def _insert_api_key(session: Session, org_id: UUID, member_id: UUID, scopes: list[str]) -> str:
    prefix = uuid4().hex[:12]
    token = f"dlp_{prefix}.{uuid4().hex}{uuid4().hex[:12]}"
    session.execute(
        API_KEYS.insert().values(
            id=str(uuid4()),
            org_id=str(org_id),
            name="synthetic p15 test key",
            prefix=prefix,
            key_hash=hashlib.sha256(token.encode()).hexdigest(),
            scopes=scopes,
            created_by=str(member_id),
            created_at=datetime.now(UTC),
        )
    )
    return token


def test_postgres_public_api_uses_api_key_scope_and_tenant_rls(monkeypatch) -> None:
    assert DATABASE_URL is not None
    from sqlalchemy import create_engine

    engine = create_engine(DATABASE_URL, pool_size=6)
    subjects = (f"p15-a-{uuid4()}", f"p15-b-{uuid4()}")
    try:
        with Session(engine) as session:
            org_a, member_a = _seed_tenant(session, subject=subjects[0])
            org_b, member_b = _seed_tenant(session, subject=subjects[1])
            policy_a, policy_b = str(uuid4()), str(uuid4())
            now = datetime.now(UTC)
            for org_id, member_id, policy_id, name in (
                (org_a, member_a, policy_a, "Tenant A public policy"),
                (org_b, member_b, policy_b, "Tenant B private policy"),
            ):
                session.execute(
                    POLICIES.insert().values(
                        id=policy_id,
                        org_id=str(org_id),
                        name=name,
                        enabled=True,
                        priority=1,
                        conditions={"channel": "api"},
                        action="block",
                        version=1,
                        created_by=str(member_id),
                        created_at=now,
                        updated_at=now,
                    )
                )
            key_a = _insert_api_key(session, org_a, member_a, ["identity:read"])
            key_a_wrong_scope = _insert_api_key(session, org_a, member_a, ["api_keys:read"])
            key_a_revoked = _insert_api_key(session, org_a, member_a, ["identity:read"])
            session.execute(
                API_KEYS.update()
                .where(API_KEYS.c.prefix == key_a_revoked[4:16])
                .values(revoked_at=now)
            )
            session.commit()

        monkeypatch.setenv(
            "SUPABASE_JWT_SECRET", "synthetic-test-signing-secret-never-use-outside-0123456789"
        )
        monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
        monkeypatch.setenv("JWT_ISSUER", "https://synthetic-project.supabase.co/auth/v1")
        monkeypatch.setenv("JWT_AUDIENCE", "authenticated")
        monkeypatch.setenv("RATE_LIMIT_PER_KEY", "1000")
        monkeypatch.setenv("RATE_LIMIT_PER_ORG", "10000")
        monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
        monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
        prior_session = app.dependency_overrides.get(get_session)
        prior_limiter = app.dependency_overrides.get(get_rate_limiter)

        def override_session():
            with Session(engine) as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        app.dependency_overrides[get_rate_limiter] = lambda: InMemoryRateLimiter(1000, 10000, 60)
        try:
            with TestClient(app) as client:
                public_headers = {"Authorization": f"Bearer {key_a}"}
                first = client.get(
                    f"/api/v1/policies?org_id={org_b}&limit=100000000", headers=public_headers
                )
                assert first.status_code == 422
                page = client.get(f"/api/v1/policies?org_id={org_b}", headers=public_headers)
                assert page.status_code == 200
                assert page.headers.get("x-request-id")
                assert page.json()["pagination"]["total"] == 1
                assert page.json()["data"][0]["id"] == policy_a
                assert "conditions" not in page.json()["data"][0]
                assert (
                    client.get(f"/api/v1/policies/{policy_b}", headers=public_headers).status_code
                    == 404
                )
                assert client.get("/api/v1/policies").status_code == 401
                assert (
                    client.get(
                        "/api/v1/policies", headers={"Authorization": "Bearer invalid"}
                    ).status_code
                    == 401
                )
                assert (
                    client.get(
                        "/api/v1/policies",
                        headers={"Authorization": f"Bearer {key_a_wrong_scope}"},
                    ).status_code
                    == 403
                )
                assert (
                    client.get(
                        "/api/v1/policies",
                        headers={"Authorization": f"Bearer {key_a_revoked}"},
                    ).status_code
                    == 401
                )

            with engine.begin() as connection:
                connection.execute(text("SET LOCAL ROLE authenticated"))
                connection.execute(
                    text("SELECT set_config('request.jwt.claims',:claims,true)"),
                    {
                        "claims": (
                            '{"role":"authenticated","aud":"authenticated",'
                            f'"org_id":"{org_a}","app_role":"owner"' + "}"
                        )
                    },
                )
                assert (
                    connection.execute(text("SELECT count(*) FROM dlp_policies")).scalar_one() == 1
                )
            with engine.begin() as connection:
                connection.execute(text("SET LOCAL ROLE authenticated"))
                connection.execute(
                    text("SELECT set_config('request.jwt.claims',:claims,true)"),
                    {"claims": '{"role":"authenticated","aud":"authenticated"}'},
                )
                assert (
                    connection.execute(text("SELECT count(*) FROM dlp_policies")).scalar_one() == 0
                )
        finally:
            if prior_session is None:
                app.dependency_overrides.pop(get_session, None)
            else:
                app.dependency_overrides[get_session] = prior_session
            if prior_limiter is None:
                app.dependency_overrides.pop(get_rate_limiter, None)
            else:
                app.dependency_overrides[get_rate_limiter] = prior_limiter
    finally:
        engine.dispose()


def test_postgres_webhook_signatures_use_vault_raw_body_and_replay_protection() -> None:
    assert DATABASE_URL is not None
    from sqlalchemy import create_engine

    engine = create_engine(DATABASE_URL)
    clear_secret = "synthetic-p15-webhook-secret-never-production"
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_tenant(session, subject=f"p15-webhook-{uuid4()}")
            owner = Principal(
                organization_id=org_id,
                subject_id=f"p15-owner-{member_id}",
                actor_type=ActorType.USER,
                role=Role.OWNER,
                scopes=tuple(permission.value for permission in ROLE_PERMISSIONS[Role.OWNER]),
                auth_method=AuthMethod.JWT,
                member_id=member_id,
            )
            vault = SecretVault(TestKeyProvider())
            secret_metadata = vault.set(
                session,
                owner,
                name="p15-test-webhook-secret",
                secret_type=SecretType.GENERIC_SECRET,
                value=SecretStr(clear_secret),
                expires_at=None,
            )
            other_secret = vault.set(
                session,
                owner,
                name="p15-test-webhook-other-secret",
                secret_type=SecretType.GENERIC_SECRET,
                value=SecretStr("synthetic-different-webhook-secret"),
                expires_at=None,
            )
            row = (
                session.execute(
                    select(VAULT_SECRETS).where(
                        VAULT_SECRETS.c.id == str(secret_metadata.secret_id)
                    )
                )
                .mappings()
                .one()
            )
            assert clear_secret.encode() not in bytes(row["ciphertext"])
            audit_metadata = (
                session.execute(
                    select(AUDIT_EVENTS.c.event_metadata).where(
                        AUDIT_EVENTS.c.organization_id == str(org_id)
                    )
                )
                .scalars()
                .all()
            )
            assert all(clear_secret not in str(metadata) for metadata in audit_metadata)

            signer = WebhookSigner(vault, InMemoryReplayStore(capacity=10), tolerance_seconds=300)
            body = b'{ "event" : "synthetic", "value": "\xe2\x98\x83" }\n'
            signed = signer.sign(
                session, org_id, secret_metadata.secret_id, body, timestamp=1_800_000_000
            )
            assert signed.startswith("v1;t=1800000000;sig=")
            assert signer.verify(
                session,
                org_id,
                secret_metadata.secret_id,
                body,
                signed,
                now=1_800_000_000,
            ).valid
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    signed,
                    now=1_800_000_000,
                ).code
                == "replay_detected"
            )

            whitespace_changed = signer.verify(
                session,
                org_id,
                secret_metadata.secret_id,
                body.replace(b" ", b""),
                signer.sign(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    timestamp=1_800_000_001,
                ),
                now=1_800_000_001,
            )
            assert whitespace_changed.code == "invalid_signature"
            modified_timestamp = "v1;t=1800000001;sig=" + signed.split("sig=", 1)[1]
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    modified_timestamp,
                    now=1_800_000_001,
                ).code
                == "invalid_signature"
            )
            empty_body_signature = signer.sign(
                session, org_id, secret_metadata.secret_id, b"", timestamp=1_800_000_002
            )
            assert signer.verify(
                session,
                org_id,
                secret_metadata.secret_id,
                b"",
                empty_body_signature,
                now=1_800_000_002,
            ).valid
            malformed_body = b'{"unterminated":'
            malformed_signature = signer.sign(
                session,
                org_id,
                secret_metadata.secret_id,
                malformed_body,
                timestamp=1_800_000_003,
            )
            assert signer.verify(
                session,
                org_id,
                secret_metadata.secret_id,
                malformed_body,
                malformed_signature,
                now=1_800_000_003,
            ).valid
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    signed + ", " + signed,
                    now=1_800_000_000,
                ).code
                == "malformed_signature"
            )
            assert (
                signer.verify(
                    session,
                    org_id,
                    other_secret.secret_id,
                    body,
                    signed,
                    now=1_800_000_000,
                ).code
                == "invalid_signature"
            )
            assert (
                signer.verify(
                    session, org_id, secret_metadata.secret_id, body, None, now=1_800_000_000
                ).code
                == "missing_signature"
            )
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    "v2;t=1800000000;sig=" + "0" * 64,
                    now=1_800_000_000,
                ).code
                == "malformed_signature"
            )
            valid_new_time = signer.sign(
                session, org_id, secret_metadata.secret_id, body, timestamp=1_800_000_100
            )
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    valid_new_time,
                    now=1_800_000_500,
                ).code
                == "timestamp_stale"
            )
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    valid_new_time,
                    now=1_799_999_700,
                ).code
                == "timestamp_in_future"
            )
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    body,
                    valid_new_time[:-1] + ("0" if valid_new_time[-1] != "0" else "1"),
                    now=1_800_000_100,
                ).code
                == "invalid_signature"
            )
            assert (
                signer.verify(
                    session,
                    org_id,
                    uuid4(),
                    body,
                    valid_new_time,
                    now=1_800_000_100,
                ).code
                == "invalid_signature"
            )
            assert (
                signer.verify(
                    session,
                    org_id,
                    secret_metadata.secret_id,
                    b"x" * (1_048_577),
                    valid_new_time,
                    now=1_800_000_100,
                ).code
                == "body_too_large"
            )
    finally:
        engine.dispose()
