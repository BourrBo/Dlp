"""Direct PostgreSQL RLS checks for the P16 connector registry and checkpoint table."""

import hashlib
import json
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from dlp_platform.auth.principal import get_principal
from dlp_platform.connectors import google_drive
from dlp_platform.connectors.oauth import OAuthRejected, PersistentOAuthTransactions
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import connectors
from dlp_platform.tables import APP_SESSIONS, MEMBERS, ORGANIZATIONS
from dlp_platform.vault.models import SecretType

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _tenant_context(connection, org_id: str | None) -> None:
    connection.execute(text("SET LOCAL ROLE authenticated"))
    claims = {"role": "authenticated", "aud": "authenticated", "app_role": "owner"}
    if org_id is not None:
        claims["org_id"] = org_id
    connection.execute(
        text("SELECT set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def test_postgres_p16_connector_tables_enforce_tenant_rls() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    connector_a, connector_b = str(uuid4()), str(uuid4())
    now = datetime.now(UTC)
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    try:
        command.upgrade(config, "head")
        with engine.begin() as connection:
            connection.execute(
                ORGANIZATIONS.insert(),
                [
                    {
                        "id": org_a,
                        "name": f"P16 A {org_a[:8]}",
                        "settings_json": {},
                        "created_at": now,
                        "updated_at": now,
                    },
                    {
                        "id": org_b,
                        "name": f"P16 B {org_b[:8]}",
                        "settings_json": {},
                        "created_at": now,
                        "updated_at": now,
                    },
                ],
            )
            for org_id, connector_id in ((org_a, connector_a), (org_b, connector_b)):
                connection.execute(
                    text(
                        "INSERT INTO dlp_connectors "
                        "(id,org_id,provider,name,status,config_json,created_at,updated_at) "
                        "VALUES (:id,:org,'google_drive','test','connected','{}',:now,:now)"
                    ),
                    {"id": connector_id, "org": org_id, "now": now},
                )
                connection.execute(
                    text(
                        "INSERT INTO dlp_connector_state "
                        "(connector_id,org_id,provider,checkpoint,state_json,updated_at) "
                        "VALUES (:id,:org,'google_drive','checkpoint','{}',:now)"
                    ),
                    {"id": connector_id, "org": org_id, "now": now},
                )

        with engine.begin() as connection:
            _tenant_context(connection, org_a)
            assert connection.execute(text("SELECT id FROM dlp_connectors")).scalars().all() == [
                connector_a
            ]
            assert connection.execute(
                text("SELECT connector_id FROM dlp_connector_state")
            ).scalars().all() == [connector_a]
            assert (
                connection.execute(
                    text("UPDATE dlp_connectors SET name='forged' WHERE id=:id"),
                    {"id": connector_b},
                ).rowcount
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "UPDATE dlp_connector_state SET checkpoint='forged' WHERE connector_id=:id"
                    ),
                    {"id": connector_b},
                ).rowcount
                == 0
            )
            assert (
                connection.execute(
                    text("DELETE FROM dlp_connectors WHERE id=:id"), {"id": connector_b}
                ).rowcount
                == 0
            )

        with engine.begin() as connection:
            _tenant_context(connection, None)
            assert connection.execute(text("SELECT id FROM dlp_connectors")).scalars().all() == []
            assert (
                connection.execute(text("SELECT connector_id FROM dlp_connector_state"))
                .scalars()
                .all()
                == []
            )

        with engine.begin() as connection:
            _tenant_context(connection, org_a)
            with pytest.raises(DBAPIError):
                connection.execute(
                    text(
                        "INSERT INTO dlp_connectors "
                        "(id,org_id,provider,name,status,config_json,created_at,updated_at) "
                        "VALUES (:id,:org,'google_drive','forged','connected','{}',:now,:now)"
                    ),
                    {"id": str(uuid4()), "org": org_b, "now": now},
                )
    finally:
        with engine.begin() as connection:
            # Cleanup requires privileged owner context and is isolated to these fixture IDs.
            connection.execute(
                text("DELETE FROM dlp_connectors WHERE id IN (:a,:b)"),
                {"a": connector_a, "b": connector_b},
            )
            connection.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()


def test_postgres_oauth_state_is_durable_and_atomically_one_time() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_size=5)
    org_id = uuid4()
    now = datetime.now(UTC)
    transactions = PersistentOAuthTransactions()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    try:
        command.upgrade(config, "head")
        with engine.begin() as connection:
            connection.execute(
                ORGANIZATIONS.insert().values(
                    id=str(org_id),
                    name=f"P16 OAuth {str(org_id)[:8]}",
                    settings_json={},
                    created_at=now,
                    updated_at=now,
                )
            )

        def create_transaction():
            with Session(engine) as session:
                return transactions.create(
                    session,
                    organization_id=org_id,
                    principal_id="oauth-user",
                    provider="google_drive",
                    redirect_uri="https://dlp.example.test/oauth/callback",
                    binding_id=str(uuid4()),
                    role=Role.OWNER,
                    member_id=uuid4(),
                    session_id=uuid4(),
                    scopes=("connectors:write",),
                    auth_method=AuthMethod.SSO,
                )[0]

        first = create_transaction()
        with Session(engine) as session, pytest.raises(OAuthRejected):
            transactions.consume_callback(session, first.state, provider="other_provider")
        with Session(engine) as session:
            consumed = transactions.consume_callback(session, first.state, provider="google_drive")
        assert consumed.verifier == first.verifier
        assert consumed.principal_id == "oauth-user"
        with Session(engine) as session, pytest.raises(OAuthRejected):
            transactions.consume_callback(session, first.state, provider="google_drive")

        _, _, state_random = first.state.partition(".")
        other_tenant_state = f"{uuid4()}.{state_random}"
        with Session(engine) as session, pytest.raises(OAuthRejected):
            transactions.consume_callback(session, other_tenant_state, provider="google_drive")
        invalid_state = f"{org_id}.{secrets.token_urlsafe(32)}"
        with Session(engine) as session, pytest.raises(OAuthRejected):
            transactions.consume_callback(session, invalid_state, provider="google_drive")

        expired = create_transaction()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE dlp_oauth_transactions SET expires_at=:expired WHERE state_hash=:hash"
                ),
                {
                    "expired": datetime.now(UTC),
                    "hash": hashlib.sha256(expired.state.encode()).hexdigest(),
                },
            )
        with Session(engine) as session, pytest.raises(OAuthRejected):
            transactions.consume_callback(session, expired.state, provider="google_drive")

        concurrent = create_transaction()

        def consume_once() -> bool:
            try:
                with Session(engine) as session:
                    transactions.consume_callback(
                        session, concurrent.state, provider="google_drive"
                    )
                return True
            except OAuthRejected:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume_once(), range(2)))
        assert sorted(results) == [False, True]

        with engine.begin() as connection:
            _tenant_context(connection, str(org_id))
            oauth_rows = (
                connection.execute(
                    text(
                        "SELECT state_hash, provider, verifier FROM dlp_oauth_transactions "
                        "WHERE org_id=:org"
                    ),
                    {"org": str(org_id)},
                )
                .mappings()
                .all()
            )
            assert len(oauth_rows) == 2
            assert {row["state_hash"] for row in oauth_rows} == {
                hashlib.sha256(item.state.encode()).hexdigest() for item in (first, concurrent)
            }
            serialized_oauth_rows = json.dumps([dict(row) for row in oauth_rows])
            for secret in (
                "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
                "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
                "TEST_OAUTH_CODE_DO_NOT_LEAK",
                "TEST_CLIENT_SECRET_DO_NOT_LEAK",
                "TEST_VAULT_PLAINTEXT_DO_NOT_LEAK",
            ):
                assert secret not in serialized_oauth_rows
            assert (
                connection.execute(
                    text("SELECT count(*) FROM dlp_oauth_transactions WHERE org_id=:org"),
                    {"org": str(org_id)},
                ).scalar_one()
                == 2
            )
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM organizations WHERE id=:id"), {"id": str(org_id)})
        engine.dispose()


def test_persistent_postgres_oauth_callback_consumes_state_over_http(monkeypatch) -> None:
    """Exercise the real persistent state store at the mounted HTTP callback boundary."""
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    org_id, member_id, session_id = uuid4(), uuid4(), uuid4()
    now = datetime.now(UTC)
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    writes = []
    exchange_calls = []
    expected_verifier = {"value": None}

    class FixtureVault:
        def set(self, _session, _principal, **kwargs):
            writes.append(kwargs)
            return type("VaultSecret", (), {"secret_id": uuid4()})()

        def disable(self, *_args, **_kwargs):
            raise AssertionError("valid callback must not disable its credential")

    class FixtureService:
        def _rls(self, _session, _principal):
            pass

        def set_connection(self, *_args, **_kwargs):
            pass

        def mark_connect_failed(self, *_args, **_kwargs):
            pass

    class FixtureTransport:
        def request(
            self,
            method,
            url,
            *,
            headers,
            body=None,
            max_bytes=google_drive.MAX_RESPONSE_BYTES,
        ):
            del headers, max_bytes
            assert method == "POST"
            assert google_drive.validate_provider_endpoint(url, google_drive.GOOGLE_OAUTH_HOSTS)
            assert url == google_drive.GOOGLE_TOKEN_ENDPOINT
            assert body is not None
            if parse_qs(body.decode())["code_verifier"][0] != expected_verifier["value"]:
                raise google_drive.ProviderFailure("authorization_failed")
            exchange_calls.append((url, body))
            return (
                b'{"access_token":"TEST_ACCESS_TOKEN_DO_NOT_LEAK",'
                b'"refresh_token":"TEST_REFRESH_TOKEN_DO_NOT_LEAK",'
                b'"scope":"https://www.googleapis.com/auth/drive",'
                b'"token_type":"Bearer"}'
            )

    class FixtureDrive:
        def __init__(self, access_token):
            assert access_token == "TEST_ACCESS_TOKEN_DO_NOT_LEAK"

        def get_start_page_token(self):
            return "fixture-checkpoint"

    principal = Principal(
        organization_id=org_id,
        subject_id="persistent-oauth-user",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("connectors:write",),
        auth_method=AuthMethod.SSO,
        member_id=member_id,
        session_id=session_id,
    )
    transactions = PersistentOAuthTransactions()
    try:
        command.upgrade(config, "head")
        with engine.begin() as connection:
            connection.execute(
                ORGANIZATIONS.insert().values(
                    id=str(org_id),
                    name=f"P16 callback {str(org_id)[:8]}",
                    settings_json={},
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                MEMBERS.insert().values(
                    id=str(member_id),
                    organization_id=str(org_id),
                    auth_subject_id=principal.subject_id,
                    role=Role.OWNER.value,
                    active=True,
                    created_at=now,
                )
            )
            connection.execute(
                APP_SESSIONS.insert().values(
                    id=str(session_id),
                    org_id=str(org_id),
                    member_id=str(member_id),
                    token_hash=hashlib.sha256(str(uuid4()).encode()).hexdigest(),
                    auth_method=AuthMethod.SSO.value,
                    created_at=now,
                    last_seen_at=now,
                    expires_at=now + timedelta(hours=1),
                    revoked_at=None,
                    source_ip=None,
                    user_agent=None,
                )
            )
        with factory() as session:
            transaction, _challenge = transactions.create(
                session,
                organization_id=org_id,
                principal_id=principal.subject_id,
                provider="google_drive",
                redirect_uri="https://dlp.example.test/connectors/oauth/google/callback",
                binding_id=str(uuid4()),
                role=Role.OWNER,
                member_id=member_id,
                session_id=session_id,
                scopes=principal.scopes,
                auth_method=AuthMethod.SSO,
            )
            expected_verifier["value"] = transaction.verifier

        settings = google_drive.GoogleOAuthSettings(
            client_id="fixture-client",
            client_secret="TEST_CLIENT_SECRET_DO_NOT_LEAK",
            redirect_uri=transaction.redirect_uri,
        )
        oauth_client = google_drive.GoogleOAuthClient(settings, FixtureTransport())
        monkeypatch.setattr(connectors, "_service", FixtureService())
        monkeypatch.setattr(connectors, "_oauth_transactions", transactions)
        monkeypatch.setattr(connectors, "_oauth", lambda: (settings, oauth_client))
        monkeypatch.setattr(connectors, "GoogleDriveAPI", FixtureDrive)
        app = FastAPI()
        app.include_router(connectors.router)
        app.dependency_overrides[get_principal] = lambda: principal

        def get_test_session():
            with factory() as session:
                yield session

        app.dependency_overrides[get_session] = get_test_session
        app.dependency_overrides[get_rate_limiter] = lambda: type(
            "Limiter",
            (),
            {
                "check": lambda self, *_args: type(
                    "RateResult", (), {"allowed": True, "retry_after": 0}
                )()
            },
        )()
        app.dependency_overrides[connectors._vault] = lambda: FixtureVault()

        with TestClient(app) as client:
            callback = client.get(
                "/connectors/oauth/google/callback",
                params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
                follow_redirects=False,
            )
            replay = client.get(
                "/connectors/oauth/google/callback",
                params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
                follow_redirects=False,
            )
        assert callback.status_code == 303, callback.text
        assert replay.status_code == 400
        assert len(exchange_calls) == 1
        assert len(writes) == 1
        assert writes[0]["secret_type"] is SecretType.REFRESH_TOKEN
        assert writes[0]["value"].get_secret_value() == "TEST_REFRESH_TOKEN_DO_NOT_LEAK"
        for response in (callback, replay):
            for marker in (
                "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
                "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
                "TEST_OAUTH_CODE_DO_NOT_LEAK",
                "TEST_CLIENT_SECRET_DO_NOT_LEAK",
            ):
                assert marker not in response.text
        digest = hashlib.sha256(transaction.state.encode()).hexdigest()
        with engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT state_hash, consumed_at, verifier FROM dlp_oauth_transactions "
                        "WHERE state_hash=:digest"
                    ),
                    {"digest": digest},
                )
                .mappings()
                .one()
            )
        assert row["consumed_at"] is not None
        assert row["state_hash"] == digest
        assert transaction.state not in json.dumps(dict(row), default=str)

        def create_state(principal_id=principal.subject_id):
            with factory() as session:
                return transactions.create(
                    session,
                    organization_id=org_id,
                    principal_id=principal_id,
                    provider="google_drive",
                    redirect_uri=transaction.redirect_uri,
                    binding_id=str(uuid4()),
                    role=Role.OWNER,
                    member_id=member_id,
                    session_id=session_id,
                    scopes=principal.scopes,
                    auth_method=AuthMethod.SSO,
                )[0]

        expired = create_state()
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE dlp_oauth_transactions SET expires_at=:time WHERE state_hash=:hash"),
                {
                    "time": datetime.now(UTC) - timedelta(seconds=1),
                    "hash": hashlib.sha256(expired.state.encode()).hexdigest(),
                },
            )
        expected_verifier["value"] = expired.verifier
        wrong_tenant = f"{uuid4()}.{expired.state.partition('.')[2]}"
        with TestClient(app) as client:
            expired_response = client.get(
                "/connectors/oauth/google/callback",
                params={"state": expired.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
            )
            wrong_tenant_response = client.get(
                "/connectors/oauth/google/callback",
                params={"state": wrong_tenant, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
            )
        assert expired_response.status_code == 400
        assert wrong_tenant_response.status_code == 400
        assert len(writes) == 1

        other_principal = create_state("different-oauth-user")
        with TestClient(app) as client:
            principal_response = client.get(
                "/connectors/oauth/google/callback",
                params={"state": other_principal.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
            )
        assert principal_response.status_code == 401
        assert len(writes) == 1

        pkce_mismatch = create_state()
        expected_verifier["value"] = pkce_mismatch.verifier
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE dlp_oauth_transactions SET verifier='wrong-verifier' "
                    "WHERE state_hash=:hash"
                ),
                {"hash": hashlib.sha256(pkce_mismatch.state.encode()).hexdigest()},
            )
        expected_verifier["value"] = pkce_mismatch.verifier
        with TestClient(app) as client:
            pkce_response = client.get(
                "/connectors/oauth/google/callback",
                params={"state": pkce_mismatch.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
            )
        assert pkce_response.status_code == 503
        assert len(writes) == 1
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM dlp_app_sessions WHERE id=:id"), {"id": str(session_id)}
            )
            connection.execute(text("DELETE FROM organizations WHERE id=:id"), {"id": str(org_id)})
        engine.dispose()
