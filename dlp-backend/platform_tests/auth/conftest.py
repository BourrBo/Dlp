"""Integration fixtures for P02 auth tests using synthetic identities."""

from collections.abc import Generator
from pathlib import Path
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from dlp_platform.database import get_session
from dlp_platform.main import app
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.tables import (
    APP_SESSIONS,
    AUDIT_EVENTS,
    IP_ALLOWLIST_ENTRIES,
    IP_ALLOWLIST_SETTINGS,
    LEGAL_HOLDS,
    ORG_DELETION_REQUESTS,
    RETENTION_POLICIES,
    RETENTION_RUNS,
    SCIM_CREDENTIALS,
    SCIM_GROUP_MEMBERS,
    SCIM_GROUPS,
    SCIM_USERS,
)


@pytest.fixture
def auth_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("RATE_LIMIT_PER_KEY", "1000")
    monkeypatch.setenv("RATE_LIMIT_PER_ORG", "10000")
    get_rate_limiter.cache_clear()
    database_path = (tmp_path / "p02-auth-tests.db").as_posix()
    database_url = f"sqlite:///{database_path}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    # P02 route regressions intentionally stay on the last SQLite-compatible
    # revision; 0003 is PostgreSQL/Supabase-only and is tested separately.
    command.upgrade(config, "0002_api_keys")
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE members ADD COLUMN active BOOLEAN NOT NULL DEFAULT 1"))
        connection.execute(text("ALTER TABLE members ADD COLUMN email VARCHAR(320)"))
        connection.execute(
            text("CREATE UNIQUE INDEX uq_members_id_org ON members (id, organization_id)")
        )
    AUDIT_EVENTS.create(engine)
    APP_SESSIONS.create(engine)
    IP_ALLOWLIST_SETTINGS.create(engine)
    IP_ALLOWLIST_ENTRIES.create(engine)
    SCIM_CREDENTIALS.create(engine)
    SCIM_USERS.create(engine)
    SCIM_GROUPS.create(engine)
    SCIM_GROUP_MEMBERS.create(engine)
    LEGAL_HOLDS.create(engine)
    ORG_DELETION_REQUESTS.create(engine)
    RETENTION_POLICIES.create(engine)
    RETENTION_RUNS.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    app.state.test_session_factory = factory

    with factory.begin() as session:
        for org_id in (ORG_A, ORG_B):
            session.execute(
                text("INSERT INTO organizations (id, name) VALUES (:id, :name)"),
                {"id": str(org_id), "name": f"Test {org_id.hex[:4]}"},
            )
        for member_id, org_id, subject, role in MEMBERS:
            session.execute(
                text(
                    "INSERT INTO members (id, organization_id, auth_subject_id, role) "
                    "VALUES (:id, :org, :subject, :role)"
                ),
                {"id": str(member_id), "org": str(org_id), "subject": subject, "role": role},
            )

    def override_session() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    monkeypatch.setenv("SUPABASE_JWT_SECRET", JWT_SECRET)
    monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
    monkeypatch.setenv("JWT_ISSUER", ISSUER)
    monkeypatch.setenv("JWT_AUDIENCE", "authenticated")
    monkeypatch.setenv("JWT_LEEWAY_SECONDS", "0")
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    get_rate_limiter.cache_clear()
    engine.dispose()


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")
OWNER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ADMIN_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
ANALYST_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
VIEWER_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
AUDITOR_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
ORG_B_OWNER_ID = UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")
MEMBERS = (
    (OWNER_ID, ORG_A, "user-owner-a", "owner"),
    (ADMIN_ID, ORG_A, "user-admin-a", "admin"),
    (ANALYST_ID, ORG_A, "user-analyst-a", "analyst"),
    (VIEWER_ID, ORG_A, "user-viewer-a", "viewer"),
    (AUDITOR_ID, ORG_A, "user-auditor-a", "auditor"),
    (ORG_B_OWNER_ID, ORG_B, "user-owner-b", "owner"),
)
JWT_SECRET = "synthetic-test-signing-secret-never-use-outside-tests-0123456789"
ISSUER = "https://synthetic-project.supabase.co/auth/v1"
