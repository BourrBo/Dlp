"""Real PostgreSQL RLS checks for SCIM tenant resources and credentials."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from dlp_platform.database import get_session
from dlp_platform.main import app

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _claims(org_id: str | None, app_role: str = "scim") -> str:
    claims: dict[str, str] = {
        "role": "authenticated",
        "aud": "authenticated",
        "app_role": app_role,
    }
    if org_id is not None:
        claims["org_id"] = org_id
    return json.dumps(claims)


def test_scim_rls_tenant_binding_mutations_and_missing_context() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    member_a, member_b = str(uuid4()), str(uuid4())
    race_member_a, race_member_b = str(uuid4()), str(uuid4())
    credential_a, credential_b = str(uuid4()), str(uuid4())
    user_a, user_b = str(uuid4()), str(uuid4())
    group_a, group_b = str(uuid4()), str(uuid4())
    try:
        with engine.begin() as conn:
            for org_id in (org_a, org_b):
                conn.execute(
                    text(
                        "INSERT INTO organizations (id,name) VALUES (:id,'P12 RLS test')"
                    ),
                    {"id": org_id},
                )
            for member, org in (
                (member_a, org_a),
                (member_b, org_b),
                (race_member_a, org_a),
                (race_member_b, org_a),
            ):
                conn.execute(
                    text(
                        "INSERT INTO members (id,organization_id,auth_subject_id,role,email) "
                        "VALUES (:id,:org,:sub,'owner',:email)"
                    ),
                    {
                        "id": member,
                        "org": org,
                        "sub": member,
                        "email": f"{member}@test.invalid",
                    },
                )
            for credential, member, org in (
                (credential_a, member_a, org_a),
                (credential_b, member_b, org_b),
            ):
                conn.execute(
                    text(
                        "INSERT INTO dlp_scim_credentials "
                        "(id,org_id,name,prefix,token_hash,created_by,created_at) "
                        "VALUES (:id,:org,'RLS test',:prefix,:hash,:member,now())"
                    ),
                    {
                        "id": credential,
                        "org": org,
                        "prefix": credential[:12],
                        "hash": "a" * 64,
                        "member": member,
                    },
                )
            for user, member, org in (
                (user_a, member_a, org_a),
                (user_b, member_b, org_b),
            ):
                conn.execute(
                    text(
                        "INSERT INTO dlp_scim_users "
                        "(id,org_id,member_id,external_id,user_name,created_at,updated_at) "
                        "VALUES (:id,:org,:member,:external,:name,now(),now())"
                    ),
                    {
                        "id": user,
                        "org": org,
                        "member": member,
                        "external": user,
                        "name": f"{user}@test.invalid",
                    },
                )
            for group, org in ((group_a, org_a), (group_b, org_b)):
                conn.execute(
                    text(
                        "INSERT INTO dlp_scim_groups "
                        "(id,org_id,external_id,display_name,created_at,updated_at) "
                        "VALUES (:id,:org,:external,:name,now(),now())"
                    ),
                    {
                        "id": group,
                        "org": org,
                        "external": group,
                        "name": f"group-{group}",
                    },
                )
            conn.execute(
                text(
                    "INSERT INTO dlp_scim_group_members (org_id,group_id,member_id,created_at) "
                    "VALUES (:org,:group,:member,now())"
                ),
                {"org": org_a, "group": group_a, "member": member_a},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_scim_group_members (org_id,group_id,member_id,created_at) "
                    "VALUES (:org,:group,:member,now())"
                ),
                {"org": org_b, "group": group_b, "member": member_b},
            )

        with engine.connect() as conn:
            tx = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": _claims(org_a)},
            )
            for table, id_a, id_b in (
                ("dlp_scim_users", user_a, user_b),
                ("dlp_scim_groups", group_a, group_b),
            ):
                visible = (
                    conn.execute(
                        text(f"SELECT id FROM {table} WHERE id IN (:a,:b)"),
                        {"a": id_a, "b": id_b},
                    )
                    .scalars()
                    .all()
                )
                assert visible == [id_a]
                assert (
                    conn.execute(
                        text(f"UPDATE {table} SET updated_at=now() WHERE id=:id"),
                        {"id": id_b},
                    ).rowcount
                    == 0
                )
                assert (
                    conn.execute(
                        text(f"DELETE FROM {table} WHERE id=:id"), {"id": id_b}
                    ).rowcount
                    == 0
                )
            assert conn.execute(
                text(
                    "SELECT member_id FROM dlp_scim_group_members WHERE org_id IN (:a,:b)"
                ),
                {"a": org_a, "b": org_b},
            ).scalars().all() == [member_a]
            assert (
                conn.execute(
                    text(
                        "UPDATE dlp_scim_group_members SET created_at=now() "
                        "WHERE org_id=:org AND group_id=:group"
                    ),
                    {"org": org_b, "group": group_b},
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text(
                        "DELETE FROM dlp_scim_group_members "
                        "WHERE org_id=:org AND group_id=:group"
                    ),
                    {"org": org_b, "group": group_b},
                ).rowcount
                == 0
            )
            # SCIM tokens can use provisioned resources but cannot inspect credential hashes.
            assert (
                conn.execute(text("SELECT id FROM dlp_scim_credentials"))
                .scalars()
                .all()
                == []
            )
            tx.rollback()

            tx = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": _claims(org_a)},
            )
            with pytest.raises(DBAPIError):
                conn.execute(
                    text("UPDATE members SET role='admin' WHERE id=:member"),
                    {"member": member_a},
                )
            tx.rollback()

            tx = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": _claims(org_a, "owner")},
            )
            assert conn.execute(
                text("SELECT id FROM dlp_scim_credentials WHERE id IN (:a,:b)"),
                {"a": credential_a, "b": credential_b},
            ).scalars().all() == [credential_a]
            tx.rollback()

            tx = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": _claims(None)},
            )
            assert (
                conn.execute(text("SELECT id FROM dlp_scim_users")).scalars().all()
                == []
            )
            with pytest.raises(DBAPIError):
                conn.execute(
                    text(
                        "INSERT INTO dlp_scim_groups "
                        "(id,org_id,display_name,created_at,updated_at) "
                        "VALUES (:id,:org,'forged',now(),now())"
                    ),
                    {"id": str(uuid4()), "org": org_b},
                )
            tx.rollback()

        # The database's case-insensitive unique index serializes concurrent provisioning.
        barrier = Barrier(2)

        def insert_duplicate(race_member: str) -> bool:
            try:
                with engine.begin() as conn:
                    barrier.wait(timeout=10)
                    conn.execute(
                        text(
                            "INSERT INTO dlp_scim_users "
                            "(id,org_id,member_id,user_name,created_at,updated_at) "
                            "VALUES (:id,:org,:member,'race@example.invalid',:now,:now)"
                        ),
                        {
                            "id": str(uuid4()),
                            "org": org_a,
                            "member": race_member,
                            "now": datetime.now(UTC),
                        },
                    )
                return True
            except DBAPIError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sum(pool.map(insert_duplicate, (race_member_a, race_member_b))) == 1
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
        engine.dispose()


def test_scim_endpoints_execute_inside_real_postgres_tenant_context(
    monkeypatch,
) -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    org_id, member_id = str(uuid4()), str(uuid4())
    test_email = f"{uuid4()}@p12-test.invalid"
    provisioned_email = f"provisioned-{uuid4()}@p12-test.invalid"
    secret = "synthetic-p12-jwt-signing-key-not-a-real-credential-0123456789"
    subject = "p12-postgres-test-owner"
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("SUPABASE_JWT_SECRET", secret)
    monkeypatch.setenv("JWT_ISSUER", "https://p12-test.invalid/auth")
    monkeypatch.setenv("JWT_AUDIENCE", "authenticated")
    monkeypatch.setenv("RATE_LIMIT_PER_KEY", "1000")
    monkeypatch.setenv("RATE_LIMIT_PER_ORG", "10000")
    from dlp_platform.ratelimit.dependencies import get_rate_limiter

    get_rate_limiter.cache_clear()

    def override_session():
        with factory() as session:
            yield session

    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO organizations (id,name) VALUES (:id,'P12 API test')"),
            {"id": org_id},
        )
        conn.execute(
            text(
                "INSERT INTO members (id,organization_id,auth_subject_id,role,email) "
                "VALUES (:id,:org,:subject,'owner',:email)"
            ),
            {"id": member_id, "org": org_id, "subject": subject, "email": test_email},
        )
    app.dependency_overrides[get_session] = override_session
    jwt_token = jwt.encode(
        {
            "sub": subject,
            "org_id": org_id,
            "iss": "https://p12-test.invalid/auth",
            "aud": "authenticated",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        secret,
        algorithm="HS256",
    )
    try:
        with TestClient(app) as client:
            admin_headers = {"Authorization": f"Bearer {jwt_token}"}
            credential = client.post(
                "/api/scim/credentials",
                json={"name": "PostgreSQL integration"},
                headers=admin_headers,
            )
            assert credential.status_code == 201
            scim_headers = {
                "Authorization": f"Bearer {credential.json()['token']}",
                "Content-Type": "application/scim+json",
            }
            created = client.post(
                "/scim/v2/Users",
                json={
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": provisioned_email,
                    "externalId": "pg-123",
                    "emails": [{"type": "work", "value": provisioned_email}],
                },
                headers=scim_headers,
            )
            assert created.status_code == 201
            resource_id = created.json()["id"]
            assert (
                client.get(
                    f"/scim/v2/Users/{resource_id}", headers=scim_headers
                ).status_code
                == 200
            )
            assert (
                client.get(
                    "/scim/v2/Users", headers={"Authorization": "Bearer invalid"}
                ).status_code
                == 401
            )
            assert client.get("/policies", headers=scim_headers).status_code == 401
            group = client.post(
                "/scim/v2/Groups",
                json={
                    "displayName": "Provisioned group",
                    "members": [{"value": resource_id}],
                },
                headers=scim_headers,
            )
            assert group.status_code == 201
            assert group.json()["members"][0]["value"] == resource_id
            deleted = client.delete(
                f"/scim/v2/Users/{resource_id}", headers=scim_headers
            )
            assert deleted.status_code == 204
            with engine.connect() as conn:
                member = conn.execute(
                    text(
                        "SELECT auth_subject_id,active,role FROM members WHERE email=:email"
                    ),
                    {"email": provisioned_email},
                ).one()
            inactive = jwt.encode(
                {
                    "sub": member.auth_subject_id,
                    "org_id": org_id,
                    "iss": "https://p12-test.invalid/auth",
                    "aud": "authenticated",
                    "iat": datetime.now(UTC),
                    "exp": datetime.now(UTC) + timedelta(minutes=5),
                },
                secret,
                algorithm="HS256",
            )
            assert member.active is False and member.role == "viewer"
            assert (
                client.get(
                    "/auth/me", headers={"Authorization": f"Bearer {inactive}"}
                ).status_code
                == 401
            )
    finally:
        app.dependency_overrides.clear()
        get_rate_limiter.cache_clear()
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            )
            conn.execute(
                text("DELETE FROM audit_events WHERE organization_id=:org"),
                {"org": org_id},
            )
            conn.execute(
                text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable")
            )
            conn.execute(
                text("DELETE FROM organizations WHERE id=:org"), {"org": org_id}
            )
        engine.dispose()
