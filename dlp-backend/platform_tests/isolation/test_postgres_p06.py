"""Real PostgreSQL P06 tenant RLS, immutable version and isolation checks."""

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from dlp_platform.contracts.common import (
    ActorType,
    AuthMethod,
    ClassificationLevel,
    FindingStatus,
    Role,
    SeverityLevel,
)
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.policy.exceptions import ExceptionRepository
from dlp_platform.policy.suppressions import DatabaseSuppressor

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _claims(connection, org_id: str | None, app_role: str = "owner") -> None:
    connection.execute(text("SET LOCAL ROLE authenticated"))
    claims = {"role": "authenticated", "aud": "authenticated", "app_role": app_role}
    if org_id is not None:
        claims["org_id"] = org_id
    connection.execute(
        text("SELECT set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def test_p06_postgres_rls_and_immutable_policy_versions() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    member_a, member_b = str(uuid4()), str(uuid4())
    policy_a, policy_b = str(uuid4()), str(uuid4())
    version_a, version_b = str(uuid4()), str(uuid4())
    exception_a, exception_b = str(uuid4()), str(uuid4())
    suppression_a, suppression_b = str(uuid4()), str(uuid4())
    expiry = datetime.now(UTC) + timedelta(days=1)
    try:
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO organizations (id,name) VALUES (:id,:name)"),
                [{"id": org_a, "name": "P06 A"}, {"id": org_b, "name": "P06 B"}],
            )
            conn.execute(
                text(
                    "INSERT INTO members (id,organization_id,auth_subject_id,role) "
                    "VALUES (:id,:org,:sub,'owner')"
                ),
                [
                    {"id": member_a, "org": org_a, "sub": "p06-a"},
                    {"id": member_b, "org": org_b, "sub": "p06-b"},
                ],
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_policies "
                    "(id,org_id,name,enabled,priority,conditions,action,version,created_by) "
                    "VALUES (:id,:org,'P06 policy',true,100,'{}'::jsonb,'block',1,:member)"
                ),
                [
                    {"id": policy_a, "org": org_a, "member": member_a},
                    {"id": policy_b, "org": org_b, "member": member_b},
                ],
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_policy_versions "
                    "(id,policy_id,org_id,version,snapshot,created_by) "
                    "VALUES (:id,:policy,:org,1,'{}'::jsonb,:member)"
                ),
                [
                    {"id": version_a, "policy": policy_a, "org": org_a, "member": member_a},
                    {"id": version_b, "policy": policy_b, "org": org_b, "member": member_b},
                ],
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_exceptions "
                    "(id,org_id,policy_id,scope,reason,approver_id,created_by,updated_by,"
                    "expires_at) "
                    "VALUES (:id,:org,:policy,'{\"channel\":\"api\"}'::jsonb,'test',"
                    ":member,:member,:member,:expires)"
                ),
                [
                    {
                        "id": exception_a,
                        "org": org_a,
                        "policy": policy_a,
                        "member": member_a,
                        "expires": expiry,
                    },
                    {
                        "id": exception_b,
                        "org": org_b,
                        "policy": policy_b,
                        "member": member_b,
                        "expires": expiry,
                    },
                ],
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_suppressions "
                    "(id,org_id,match,reason,created_by,updated_by,expires_at) "
                    "VALUES (:id,:org,'{\"pattern\":\"p06-detector\"}'::jsonb,'test',"
                    ":member,:member,:expires)"
                ),
                [
                    {"id": suppression_a, "org": org_a, "member": member_a, "expires": expiry},
                    {"id": suppression_b, "org": org_b, "member": member_b, "expires": expiry},
                ],
            )
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO dlp_suppressions "
                        "(id,org_id,match,reason,created_by,updated_by,expires_at) "
                        'VALUES (:id,:org,\'{"path":"/x","pattern":"detector"}\'::jsonb,'
                        "'invalid',:member,:member,:expires)"
                    ),
                    {
                        "id": str(uuid4()),
                        "org": org_a,
                        "member": member_a,
                        "expires": expiry,
                    },
                )

        exception_repository = ExceptionRepository(engine)
        before_expiry = exception_repository.active_for_tenant(
            UUID(org_a), expiry - timedelta(microseconds=1)
        )
        at_expiry = exception_repository.active_for_tenant(UUID(org_a), expiry)
        assert [row["id"] for row in before_expiry] == [exception_a]
        assert at_expiry == ()
        principal = Principal(
            organization_id=UUID(org_a),
            subject_id="p06-suppression-test",
            actor_type=ActorType.USER,
            role=Role.OWNER,
            scopes=("scan:request",),
            auth_method=AuthMethod.JWT,
        )
        finding = Finding(
            finding_id=uuid4(),
            data_type="test-secret",
            classification=ClassificationLevel.CONFIDENTIAL,
            severity=SeverityLevel.HIGH,
            confidence=0.99,
            detector="p06-detector",
            masked_evidence="[masked]",
            status=FindingStatus.OPEN,
            first_seen_at=datetime.now(UTC),
        )
        suppressor = DatabaseSuppressor(engine)
        before_suppression_expiry = suppressor.suppress_at(
            (finding,), principal, expiry - timedelta(microseconds=1)
        )
        at_suppression_expiry = suppressor.suppress_at((finding,), principal, expiry)
        assert before_suppression_expiry.findings == ()
        assert before_suppression_expiry.applied_ids == (suppression_a,)
        assert at_suppression_expiry.findings == (finding,)

        with engine.begin() as conn:
            _claims(conn, org_a)
            assert conn.execute(
                text("SELECT id FROM dlp_exceptions ORDER BY id")
            ).scalars().all() == [exception_a]
            assert conn.execute(
                text("SELECT id FROM dlp_suppressions ORDER BY id")
            ).scalars().all() == [suppression_a]
            assert conn.execute(
                text("SELECT id FROM dlp_policy_versions ORDER BY id")
            ).scalars().all() == [version_a]
            assert (
                conn.execute(
                    text("UPDATE dlp_exceptions SET reason='cross-org' WHERE id=:id"),
                    {"id": exception_b},
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("DELETE FROM dlp_suppressions WHERE id=:id"), {"id": suppression_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("DELETE FROM dlp_exceptions WHERE id=:id"), {"id": exception_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("UPDATE dlp_policy_versions SET snapshot='{}'::jsonb WHERE id=:id"),
                    {"id": version_b},
                ).rowcount
                == 0
            )
            assert conn.execute(
                text("UPDATE dlp_policy_versions SET snapshot='{}'::jsonb WHERE id=:id"),
                {"id": version_a},
            ).rowcount == 0
            assert conn.execute(
                text("DELETE FROM dlp_policy_versions WHERE id=:id"), {"id": version_a}
            ).rowcount == 0
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO dlp_suppressions "
                        "(id,org_id,match,reason,created_by,updated_by,expires_at) "
                        "VALUES (:id,:org,'{\"path\":\"/other\"}'::jsonb,'forged',"
                        ":member,:member,now()+interval '1 day')"
                    ),
                    {"id": str(uuid4()), "org": org_b, "member": member_b},
                )

        with engine.begin() as conn:
            _claims(conn, None)
            for table in ("dlp_policy_versions", "dlp_exceptions", "dlp_suppressions"):
                assert conn.execute(text(f"SELECT id FROM {table}")).scalars().all() == []

        with engine.begin() as conn:
            _claims(conn, org_a, app_role="analyst")
            assert conn.execute(text("SELECT id FROM dlp_exceptions")).scalars().all() == [
                exception_a
            ]
            assert (
                conn.execute(
                    text("UPDATE dlp_exceptions SET reason='analyst' WHERE id=:id"),
                    {"id": exception_a},
                ).rowcount
                == 0
            )

        # Immutable trigger is independent from application role and grants.
        with engine.begin() as conn:
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(
                    text("UPDATE dlp_policy_versions SET snapshot='{}'::jsonb WHERE id=:id"),
                    {"id": version_a},
                )
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(
                    text("DELETE FROM dlp_policy_versions WHERE id=:id"), {"id": version_a}
                )
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE dlp_policy_versions DISABLE TRIGGER dlp_policy_versions_immutable"
                )
            )
            conn.execute(
                text("DELETE FROM dlp_suppressions WHERE id IN (:a,:b)"),
                {"a": suppression_a, "b": suppression_b},
            )
            conn.execute(
                text("DELETE FROM dlp_exceptions WHERE id IN (:a,:b)"),
                {"a": exception_a, "b": exception_b},
            )
            conn.execute(
                text("DELETE FROM dlp_policy_versions WHERE id IN (:a,:b)"),
                {"a": version_a, "b": version_b},
            )
            conn.execute(
                text("ALTER TABLE dlp_policy_versions ENABLE TRIGGER dlp_policy_versions_immutable")
            )
            conn.execute(
                text("DELETE FROM dlp_policies WHERE id IN (:a,:b)"), {"a": policy_a, "b": policy_b}
            )
            conn.execute(
                text("DELETE FROM members WHERE id IN (:a,:b)"), {"a": member_a, "b": member_b}
            )
            conn.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()
