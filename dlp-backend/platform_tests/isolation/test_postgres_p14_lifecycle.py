"""PostgreSQL RLS isolation for P14 tenant-owned lifecycle state."""

import json
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _claims(org_id: str | None, role: str = "owner") -> str:
    claims = {"role": "authenticated", "aud": "authenticated", "app_role": role}
    if org_id is not None:
        claims["org_id"] = org_id
    return json.dumps(claims)


def test_p14_rls_hides_cross_tenant_lifecycle_state_and_rejects_writes() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    member_a, member_b = str(uuid4()), str(uuid4())
    now = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            for org_id, member_id in ((org_a, member_a), (org_b, member_b)):
                conn.execute(
                    text("INSERT INTO organizations (id,name) VALUES (:org,'P14 RLS')"),
                    {"org": org_id},
                )
                conn.execute(
                    text(
                        "INSERT INTO members (id,organization_id,auth_subject_id,role) "
                        "VALUES (:member,:org,:subject,'owner')"
                    ),
                    {"member": member_id, "org": org_id, "subject": f"p14-{member_id}"},
                )
            conn.execute(
                text(
                    "INSERT INTO dlp_retention_policies "
                    "(org_id,category,retention_days,enabled,effective_at,updated_by,created_at,"
                    "updated_at) "
                    "VALUES (:org,'sessions',30,true,:now,:member,:now,:now)"
                ),
                {"org": org_b, "member": member_b, "now": now},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_legal_holds "
                    "(id,org_id,name,reason,scope_category,status,created_by_member_id,created_at) "
                    "VALUES (:id,:org,'P14 hold','synthetic',NULL,'active',:member,:now)"
                ),
                {"id": str(uuid4()), "org": org_b, "member": member_b, "now": now},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_org_deletion_requests "
                    "(org_id,status,requested_by_member_id,requested_at,updated_at) "
                    "VALUES (:org,'requested',:member,:now,:now)"
                ),
                {"org": org_b, "member": member_b, "now": now},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_retention_runs "
                    "(id,org_id,category,status,deleted_count,failure_code,started_at) "
                    "VALUES (:id,:org,'sessions','completed',0,NULL,:now)"
                ),
                {"id": str(uuid4()), "org": org_b, "now": now},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_retention_policies "
                    "(org_id,category,retention_days,enabled,effective_at,updated_by,created_at,"
                    "updated_at) VALUES (:org,'sessions',30,true,:now,:member,:now,:now)"
                ),
                {"org": org_a, "member": member_a, "now": now},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_legal_holds "
                    "(id,org_id,name,reason,scope_category,status,created_by_member_id,created_at) "
                    "VALUES (:id,:org,'P14 A hold','synthetic',NULL,'active',:member,:now)"
                ),
                {"id": str(uuid4()), "org": org_a, "member": member_a, "now": now},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_org_deletion_requests "
                    "(org_id,status,requested_by_member_id,requested_at,updated_at) "
                    "VALUES (:org,'requested',:member,:now,:now)"
                ),
                {"org": org_a, "member": member_a, "now": now},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_retention_runs "
                    "(id,org_id,category,status,deleted_count,failure_code,started_at) "
                    "VALUES (:id,:org,'sessions','completed',0,NULL,:now)"
                ),
                {"id": str(uuid4()), "org": org_a, "now": now},
            )

        with engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims',:claims,true)"),
                {"claims": _claims(org_a)},
            )
            assert (
                conn.execute(text("SELECT count(*) FROM dlp_retention_policies")).scalar_one() == 1
            )
            assert conn.execute(text("SELECT count(*) FROM dlp_legal_holds")).scalar_one() == 1
            assert (
                conn.execute(text("SELECT count(*) FROM dlp_org_deletion_requests")).scalar_one()
                == 1
            )
            assert conn.execute(text("SELECT count(*) FROM dlp_retention_runs")).scalar_one() == 1
            assert (
                conn.execute(
                    text("UPDATE dlp_retention_policies SET retention_days=31 WHERE org_id=:org"),
                    {"org": org_b},
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("UPDATE dlp_retention_policies SET retention_days=31 WHERE org_id=:org"),
                    {"org": org_a},
                ).rowcount
                == 1
            )
            assert (
                conn.execute(
                    text("DELETE FROM dlp_legal_holds WHERE org_id=:org"), {"org": org_b}
                ).rowcount
                == 0
            )
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO dlp_legal_holds "
                        "(id,org_id,name,reason,scope_category,status,created_by_member_id,"
                        "created_at) "
                        "VALUES (:id,:org,'forbidden','synthetic',NULL,'active',:member,:now)"
                    ),
                    {"id": str(uuid4()), "org": org_b, "member": member_b, "now": now},
                )

        with engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims',:claims,true)"),
                {"claims": _claims(org_a, role="analyst")},
            )
            assert conn.execute(text("SELECT count(*) FROM dlp_legal_holds")).scalar_one() == 0
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO dlp_legal_holds "
                        "(id,org_id,name,reason,scope_category,status,"
                        "created_by_member_id,created_at) "
                        "VALUES (:id,:org,'forbidden','synthetic',NULL,'active',:member,:now)"
                    ),
                    {"id": str(uuid4()), "org": org_a, "member": member_a, "now": now},
                )

        with engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims',:claims,true)"),
                {"claims": _claims(None)},
            )
            assert conn.execute(text("SELECT count(*) FROM dlp_legal_holds")).scalar_one() == 0
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM dlp_org_deletion_requests WHERE org_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            conn.execute(
                text("DELETE FROM dlp_retention_runs WHERE org_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            conn.execute(
                text("DELETE FROM dlp_legal_holds WHERE org_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            conn.execute(
                text("DELETE FROM dlp_retention_policies WHERE org_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            conn.execute(
                text("DELETE FROM members WHERE organization_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            conn.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()
