"""True PostgreSQL/Supabase RLS checks; never substituted with SQLite."""

import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="P03_TEST_DATABASE_URL is not configured")


def test_authenticated_role_isolation_on_tenant_tables() -> None:
    """Exercise direct SQL under authenticated, with no app WHERE filters."""
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    channel_a, channel_b = str(uuid4()), str(uuid4())
    event_a, event_b = str(uuid4()), str(uuid4())
    key_a, key_b = str(uuid4()), str(uuid4())
    member_a, member_b = str(uuid4()), str(uuid4())
    try:
        # Leave the outer transaction uncommitted so its synthetic fixtures are rolled back.
        with engine.connect() as conn:
            conn.execute(
                text("INSERT INTO organizations (id, name) VALUES (:a, 'A'), (:b, 'B')"),
                {"a": org_a, "b": org_b},
            )
            conn.execute(
                text(
                    "INSERT INTO channels (id, organization_id, channel_type, name) "
                    "VALUES (:ca, :a, 'api', 'A'), (:cb, :b, 'api', 'B')"
                ),
                {"ca": channel_a, "a": org_a, "cb": channel_b, "b": org_b},
            )
            conn.execute(
                text(
                    "INSERT INTO events (id, organization_id, request_id, scan_id, channel, "
                    "decision, reason) VALUES (:ea, :a, :ra, :sa, 'api', 'allow', 'A'), "
                    "(:eb, :b, :rb, :sb, 'api', 'allow', 'B')"
                ),
                {
                    "ea": event_a,
                    "a": org_a,
                    "ra": str(uuid4()),
                    "sa": str(uuid4()),
                    "eb": event_b,
                    "b": org_b,
                    "rb": str(uuid4()),
                    "sb": str(uuid4()),
                },
            )
            conn.execute(
                text(
                    "INSERT INTO members "
                    "(id, organization_id, auth_subject_id, role) "
                    "VALUES (:ma, :a, 'rls-a', 'owner'), (:mb, :b, 'rls-b', 'owner')"
                ),
                {"ma": member_a, "a": org_a, "mb": member_b, "b": org_b},
            )
            # Keys are synthetic and hashes cannot authenticate.
            conn.execute(
                text(
                    "INSERT INTO dlp_api_keys "
                    "(id, org_id, name, prefix, key_hash, scopes, created_by) "
                    "VALUES (:ka, :a, 'A', 'a-prefix', :hash, '[]', :ma), "
                    "(:kb, :b, 'B', 'b-prefix', :hash, '[]', :mb)"
                ),
                {
                    "ka": key_a,
                    "a": org_a,
                    "kb": key_b,
                    "b": org_b,
                    "hash": "0" * 64,
                    "ma": member_a,
                    "mb": member_b,
                },
            )
            claims = json.dumps(
                {
                    "sub": "rls-test",
                    "role": "authenticated",
                    "aud": "authenticated",
                    "org_id": org_a,
                    "app_role": "owner",
                }
            )
            conn.execute(text("SET LOCAL ROLE authenticated"))
            assert conn.execute(text("SELECT id FROM organizations")).scalars().all() == []
            assert conn.execute(text("SELECT current_user")).scalar_one() == "authenticated"
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"), {"claims": claims}
            )
            assert conn.execute(text("SELECT id FROM organizations")).scalars().all() == [org_a]
            assert conn.execute(text("SELECT id FROM channels")).scalars().all() == [channel_a]
            assert conn.execute(text("SELECT id FROM events")).scalars().all() == [event_a]
            assert conn.execute(text("SELECT id FROM members")).scalars().all() == [member_a]
            assert conn.execute(text("SELECT id FROM dlp_api_keys")).scalars().all() == [key_a]
            assert (
                conn.execute(
                    text("SELECT current_setting('request.jwt.claims', true)")
                ).scalar_one()
                == claims
            )
            for table, privilege in (
                ("organizations", "UPDATE"),
                ("organizations", "DELETE"),
                ("channels", "UPDATE"),
                ("channels", "DELETE"),
                ("events", "UPDATE"),
                ("events", "DELETE"),
                ("events", "INSERT"),
                ("dlp_api_keys", "UPDATE"),
                ("dlp_api_keys", "DELETE"),
            ):
                assert conn.execute(
                    text("SELECT has_table_privilege('authenticated', :table, :privilege)"),
                    {"table": f"public.{table}", "privilege": privilege},
                ).scalar_one()
            assert (
                conn.execute(
                    text("UPDATE channels SET name='changed' WHERE id=:id"), {"id": channel_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(text("DELETE FROM channels WHERE id=:id"), {"id": channel_b}).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("UPDATE events SET reason='changed' WHERE id=:id"), {"id": event_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(text("DELETE FROM events WHERE id=:id"), {"id": event_b}).rowcount == 0
            )
            assert (
                conn.execute(
                    text("UPDATE members SET role='admin' WHERE id=:id"), {"id": member_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(text("DELETE FROM members WHERE id=:id"), {"id": member_b}).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("UPDATE organizations SET name='changed' WHERE id=:id"), {"id": org_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(text("DELETE FROM organizations WHERE id=:id"), {"id": org_b}).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("UPDATE dlp_api_keys SET name='changed' WHERE id=:id"), {"id": key_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(text("DELETE FROM dlp_api_keys WHERE id=:id"), {"id": key_b}).rowcount
                == 0
            )
            with pytest.raises(DBAPIError) as denied, conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO events (id, organization_id, request_id, scan_id, channel, "
                        "decision, reason) "
                        "VALUES (:id, :org, :req, :scan, 'api', 'allow', 'test')"
                    ),
                    {
                        "id": str(uuid4()),
                        "org": org_a,
                        "req": str(uuid4()),
                        "scan": str(uuid4()),
                    },
                )
            assert "row-level security policy" in str(denied.value.orig).lower()
            # Verify that zero-row cross-tenant UPDATE/DELETE did not mutate or remove rows.
            conn.execute(text("RESET ROLE"))
            assert (
                conn.execute(
                    text("SELECT name FROM channels WHERE id=:id"), {"id": channel_b}
                ).scalar_one()
                == "B"
            )
            assert (
                conn.execute(
                    text("SELECT reason FROM events WHERE id=:id"), {"id": event_b}
                ).scalar_one()
                == "B"
            )
            assert (
                conn.execute(
                    text("SELECT role FROM members WHERE id=:id"), {"id": member_b}
                ).scalar_one()
                == "owner"
            )
            assert (
                conn.execute(
                    text("SELECT id FROM dlp_api_keys WHERE id=:id"), {"id": key_b}
                ).scalar_one()
                == key_b
            )
    finally:
        engine.dispose()


def test_tenant_context_is_transaction_local() -> None:
    """SET LOCAL ROLE and request claims must not leak to the next transaction."""
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    try:
        with engine.begin() as conn:
            # Connection checkout starts as the service/database login role.
            assert conn.execute(text("SELECT current_user")).scalar_one() == "postgres"
            assert conn.execute(
                text("SELECT current_setting('request.jwt.claims', true)")
            ).scalar_one_or_none() in (None, "")
            conn.execute(text("SET LOCAL ROLE authenticated"))
            assert conn.execute(text("SELECT current_user")).scalar_one() == "authenticated"
            conn.execute(
                text("SELECT set_config('request.jwt.claims', '{\"org_id\":\"org-a\"}', true)")
            )
        with engine.begin() as conn:
            assert conn.execute(text("SELECT current_user")).scalar_one() == "postgres"
            assert conn.execute(
                text("SELECT current_setting('request.jwt.claims', true)")
            ).scalar_one_or_none() in (None, "")
    finally:
        engine.dispose()
