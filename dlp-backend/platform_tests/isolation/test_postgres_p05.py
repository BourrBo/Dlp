"""Real PostgreSQL RLS isolation for the P05 policy and destination tables."""

import json
import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)

ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")
MEMBER_A = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
MEMBER_B = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
POLICY_A = "55555555-5555-4555-8555-555555555555"
POLICY_B = "66666666-6666-4666-8666-666666666666"
DEST_A = "77777777-7777-4777-8777-777777777777"
DEST_B = "88888888-8888-4888-8888-888888888888"


def set_tenant(connection, organization_id: UUID | None, *, app_role: str = "owner") -> None:
    connection.execute(text("SET LOCAL ROLE authenticated"))
    claims = {"role": "authenticated", "aud": "authenticated", "app_role": app_role}
    if organization_id is not None:
        claims["org_id"] = str(organization_id)
    connection.execute(
        text("SELECT set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def test_postgres_policy_and_destination_rls_and_transaction_local_claims() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    policy_a, policy_b, dest_a, dest_b = POLICY_A, POLICY_B, DEST_A, DEST_B
    try:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM dlp_destinations WHERE id IN (:a,:b)"), {"a": dest_a, "b": dest_b}
            )
            conn.execute(
                text(
                    "INSERT INTO organizations (id,name) VALUES (:id,:name) ON CONFLICT DO NOTHING"
                ),
                [{"id": str(ORG_A), "name": "P05 A"}, {"id": str(ORG_B), "name": "P05 B"}],
            )
            conn.execute(
                text(
                    "INSERT INTO members (id,organization_id,auth_subject_id,role) "
                    "VALUES (:id,:org,:sub,'owner') ON CONFLICT DO NOTHING"
                ),
                [
                    {"id": str(MEMBER_A), "org": str(ORG_A), "sub": "p05-a"},
                    {"id": str(MEMBER_B), "org": str(ORG_B), "sub": "p05-b"},
                ],
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_policies "
                    "(id,org_id,name,enabled,priority,conditions,action,version,created_by) "
                    "VALUES (:id,:org,:name,true,100,'{}'::jsonb,'block',1,:member) "
                    "ON CONFLICT DO NOTHING"
                ),
                [
                    {
                        "id": policy_a,
                        "org": str(ORG_A),
                        "name": "A policy",
                        "member": str(MEMBER_A),
                    },
                    {
                        "id": policy_b,
                        "org": str(ORG_B),
                        "name": "B policy",
                        "member": str(MEMBER_B),
                    },
                ],
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_destinations (id,org_id,class,kind,pattern) "
                    "VALUES (:id,:org,'public','domain',:pattern) ON CONFLICT DO NOTHING"
                ),
                [
                    {"id": dest_a, "org": str(ORG_A), "pattern": "a-p05.example"},
                    {"id": dest_b, "org": str(ORG_B), "pattern": "b-p05.example"},
                ],
            )

        with engine.begin() as conn:
            set_tenant(conn, ORG_A)
            assert conn.execute(
                text("SELECT id FROM dlp_policies WHERE id IN (:a,:b) ORDER BY id"),
                {"a": policy_a, "b": policy_b},
            ).scalars().all() == [policy_a]
            assert conn.execute(
                text("SELECT id FROM dlp_destinations ORDER BY id")
            ).scalars().all() == [dest_a]
            assert (
                conn.execute(
                    text("UPDATE dlp_policies SET name='cross tenant' WHERE id=:id"),
                    {"id": policy_b},
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("DELETE FROM dlp_destinations WHERE id=:id"), {"id": dest_b}
                ).rowcount
                == 0
            )
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO dlp_policies "
                        "(id,org_id,name,conditions,action,created_by) "
                        "VALUES (:id,:org,'forged','{}'::jsonb,'block',:member)"
                    ),
                    {"id": str(uuid4()), "org": str(ORG_B), "member": str(MEMBER_B)},
                )

        with engine.begin() as conn:
            set_tenant(conn, None)
            assert conn.execute(text("SELECT id FROM dlp_policies")).scalars().all() == []
            assert conn.execute(text("SELECT id FROM dlp_destinations")).scalars().all() == []

        with engine.begin() as conn:
            set_tenant(conn, ORG_A, app_role="analyst")
            assert conn.execute(
                text("SELECT id FROM dlp_policies WHERE id IN (:a,:b)"),
                {"a": policy_a, "b": policy_b},
            ).scalars().all() == [policy_a]
            assert (
                conn.execute(
                    text("UPDATE dlp_policies SET name='unauthorized' WHERE id=:id"),
                    {"id": policy_a},
                ).rowcount
                == 0
            )

        # SET LOCAL ROLE and claims expire at transaction end; the next transaction
        # must supply tenant context again and cannot inherit the prior organization's claims.
        with engine.begin() as conn:
            assert conn.execute(text("SELECT current_user")).scalar_one() != "authenticated"
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(text("SELECT set_config('request.jwt.claims', '{}', true)"))
            assert conn.execute(text("SELECT id FROM dlp_policies")).scalars().all() == []
    finally:
        engine.dispose()
