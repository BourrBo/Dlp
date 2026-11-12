"""Real PostgreSQL RLS tests for P13 session, membership, and IP records."""

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _claims(org_id: str | None, subject: str, app_role: str = "viewer") -> str:
    claims: dict[str, str] = {
        "role": "authenticated",
        "aud": "authenticated",
        "sub": subject,
        "app_role": app_role,
    }
    if org_id is not None:
        claims["org_id"] = org_id
    return json.dumps(claims)


def test_p13_rls_limits_sessions_and_allowlists_and_discloses_only_own_memberships() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    member_a, member_b, member_other = str(uuid4()), str(uuid4()), str(uuid4())
    session_a, session_b, session_other = str(uuid4()), str(uuid4()), str(uuid4())
    entry_a, entry_b = str(uuid4()), str(uuid4())
    subject = f"p13-user-{uuid4()}"
    now = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            for org_id in (org_a, org_b):
                conn.execute(
                    text("INSERT INTO organizations (id,name) VALUES (:id,'P13 RLS test')"),
                    {"id": org_id},
                )
            for member_id, org_id, member_subject, role in (
                (member_a, org_a, subject, "viewer"),
                (member_b, org_b, subject, "admin"),
                (member_other, org_b, f"other-{uuid4()}", "owner"),
            ):
                conn.execute(
                    text(
                        "INSERT INTO members "
                        "(id,organization_id,auth_subject_id,role,email) "
                        "VALUES (:id,:org,:subject,:role,:email)"
                    ),
                    {
                        "id": member_id,
                        "org": org_id,
                        "subject": member_subject,
                        "role": role,
                        "email": f"{member_id}@test.invalid",
                    },
                )
            for session_id, member_id, org_id in (
                (session_a, member_a, org_a),
                (session_b, member_b, org_b),
                (session_other, member_other, org_b),
            ):
                conn.execute(
                    text(
                        "INSERT INTO dlp_app_sessions "
                        "(id,org_id,member_id,token_hash,auth_method,created_at,last_seen_at,"
                        "expires_at) "
                        "VALUES (:id,:org,:member,:hash,'jwt',:now,:now,:expires)"
                    ),
                    {
                        "id": session_id,
                        "org": org_id,
                        "member": member_id,
                        "hash": uuid4().hex * 2,
                        "now": now,
                        "expires": now + timedelta(minutes=5),
                    },
                )
            for org_id, member_id in ((org_a, member_a), (org_b, member_b)):
                conn.execute(
                    text(
                        "INSERT INTO dlp_ip_allowlist_settings "
                        "(org_id,enabled,updated_by,updated_at) VALUES (:org,true,:member,:now)"
                    ),
                    {"org": org_id, "member": member_id, "now": now},
                )
            for entry_id, org_id, member_id, network in (
                (entry_a, org_a, member_a, "192.0.2.0/24"),
                (entry_b, org_b, member_b, "198.51.100.0/24"),
            ):
                conn.execute(
                    text(
                        "INSERT INTO dlp_ip_allowlist_entries "
                        "(id,org_id,network,label,created_by,created_at) "
                        "VALUES (:id,:org,CAST(:network AS cidr),'office',:member,:now)"
                    ),
                    {
                        "id": entry_id,
                        "org": org_id,
                        "network": network,
                        "member": member_id,
                        "now": now,
                    },
                )

        with engine.connect() as conn:
            transaction = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": _claims(org_a, subject)},
            )
            own_sessions = conn.execute(
                text("SELECT id FROM dlp_app_sessions ORDER BY id")
            ).scalars().all()
            assert own_sessions == [session_a]
            assert (
                conn.execute(
                    text("UPDATE dlp_app_sessions SET revoked_at=now() WHERE id=:id"),
                    {"id": session_other},
                ).rowcount
                == 0
            )
            memberships = conn.execute(
                text("SELECT id FROM members WHERE auth_subject_id=:subject"),
                {"subject": subject},
            ).scalars().all()
            assert set(memberships) == {member_a, member_b}
            orgs = conn.execute(
                text("SELECT id FROM organizations WHERE id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            ).scalars().all()
            assert set(orgs) == {org_a, org_b}
            assert conn.execute(
                text("SELECT id FROM members WHERE id=:id"), {"id": member_other}
            ).first() is None
            transaction.rollback()

            transaction = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": _claims(org_a, subject, "admin")},
            )
            visible_entries = conn.execute(
                text("SELECT id FROM dlp_ip_allowlist_entries ORDER BY id")
            ).scalars().all()
            assert visible_entries == [entry_a]
            assert (
                conn.execute(
                    text("DELETE FROM dlp_ip_allowlist_entries WHERE id=:id"),
                    {"id": entry_b},
                ).rowcount
                == 0
            )
            transaction.rollback()

            transaction = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": _claims(None, subject, "owner")},
            )
            assert conn.execute(text("SELECT id FROM dlp_app_sessions")).all() == []
            assert conn.execute(text("SELECT id FROM dlp_ip_allowlist_entries")).all() == []
            transaction.rollback()
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM dlp_ip_allowlist_settings WHERE org_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            conn.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
        engine.dispose()
