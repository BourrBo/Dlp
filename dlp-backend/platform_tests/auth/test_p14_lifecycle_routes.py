"""P14 lifecycle route authorization and audited hold behavior."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, update

from dlp_platform.auth.roles import ROLE_PERMISSIONS
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.lifecycle.service import (
    create_legal_hold,
    release_legal_hold,
    run_retention_batch,
    save_retention_policy,
)
from dlp_platform.tables import APP_SESSIONS, AUDIT_EVENTS, LEGAL_HOLDS, RETENTION_POLICIES
from platform_tests.auth.conftest import ORG_A, OWNER_ID
from platform_tests.auth.helpers import auth_headers, signed_token


def test_retention_and_hold_routes_are_tenant_scoped_and_audited(auth_client) -> None:
    token_a = signed_token(subject="user-owner-a", organization_id=str(ORG_A))
    token_b = signed_token(
        subject="user-owner-b", organization_id="22222222-2222-4222-8222-222222222222"
    )

    settings = auth_client.get("/organizations/current/retention", headers=auth_headers(token_a))
    assert settings.status_code == 200
    assert {row["category"] for row in settings.json()} == {
        "sessions",
        "scan_records",
        "sso_ephemera",
        "revoked_credentials",
    }

    created = auth_client.post(
        "/organizations/current/legal-holds",
        json={
            "name": "Preservation",
            "reason": "Synthetic test reason",
            "scope_category": "scan_records",
        },
        headers=auth_headers(token_a),
    )
    assert created.status_code == 201
    hold_id = created.json()["hold_id"]
    assert (
        auth_client.get("/organizations/current/legal-holds", headers=auth_headers(token_b)).json()
        == []
    )

    with auth_client.app.state.test_session_factory() as session:
        hold = session.execute(select(LEGAL_HOLDS)).mappings().one()
        assert hold["org_id"] == str(ORG_A)
        events = session.execute(select(AUDIT_EVENTS.c.action)).scalars().all()
        assert "legal_hold.created" in events
        assert "Synthetic test reason" not in str(events)

    viewer = signed_token(subject="user-viewer-a", organization_id=str(ORG_A))
    denied = auth_client.post(
        f"/organizations/current/legal-holds/{hold_id}/release",
        json={"release_reason": "No longer needed"},
        headers=auth_headers(viewer),
    )
    assert denied.status_code == 403


def test_deletion_is_owner_only_and_requires_exact_organization_name(auth_client) -> None:
    admin = signed_token(subject="user-admin-a", organization_id=str(ORG_A))
    assert (
        auth_client.get("/organizations/current/deletion", headers=auth_headers(admin)).status_code
        == 403
    )

    owner = signed_token(subject="user-owner-a", organization_id=str(ORG_A))
    wrong = auth_client.post(
        "/organizations/current/deletion-requests",
        json={"confirmation_name": "wrong"},
        headers=auth_headers(owner),
    )
    assert wrong.status_code == 422


def test_retention_batch_respects_and_then_observes_released_hold(auth_client) -> None:
    now = datetime.now(UTC)
    session_id = uuid4()
    principal = Principal(
        organization_id=ORG_A,
        subject_id="user-owner-a",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=tuple(permission.value for permission in ROLE_PERMISSIONS[Role.OWNER]),
        auth_method=AuthMethod.JWT,
        member_id=OWNER_ID,
        session_id=session_id,
    )
    factory = auth_client.app.state.test_session_factory
    with factory() as session:
        session.execute(
            APP_SESSIONS.insert().values(
                id=str(session_id),
                org_id=str(ORG_A),
                member_id=str(OWNER_ID),
                token_hash="a" * 64,
                auth_method="jwt",
                created_at=now - timedelta(days=50),
                last_seen_at=now - timedelta(days=50),
                expires_at=now - timedelta(days=40),
                revoked_at=now - timedelta(days=40),
            )
        )
        save_retention_policy(
            session, principal, category="sessions", retention_days=30, enabled=True
        )
        session.execute(
            update(RETENTION_POLICIES)
            .where(RETENTION_POLICIES.c.org_id == str(ORG_A))
            .values(effective_at=now - timedelta(days=60))
        )
        hold = create_legal_hold(
            session, principal, name="Hold", reason="Synthetic", scope_category="sessions"
        )
        blocked = run_retention_batch(session, principal, category="sessions")
        assert blocked["deleted_count"] == 0 and blocked["held"] is True
        release_legal_hold(
            session, principal, hold_id=UUID(hold["hold_id"]), release_reason="Released"
        )
        result = run_retention_batch(session, principal, category="sessions")
        assert result["deleted_count"] == 1 and result["held"] is False
