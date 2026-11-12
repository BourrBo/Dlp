"""PostgreSQL-backed P14 retention, race, deletion, and export acceptance tests."""

import hashlib
import json
import os
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.orm import Session
from platform_tests.auth.helpers import auth_headers, signed_token

from dlp_platform.auth.roles import ROLE_PERMISSIONS
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.lifecycle.adapters import clear_adapters, register_adapter
from dlp_platform.lifecycle.service import (
    LifecycleError,
    build_subject_export,
    confirm_organization_deletion,
    create_legal_hold,
    execute_organization_deletion,
    record_subject_export,
    release_legal_hold,
    request_organization_deletion,
    retention_settings,
    run_retention_batch,
    save_retention_policy,
)
from dlp_platform.main import app
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.tables import (
    ACTIONS,
    API_KEYS,
    APP_SESSIONS,
    APPROVALS,
    AUDIT_EVENTS,
    EXCEPTIONS,
    LEGAL_HOLDS,
    ORG_DELETION_REQUESTS,
    ORGANIZATIONS,
    POLICIES,
    POLICY_VERSIONS,
    RETENTION_POLICIES,
    RETENTION_RUNS,
    SCIM_CREDENTIALS,
    SCIM_GROUP_MEMBERS,
    SCIM_GROUPS,
    SCIM_USERS,
    SSO_CONFIGS,
    SSO_IDENTITIES,
    SSO_REPLAYS,
    SSO_TRANSACTIONS,
    SUPPRESSIONS,
    VAULT_SECRETS,
)

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _principal(org_id: UUID, member_id: UUID, role: Role = Role.OWNER) -> Principal:
    return Principal(
        organization_id=org_id,
        subject_id=f"p14-{member_id}",
        actor_type=ActorType.USER,
        role=role,
        scopes=tuple(item.value for item in ROLE_PERMISSIONS[role]),
        auth_method=AuthMethod.JWT,
        member_id=member_id,
    )


def _seed_org(
    session: Session,
    *,
    org_id: UUID | None = None,
    member_id: UUID | None = None,
    subject: str = "p14-user",
) -> tuple[UUID, UUID]:
    org_id, member_id = org_id or uuid4(), member_id or uuid4()
    now = datetime.now(UTC)
    session.execute(
        ORGANIZATIONS.insert().values(
            id=str(org_id),
            name=f"P14 acceptance {org_id.hex[:8]}",
            settings_json={},
            created_at=now,
            updated_at=now,
        )
    )
    session.execute(
        text(
            "INSERT INTO members (id,organization_id,auth_subject_id,role,email,active,created_at) "
            "VALUES (:id,:org,:subject,'owner',NULL,true,:now)"
        ),
        {"id": str(member_id), "org": str(org_id), "subject": subject, "now": now},
    )
    session.commit()
    return org_id, member_id


def _expired_session(org_id: UUID, member_id: UUID, *, expired: bool) -> dict[str, object]:
    now = datetime.now(UTC)
    expires = now - timedelta(days=60) if expired else now + timedelta(days=60)
    return {
        "id": str(uuid4()),
        "org_id": str(org_id),
        "member_id": str(member_id),
        "token_hash": uuid4().hex * 2,
        "auth_method": "jwt",
        "created_at": expires - timedelta(days=10),
        "last_seen_at": expires - timedelta(days=5),
        "expires_at": expires,
        "revoked_at": None,
    }


def test_postgres_retention_is_held_bounded_idempotent_and_tenant_scoped() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_size=8)
    org_a, member_a = uuid4(), uuid4()
    org_b, member_b = uuid4(), uuid4()
    now = datetime.now(UTC)
    principal_a, principal_b = _principal(org_a, member_a), _principal(org_b, member_b)
    try:
        with Session(engine) as session:
            for org_id, member_id in ((org_a, member_a), (org_b, member_b)):
                _seed_org(
                    session,
                    org_id=org_id,
                    member_id=member_id,
                    subject=f"p14-{org_id}",
                )
            for principal in (principal_a, principal_b):
                save_retention_policy(
                    session,
                    principal,
                    category="sessions",
                    retention_days=30,
                    enabled=True,
                )
                session.execute(
                    update(RETENTION_POLICIES)
                    .where(RETENTION_POLICIES.c.org_id == str(principal.organization_id))
                    .values(effective_at=now - timedelta(days=90))
                )
                for _ in range(7):
                    session.execute(
                        APP_SESSIONS.insert().values(
                            **_expired_session(
                                principal.organization_id, principal.member_id, expired=True
                            )
                        )
                    )
                session.execute(
                    APP_SESSIONS.insert().values(
                        **_expired_session(
                            principal.organization_id, principal.member_id, expired=False
                        )
                    )
                )
            session.commit()

            hold_b = create_legal_hold(
                session,
                principal_b,
                name="Other tenant hold",
                reason="Synthetic",
                scope_category="sessions",
            )
            held = create_legal_hold(
                session,
                principal_a,
                name="Retention hold",
                reason="Synthetic",
                scope_category="sessions",
            )
            blocked = run_retention_batch(session, principal_a, category="sessions", limit=3)
            assert blocked["held"] is True and blocked["deleted_count"] == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(APP_SESSIONS)
                    .where(APP_SESSIONS.c.org_id == str(org_a))
                )
                == 8
            )

            release_legal_hold(
                session,
                principal_b,
                hold_id=UUID(str(hold_b["hold_id"])),
                release_reason="Synthetic release",
            )
            release_legal_hold(
                session,
                principal_a,
                hold_id=UUID(str(held["hold_id"])),
                release_reason="Synthetic release",
            )

            first = run_retention_batch(session, principal_a, category="sessions", limit=3)
            second = run_retention_batch(session, principal_a, category="sessions", limit=3)
            third = run_retention_batch(session, principal_a, category="sessions", limit=3)
            repeated = run_retention_batch(session, principal_a, category="sessions", limit=3)
            assert [first["deleted_count"], second["deleted_count"], third["deleted_count"]] == [
                3,
                3,
                1,
            ]
            assert repeated["deleted_count"] == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(APP_SESSIONS)
                    .where(APP_SESSIONS.c.org_id == str(org_a))
                )
                == 1
            )

            # A hold in tenant B does not suppress tenant A's eligible cleanup.
            session.execute(
                update(LEGAL_HOLDS)
                .where(LEGAL_HOLDS.c.id == hold_b["hold_id"])
                .values(status="active", released_by_member_id=None, released_at=None)
            )
            session.execute(
                APP_SESSIONS.insert().values(**_expired_session(org_a, member_a, expired=True))
            )
            session.commit()
            unprotected = run_retention_batch(session, principal_a, category="sessions", limit=1)
            assert unprotected["deleted_count"] == 1 and unprotected["held"] is False
            remaining_a = session.scalar(
                select(func.count())
                .select_from(APP_SESSIONS)
                .where(APP_SESSIONS.c.org_id == str(org_a))
            )
            remaining_b = session.scalar(
                select(func.count())
                .select_from(APP_SESSIONS)
                .where(APP_SESSIONS.c.org_id == str(org_b))
            )
            assert remaining_a == 1
            assert remaining_b == 8
            audited_actions = set(
                session.execute(
                    select(AUDIT_EVENTS.c.action).where(
                        AUDIT_EVENTS.c.organization_id == str(org_a)
                    )
                ).scalars()
            )
            assert "retention.policy_updated" in audited_actions
            assert "retention.batch_completed" in audited_actions
    finally:
        engine.dispose()


def test_postgres_concurrent_retention_workers_do_not_double_process() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_size=4)
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_org(session)
            principal = _principal(org_id, member_id)
            now = datetime.now(UTC)
            save_retention_policy(
                session, principal, category="sessions", retention_days=30, enabled=True
            )
            session.execute(
                update(RETENTION_POLICIES)
                .where(RETENTION_POLICIES.c.org_id == str(org_id))
                .values(effective_at=now - timedelta(days=90))
            )
            for _ in range(12):
                session.execute(
                    APP_SESSIONS.insert().values(
                        **_expired_session(org_id, member_id, expired=True)
                    )
                )
            session.commit()

        barrier = Barrier(2)

        def worker() -> int:
            with Session(engine) as session:
                barrier.wait(timeout=10)
                return int(
                    run_retention_batch(session, principal, category="sessions", limit=12)[
                        "deleted_count"
                    ]
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            deleted = list(executor.map(lambda _: worker(), range(2)))
        assert sum(deleted) == 12
        with Session(engine) as session:
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(APP_SESSIONS)
                    .where(APP_SESSIONS.c.org_id == str(org_id))
                )
                == 0
            )
            runs = session.execute(
                text(
                    "SELECT status, deleted_count FROM dlp_retention_runs "
                    "WHERE org_id=:org ORDER BY started_at"
                ),
                {"org": str(org_id)},
            ).all()
            assert sum(row.deleted_count for row in runs) == 12
            assert all(row.status == "completed" for row in runs)
    finally:
        engine.dispose()


def test_postgres_retention_and_hold_creation_race_is_serialized() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_size=4)
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_org(session)
            principal = _principal(org_id, member_id)
            now = datetime.now(UTC)
            save_retention_policy(
                session, principal, category="sessions", retention_days=30, enabled=True
            )
            session.execute(
                update(RETENTION_POLICIES)
                .where(RETENTION_POLICIES.c.org_id == str(org_id))
                .values(effective_at=now - timedelta(days=90))
            )
            session.execute(
                APP_SESSIONS.insert().values(**_expired_session(org_id, member_id, expired=True))
            )
            session.commit()

        barrier = Barrier(2)

        def retention_worker() -> dict[str, object]:
            with Session(engine) as session:
                barrier.wait(timeout=10)
                return run_retention_batch(session, principal, category="sessions", limit=1)

        def hold_worker() -> dict[str, object]:
            with Session(engine) as session:
                barrier.wait(timeout=10)
                return create_legal_hold(
                    session,
                    principal,
                    name="Concurrent hold",
                    reason="Synthetic",
                    scope_category="sessions",
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            cleanup_future = executor.submit(retention_worker)
            hold_future = executor.submit(hold_worker)
            cleanup, hold = cleanup_future.result(), hold_future.result()

        with Session(engine) as session:
            remaining = session.scalar(
                select(func.count())
                .select_from(APP_SESSIONS)
                .where(APP_SESSIONS.c.org_id == str(org_id))
            )
            assert hold["status"] == "active"
            assert cleanup["deleted_count"] in {0, 1}
            assert remaining == 1 - cleanup["deleted_count"]
            # Once the hold transaction has committed, every subsequent run is blocked.
            next_batch = run_retention_batch(session, principal, category="sessions", limit=1)
            assert next_batch["held"] is True and next_batch["deleted_count"] == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(APP_SESSIONS)
                    .where(APP_SESSIONS.c.org_id == str(org_id))
                )
                == remaining
            )
    finally:
        engine.dispose()


def test_postgres_retention_failure_is_recorded_and_retry_succeeds(monkeypatch) -> None:
    assert DATABASE_URL is not None
    from dlp_platform.lifecycle import service

    engine = create_engine(DATABASE_URL)
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_org(session)
            principal = _principal(org_id, member_id)
            now = datetime.now(UTC)
            save_retention_policy(
                session, principal, category="sessions", retention_days=30, enabled=True
            )
            session.execute(
                update(RETENTION_POLICIES)
                .where(RETENTION_POLICIES.c.org_id == str(org_id))
                .values(effective_at=now - timedelta(days=90))
            )
            session.execute(
                APP_SESSIONS.insert().values(**_expired_session(org_id, member_id, expired=True))
            )
            session.commit()

            original_delete = service._batch_delete
            calls = 0

            def fail_first_delete(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise SQLAlchemyError("synthetic deletion failure")
                return original_delete(*args, **kwargs)

            monkeypatch.setattr(service, "_batch_delete", fail_first_delete)
            with pytest.raises(LifecycleError, match="safely retried"):
                run_retention_batch(session, principal, category="sessions", limit=1)
            failed_run = session.execute(
                text(
                    "SELECT status,failure_code FROM dlp_retention_runs "
                    "WHERE org_id=:org ORDER BY started_at DESC LIMIT 1"
                ),
                {"org": str(org_id)},
            ).one()
            assert failed_run.status == "failed"
            assert failed_run.failure_code == "retention_batch_failed"
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(APP_SESSIONS)
                    .where(APP_SESSIONS.c.org_id == str(org_id))
                )
                == 1
            )

            monkeypatch.setattr(service, "_batch_delete", original_delete)
            retried = run_retention_batch(session, principal, category="sessions", limit=1)
            assert retried["status"] == "completed" and retried["deleted_count"] == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(APP_SESSIONS)
                    .where(APP_SESSIONS.c.org_id == str(org_id))
                )
                == 0
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(AUDIT_EVENTS)
                    .where(
                        AUDIT_EVENTS.c.organization_id == str(org_id),
                        AUDIT_EVENTS.c.action == "retention.batch_failed",
                    )
                )
                == 1
            )
    finally:
        engine.dispose()


def test_postgres_cross_tenant_lifecycle_ids_and_unauthorized_roles_are_denied() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    try:
        with Session(engine) as session:
            org_a, member_a = _seed_org(session, subject="p14-idor-shared")
            org_b, member_b = _seed_org(session, subject="p14-idor-shared")
            owner_a = _principal(org_a, member_a)
            viewer_a = _principal(org_a, member_a, role=Role.VIEWER)
            owner_b = _principal(org_b, member_b)
            hold_b = create_legal_hold(
                session,
                owner_b,
                name="Org B hold",
                reason="Synthetic",
                scope_category=None,
            )
            before_b = retention_settings(session, org_b)
            with pytest.raises(HTTPException) as denied_create:
                create_legal_hold(
                    session,
                    viewer_a,
                    name="Unauthorized hold",
                    reason="Synthetic",
                    scope_category=None,
                )
            assert denied_create.value.status_code == 403
            with pytest.raises(HTTPException) as denied_delete:
                request_organization_deletion(
                    session,
                    viewer_a,
                    confirmation_name="Org A",
                    actual_name="Org A",
                )
            assert denied_delete.value.status_code == 403
            with pytest.raises(LookupError):
                release_legal_hold(
                    session,
                    owner_a,
                    hold_id=UUID(str(hold_b["hold_id"])),
                    release_reason="IDOR attempt",
                )
            with pytest.raises(LookupError):
                build_subject_export(
                    session,
                    organization_id=org_a,
                    organization_name="Org A",
                    member_id=member_b,
                    subject_id="p14-idor-shared",
                )
            assert retention_settings(session, org_b) == before_b
            assert (
                session.scalar(
                    select(LEGAL_HOLDS.c.status).where(LEGAL_HOLDS.c.id == hold_b["hold_id"])
                )
                == "active"
            )
            assert (
                session.scalar(
                    select(ORG_DELETION_REQUESTS.c.status).where(
                        ORG_DELETION_REQUESTS.c.org_id == str(org_b)
                    )
                )
                is None
            )
    finally:
        engine.dispose()


def test_postgres_lifecycle_http_routes_authenticate_scoped_sessions_and_exports(
    monkeypatch,
) -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_size=8)
    owner_subject = f"p14-http-owner-{uuid4()}"
    admin_subject = f"p14-http-admin-{uuid4()}"
    viewer_subject = f"p14-http-viewer-{uuid4()}"
    org_a = member_owner = member_admin = member_viewer = None
    org_b = member_b = None
    token_secret = "synthetic-api-key-secret-value-that-is-long-enough-0001"
    api_prefix = uuid4().hex[:12]
    api_token = f"dlp_{api_prefix}.{token_secret}"

    try:
        with Session(engine) as session:
            org_a, member_owner = _seed_org(session, subject=owner_subject)
            org_b, member_b = _seed_org(session, subject=owner_subject)
            member_admin, member_viewer = uuid4(), uuid4()
            now = datetime.now(UTC)
            for member_id, subject, role in (
                (member_admin, admin_subject, "admin"),
                (member_viewer, viewer_subject, "viewer"),
            ):
                session.execute(
                    text(
                        "INSERT INTO members "
                        "(id,organization_id,auth_subject_id,role,email,active,created_at) "
                        "VALUES (:id,:org,:subject,:role,NULL,true,:now)"
                    ),
                    {
                        "id": str(member_id),
                        "org": str(org_a),
                        "subject": subject,
                        "role": role,
                        "now": now,
                    },
                )
            session.execute(
                API_KEYS.insert().values(
                    id=str(uuid4()),
                    org_id=str(org_a),
                    name="synthetic lifecycle API key",
                    prefix=api_prefix,
                    key_hash=hashlib.sha256(api_token.encode()).hexdigest(),
                    scopes=["data_lifecycle:write", "subject_data:export"],
                    created_by=str(member_owner),
                    created_at=now,
                )
            )
            session.commit()
            hold_b = create_legal_hold(
                session,
                _principal(org_b, member_b),
                name="Org B hold",
                reason="Synthetic",
                scope_category=None,
            )

        monkeypatch.setenv(
            "SUPABASE_JWT_SECRET",
            "synthetic-test-signing-secret-never-use-outside-tests-0123456789",
        )
        monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
        monkeypatch.setenv("JWT_ISSUER", "https://synthetic-project.supabase.co/auth/v1")
        monkeypatch.setenv("JWT_AUDIENCE", "authenticated")
        monkeypatch.setenv("JWT_LEEWAY_SECONDS", "0")
        monkeypatch.setenv("RATE_LIMIT_PER_KEY", "1000")
        monkeypatch.setenv("RATE_LIMIT_PER_ORG", "10000")
        get_rate_limiter.cache_clear()

        def override_session() -> Generator[Session, None, None]:
            with Session(engine) as session:
                yield session

        prior_override = app.dependency_overrides.get(get_session)
        app.dependency_overrides[get_session] = override_session
        try:
            owner = auth_headers(signed_token(owner_subject, org_a))
            admin = auth_headers(signed_token(admin_subject, org_a))
            viewer = auth_headers(signed_token(viewer_subject, org_a))
            with TestClient(app) as client:
                hold_response = client.post(
                    "/organizations/current/legal-holds",
                    headers={**owner, "User-Agent": "Bearer P14_HTTP_SESSION_SENTINEL"},
                    json={"name": "HTTP hold", "reason": "Synthetic", "scope_category": "sessions"},
                )
                assert hold_response.status_code == 201
                hold_id = hold_response.json()["hold_id"]

                denied = client.post(
                    "/organizations/current/legal-holds",
                    headers=viewer,
                    json={"name": "Denied", "reason": "Synthetic", "scope_category": None},
                )
                assert denied.status_code == 403
                denied_delete = client.post(
                    "/organizations/current/deletion-requests",
                    headers=admin,
                    json={"confirmation_name": "anything"},
                )
                assert denied_delete.status_code == 403
                wrong_name = client.post(
                    "/organizations/current/deletion-requests",
                    headers=owner,
                    json={"confirmation_name": "incorrect"},
                )
                assert wrong_name.status_code == 422

                cross_release = client.post(
                    f"/organizations/current/legal-holds/{hold_b['hold_id']}/release",
                    headers=owner,
                    json={"release_reason": "IDOR"},
                )
                assert cross_release.status_code == 404
                cross_export = client.post(
                    f"/organizations/current/subjects/{member_b}/export", headers=admin
                )
                assert cross_export.status_code == 404
                nonexistent_export = client.post(
                    f"/organizations/current/subjects/{uuid4()}/export", headers=admin
                )
                assert nonexistent_export.status_code == 404
                unauthorized_export = client.post(
                    f"/organizations/current/subjects/{member_owner}/export", headers=viewer
                )
                assert unauthorized_export.status_code == 403
                forged_org = client.post(
                    "/organizations/current/legal-holds",
                    headers=owner,
                    json={
                        "name": "Forged",
                        "reason": "Synthetic",
                        "scope_category": None,
                        "org_id": str(org_b),
                    },
                )
                assert forged_org.status_code == 422

                own_export = client.post("/identity/export", headers=owner)
                assert own_export.status_code == 200
                exported = own_export.json()
                exported_json = json.dumps(exported, sort_keys=True)
                assert exported["subject"]["subject_id"] == owner_subject
                assert "P14_HTTP_SESSION_SENTINEL" not in exported_json
                assert "token_hash" not in exported["p2_data"]["sessions"][0]
                denied_release = client.post(
                    f"/organizations/current/legal-holds/{hold_id}/release",
                    headers=viewer,
                    json={"release_reason": "Unauthorized release attempt"},
                )
                assert denied_release.status_code == 403
                released = client.post(
                    f"/organizations/current/legal-holds/{hold_id}/release",
                    headers=owner,
                    json={"release_reason": "Synthetic HTTP release"},
                )
                assert released.status_code == 200
                assert released.json()["status"] == "released"
                assert released.json()["release_reason"] == "Synthetic HTTP release"
                with Session(engine) as session:
                    session.execute(
                        text("UPDATE members SET active=false WHERE id=:id"),
                        {"id": str(member_viewer)},
                    )
                    session.commit()
                admin_export = client.post(
                    f"/organizations/current/subjects/{member_viewer}/export", headers=admin
                )
                assert admin_export.status_code == 200
                assert admin_export.json()["subject"]["subject_id"] == viewer_subject
                assert admin_export.json()["subject"]["active"] is False

                api_key_attempt = client.post(
                    "/organizations/current/legal-holds",
                    headers={"Authorization": f"Bearer {api_token}"},
                    json={"name": "Service actor", "reason": "Synthetic", "scope_category": None},
                )
                assert api_key_attempt.status_code == 403
                ambiguous_subject = client.get(
                    "/organizations/current/legal-holds",
                    headers=auth_headers(signed_token(owner_subject, include_org=False)),
                )
                assert ambiguous_subject.status_code == 401
                audit_response = client.get("/audit/events", headers=owner)
                assert audit_response.status_code == 200
                assert str(hold_b["hold_id"]) not in audit_response.text

            with Session(engine) as session:
                hold_row = session.execute(
                    select(LEGAL_HOLDS.c.status).where(LEGAL_HOLDS.c.id == hold_id)
                ).scalar_one()
                assert hold_row == "released"
                assert (
                    session.scalar(
                        select(func.count())
                        .select_from(LEGAL_HOLDS)
                        .where(LEGAL_HOLDS.c.org_id == str(org_a))
                    )
                    == 1
                )
                audit_rows = session.execute(
                    select(
                        AUDIT_EVENTS.c.organization_id,
                        AUDIT_EVENTS.c.action,
                        AUDIT_EVENTS.c.correlation_id,
                        AUDIT_EVENTS.c.event_metadata,
                        AUDIT_EVENTS.c.actor_id,
                        AUDIT_EVENTS.c.outcome,
                        AUDIT_EVENTS.c.user_agent,
                    ).where(AUDIT_EVENTS.c.organization_id == str(org_a))
                ).all()
                actions = {row.action for row in audit_rows}
                assert "legal_hold.created" in actions
                assert "legal_hold.released" in actions
                assert "auth.authorization_denied" in actions
                assert "subject.export_completed" in actions
                assert all("P14_HTTP_SESSION_SENTINEL" not in str(row) for row in audit_rows)
                created_event = next(
                    row for row in audit_rows if row.action == "legal_hold.created"
                )
                released_event = next(
                    row for row in audit_rows if row.action == "legal_hold.released"
                )
                denied_event = next(
                    row for row in audit_rows if row.action == "auth.authorization_denied"
                )
                export_event = next(
                    row for row in audit_rows if row.action == "subject.export_completed"
                )
                assert created_event.organization_id == released_event.organization_id == str(org_a)
                assert created_event.actor_id == released_event.actor_id == str(member_owner)
                assert created_event.correlation_id == hold_response.headers["x-request-id"]
                assert released_event.correlation_id == released.headers["x-request-id"]
                assert denied_event.actor_id == str(member_viewer)
                assert denied_event.outcome == "denied"
                assert export_event.actor_id == str(member_owner)
                assert export_event.correlation_id == own_export.headers["x-request-id"]
        finally:
            if prior_override is None:
                app.dependency_overrides.pop(get_session, None)
            else:
                app.dependency_overrides[get_session] = prior_override
            get_rate_limiter.cache_clear()
    finally:
        clear_adapters()
        engine.dispose()


def test_postgres_deletion_and_hold_creation_are_serialized() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_size=4)
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_org(session)
            principal = _principal(org_id, member_id)
            actual_name = session.scalar(
                select(ORGANIZATIONS.c.name).where(ORGANIZATIONS.c.id == str(org_id))
            )
            request_organization_deletion(
                session,
                principal,
                confirmation_name=str(actual_name),
                actual_name=str(actual_name),
            )

        barrier = Barrier(2)

        def confirm() -> str:
            with Session(engine) as session:
                barrier.wait(timeout=10)
                return str(
                    confirm_organization_deletion(
                        session,
                        principal,
                        confirmation_name=str(actual_name),
                        actual_name=str(actual_name),
                    )["status"]
                )

        def create_hold() -> str:
            with Session(engine) as session:
                barrier.wait(timeout=10)
                try:
                    return str(
                        create_legal_hold(
                            session,
                            principal,
                            name="Race hold",
                            reason="Synthetic",
                            scope_category=None,
                        )["status"]
                    )
                except LifecycleError:
                    return "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            confirm_future = executor.submit(confirm)
            hold_future = executor.submit(create_hold)
            deletion_state, hold_state = confirm_future.result(), hold_future.result()

        with Session(engine) as session:
            actual_state = session.execute(
                select(ORG_DELETION_REQUESTS.c.status).where(
                    ORG_DELETION_REQUESTS.c.org_id == str(org_id)
                )
            ).scalar_one()
            active_holds = session.scalar(
                select(func.count())
                .select_from(LEGAL_HOLDS)
                .where(LEGAL_HOLDS.c.org_id == str(org_id), LEGAL_HOLDS.c.status == "active")
            )
            assert actual_state in {"blocked_by_legal_hold", "in_progress"}
            if actual_state == "blocked_by_legal_hold":
                assert hold_state == "active" and active_holds == 1
            else:
                assert hold_state == "rejected" and active_holds == 0
            assert deletion_state == actual_state
    finally:
        engine.dispose()


def test_postgres_subject_export_is_bounded_tenant_scoped_and_secret_free() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_org(session, subject="p14-export-subject")
            other_org, other_member = _seed_org(session, subject="p14-other-subject")
            now = datetime.now(UTC)
            secret_markers = (
                "P14_API_KEY_PLAINTEXT_SENTINEL",
                "P14_SESSION_TOKEN_SENTINEL",
                "P14_VAULT_PLAINTEXT_SENTINEL",
                "P14_PRIVATE_KEY_SENTINEL",
            )
            session_hash = uuid4().hex * 2
            api_key_hash = uuid4().hex * 2
            vault_id = str(uuid4())
            session.execute(
                APP_SESSIONS.insert().values(
                    id=str(uuid4()),
                    org_id=str(org_id),
                    member_id=str(member_id),
                    token_hash=session_hash,
                    auth_method="jwt",
                    created_at=now,
                    last_seen_at=now,
                    expires_at=now + timedelta(days=1),
                    user_agent=f"Bearer {secret_markers[1]}",
                )
            )
            for index in range(501):
                session.execute(
                    APP_SESSIONS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        member_id=str(member_id),
                        token_hash=uuid4().hex * 2,
                        auth_method="jwt",
                        created_at=now + timedelta(microseconds=index),
                        last_seen_at=now,
                        expires_at=now + timedelta(days=1),
                        user_agent="synthetic export row",
                    )
                )
            session.execute(
                API_KEYS.insert().values(
                    id=str(uuid4()),
                    org_id=str(org_id),
                    name="Synthetic key",
                    prefix=uuid4().hex[:12],
                    key_hash=api_key_hash,
                    scopes=["identity:read"],
                    created_by=str(member_id),
                    created_at=now,
                )
            )
            session.execute(
                SCIM_CREDENTIALS.insert().values(
                    id=str(uuid4()),
                    org_id=str(org_id),
                    name="Synthetic SCIM credential",
                    prefix=uuid4().hex[:12],
                    token_hash="P14_SCIM_CREDENTIAL_SECRET_SENTINEL",
                    created_by=str(member_id),
                    created_at=now,
                )
            )
            session.execute(
                VAULT_SECRETS.insert().values(
                    id=vault_id,
                    org_id=str(org_id),
                    name="synthetic export vault item",
                    secret_type="private_key",
                    ciphertext=secret_markers[2].encode(),
                    nonce=b"x" * 12,
                    key_version=1,
                    enabled=True,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.execute(
                SSO_CONFIGS.insert().values(
                    id=str(uuid4()),
                    org_id=str(org_id),
                    protocol="oidc",
                    issuer="https://synthetic-idp.example.test",
                    client_id="synthetic-client",
                    secret_ref=vault_id,
                    settings={},
                    enabled=True,
                    created_by=str(member_id),
                    created_at=now,
                    updated_at=now,
                )
            )
            # A second tenant's same-subject data must never enter this export.
            session.execute(
                APP_SESSIONS.insert().values(
                    id=str(uuid4()),
                    org_id=str(other_org),
                    member_id=str(other_member),
                    token_hash=uuid4().hex * 2,
                    auth_method="jwt",
                    created_at=now,
                    last_seen_at=now,
                    expires_at=now + timedelta(days=1),
                    user_agent="P14_OTHER_TENANT_SENTINEL",
                )
            )
            session.commit()

            export = build_subject_export(
                session,
                organization_id=org_id,
                organization_name="Synthetic Org",
                member_id=member_id,
                subject_id="p14-export-subject",
            )
            serialized = json.dumps(export, sort_keys=True, default=str)
            assert export["subject"]["subject_id"] == "p14-export-subject"
            assert len(serialized.encode("utf-8")) <= 1_000_000
            assert len(export["p2_data"]["sessions"]) == 500
            assert "sessions" in export["truncated_categories"]
            assert "P14_OTHER_TENANT_SENTINEL" not in serialized
            assert all(marker not in serialized for marker in secret_markers)
            assert session_hash not in serialized
            assert api_key_hash not in serialized
            assert "P14_SCIM_CREDENTIAL_SECRET_SENTINEL" not in serialized

            def keys(value: object) -> set[str]:
                if isinstance(value, dict):
                    return set(value).union(*(keys(item) for item in value.values()))
                if isinstance(value, list):
                    return set().union(*(keys(item) for item in value))
                return set()

            assert not keys(export).intersection(
                {
                    "password",
                    "password_hash",
                    "key",
                    "key_hash",
                    "token",
                    "token_hash",
                    "refresh_token",
                    "scim_credential",
                    "secret",
                    "secret_value",
                    "ciphertext",
                    "nonce",
                    "private_key",
                }
            )
            assert "P14_API_KEY_PLAINTEXT_SENTINEL" not in serialized
            assert "P14_SESSION_TOKEN_SENTINEL" not in serialized
            second_export = build_subject_export(
                session,
                organization_id=org_id,
                organization_name="Synthetic Org",
                member_id=member_id,
                subject_id="p14-export-subject",
            )
            assert export["p2_data"] == second_export["p2_data"]
            principal = _principal(org_id, member_id)
            record_subject_export(session, principal, member_id=member_id, result="requested")
            record_subject_export(session, principal, member_id=member_id, result="completed")
            assert set(
                session.execute(
                    select(AUDIT_EVENTS.c.action).where(
                        AUDIT_EVENTS.c.organization_id == str(org_id)
                    )
                ).scalars()
            ) >= {"subject.export_requested", "subject.export_completed"}
    finally:
        engine.dispose()


def test_postgres_oversized_subject_export_fails_and_audits_safe_metadata(monkeypatch) -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)

    class OversizedAdapter:
        name = "synthetic-oversized-export"

        def delete_organization(self, organization_id: UUID) -> None:
            del organization_id

        def export_subject(self, organization_id: UUID, member_id: UUID) -> dict[str, object]:
            del organization_id, member_id
            return {"synthetic": "P14_PRIVATE_KEY_SENTINEL" + ("x" * 1_000_000)}

    try:
        with Session(engine) as session:
            subject_id = f"p14-big-export-{uuid4()}"
            org_id, member_id = _seed_org(session, subject=subject_id)
            principal = _principal(org_id, member_id)
            register_adapter(OversizedAdapter())
            with pytest.raises(LifecycleError, match="safe response size"):
                build_subject_export(
                    session,
                    organization_id=org_id,
                    organization_name="Synthetic org",
                    member_id=member_id,
                    subject_id=subject_id,
                )
            record_subject_export(session, principal, member_id=member_id, result="requested")
            record_subject_export(session, principal, member_id=member_id, result="failed")
        monkeypatch.setenv(
            "SUPABASE_JWT_SECRET",
            "synthetic-test-signing-secret-never-use-outside-tests-0123456789",
        )
        monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
        monkeypatch.setenv("JWT_ISSUER", "https://synthetic-project.supabase.co/auth/v1")
        monkeypatch.setenv("JWT_AUDIENCE", "authenticated")
        prior_override = app.dependency_overrides.get(get_session)

        def override_session() -> Generator[Session, None, None]:
            with Session(engine) as request_session:
                yield request_session

        app.dependency_overrides[get_session] = override_session
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/identity/export",
                    headers=auth_headers(signed_token(subject_id, org_id)),
                )
                assert response.status_code == 503
                request_id = response.headers["x-request-id"]
        finally:
            if prior_override is None:
                app.dependency_overrides.pop(get_session, None)
            else:
                app.dependency_overrides[get_session] = prior_override
        with Session(engine) as session:
            events = session.execute(
                select(
                    AUDIT_EVENTS.c.action,
                    AUDIT_EVENTS.c.outcome,
                    AUDIT_EVENTS.c.event_metadata,
                    AUDIT_EVENTS.c.correlation_id,
                    AUDIT_EVENTS.c.actor_id,
                ).where(AUDIT_EVENTS.c.organization_id == str(org_id))
            ).all()
            assert any(
                row.action == "subject.export_failed" and row.outcome == "failure" for row in events
            )
            assert all("P14_PRIVATE_KEY_SENTINEL" not in str(row.event_metadata) for row in events)
            failed_event = next(
                row
                for row in events
                if row.action == "subject.export_failed" and row.correlation_id == request_id
            )
            assert failed_event.correlation_id == request_id
            assert failed_event.actor_id == str(member_id)
    finally:
        clear_adapters()
        engine.dispose()


def test_postgres_multiorg_deletion_cleans_tenant_data_and_preserves_other_org(
    monkeypatch,
) -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    try:
        with Session(engine) as session:
            subject = f"p14-multi-org-{uuid4()}"
            org_a, member_a = _seed_org(session, subject=subject)
            org_b, member_b = _seed_org(session, subject=subject)
            principal_a, principal_b = _principal(org_a, member_a), _principal(org_b, member_b)
            now = datetime.now(UTC)
            vault_a, vault_b = str(uuid4()), str(uuid4())
            for org_id, vault_id in ((org_a, vault_a), (org_b, vault_b)):
                session.execute(
                    VAULT_SECRETS.insert().values(
                        id=vault_id,
                        org_id=str(org_id),
                        name="synthetic-oidc-secret",
                        secret_type="oauth_client_secret",
                        ciphertext=b"synthetic-encrypted-value",
                        nonce=b"n" * 12,
                        key_version=1,
                        enabled=True,
                        created_at=now,
                        updated_at=now,
                    )
                )
                config_id = str(uuid4())
                session.execute(
                    SSO_CONFIGS.insert().values(
                        id=config_id,
                        org_id=str(org_id),
                        protocol="oidc",
                        issuer=f"https://idp-{org_id}.example.test",
                        client_id="synthetic-client",
                        secret_ref=vault_id,
                        settings={},
                        enabled=True,
                        created_by=str(member_a if org_id == org_a else member_b),
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.execute(
                    SSO_IDENTITIES.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        config_id=config_id,
                        member_id=str(member_a if org_id == org_a else member_b),
                        issuer=f"https://idp-{org_id}.example.test",
                        subject=f"sso-subject-{org_id}",
                        email=None,
                        created_at=now,
                    )
                )
                session.execute(
                    SSO_TRANSACTIONS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        config_id=config_id,
                        protocol="oidc",
                        state_hash=uuid4().hex * 2,
                        nonce_hash=uuid4().hex * 2,
                        expires_at=now + timedelta(minutes=5),
                    )
                )
                session.execute(
                    SSO_REPLAYS.insert().values(
                        org_id=str(org_id),
                        config_id=config_id,
                        assertion_id=f"assertion-{uuid4()}",
                        expires_at=now + timedelta(minutes=5),
                    )
                )
                session.execute(
                    APP_SESSIONS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        member_id=str(member_a if org_id == org_a else member_b),
                        token_hash=uuid4().hex * 2,
                        auth_method="jwt",
                        created_at=now,
                        last_seen_at=now,
                        expires_at=now + timedelta(days=1),
                    )
                )
                session.execute(
                    API_KEYS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        name="synthetic lifecycle key",
                        prefix=uuid4().hex[:12],
                        key_hash=uuid4().hex * 2,
                        scopes=["identity:read"],
                        created_by=str(member_a if org_id == org_a else member_b),
                        created_at=now,
                    )
                )
                session.execute(
                    SCIM_CREDENTIALS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        name="synthetic SCIM token",
                        prefix=uuid4().hex[:12],
                        token_hash=uuid4().hex * 2,
                        created_by=str(member_a if org_id == org_a else member_b),
                        created_at=now,
                    )
                )
                scim_user_id = str(uuid4())
                session.execute(
                    SCIM_USERS.insert().values(
                        id=scim_user_id,
                        org_id=str(org_id),
                        member_id=str(member_a if org_id == org_a else member_b),
                        external_id=f"ext-{org_id}",
                        user_name=f"user-{org_id}@example.test",
                        display_name="Synthetic user",
                        created_at=now,
                        updated_at=now,
                    )
                )
                group_id = str(uuid4())
                session.execute(
                    SCIM_GROUPS.insert().values(
                        id=group_id,
                        org_id=str(org_id),
                        external_id=f"group-{org_id}",
                        display_name=f"Synthetic group {org_id}",
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.execute(
                    SCIM_GROUP_MEMBERS.insert().values(
                        org_id=str(org_id),
                        group_id=group_id,
                        member_id=str(member_a if org_id == org_a else member_b),
                        created_at=now,
                    )
                )
                policy_id = str(uuid4())
                creator_id = str(member_a if org_id == org_a else member_b)
                session.execute(
                    POLICIES.insert().values(
                        id=policy_id,
                        org_id=str(org_id),
                        name="synthetic policy",
                        enabled=True,
                        priority=1,
                        conditions={"channel": "api"},
                        action="block",
                        version=1,
                        created_by=creator_id,
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.execute(
                    POLICY_VERSIONS.insert().values(
                        id=str(uuid4()),
                        policy_id=policy_id,
                        org_id=str(org_id),
                        version=1,
                        snapshot={"name": "synthetic policy"},
                        created_by=creator_id,
                        created_at=now,
                    )
                )
                session.execute(
                    RETENTION_POLICIES.insert().values(
                        org_id=str(org_id),
                        category="sessions",
                        retention_days=365,
                        enabled=True,
                        effective_at=now,
                        updated_by=creator_id,
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.execute(
                    RETENTION_RUNS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        category="sessions",
                        status="completed",
                        deleted_count=0,
                        failure_code=None,
                        started_at=now,
                        completed_at=now,
                    )
                )
                session.execute(
                    EXCEPTIONS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        policy_id=policy_id,
                        scope={"channel": "api"},
                        reason="synthetic exception",
                        approver_id=creator_id,
                        created_by=creator_id,
                        updated_by=creator_id,
                        enabled=True,
                        expires_at=now + timedelta(days=1),
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.execute(
                    SUPPRESSIONS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        match={"fingerprint": uuid4().hex * 2},
                        reason="synthetic suppression",
                        created_by=creator_id,
                        updated_by=creator_id,
                        enabled=True,
                        expires_at=now + timedelta(days=1),
                        created_at=now,
                        updated_at=now,
                    )
                )
                action_id = str(uuid4())
                session.execute(
                    ACTIONS.insert().values(
                        id=action_id,
                        org_id=str(org_id),
                        request_id=str(uuid4()),
                        policy_id=policy_id,
                        policy_version=1,
                        requested_by=creator_id,
                        action="require_approval",
                        status="pending_approval",
                        justification="synthetic action",
                        metadata={},
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.execute(
                    APPROVALS.insert().values(
                        id=str(uuid4()),
                        org_id=str(org_id),
                        action_id=action_id,
                        requested_by=creator_id,
                        status="pending",
                        justification="synthetic approval",
                        expires_at=now + timedelta(days=1),
                        created_at=now,
                    )
                )
            session.commit()

            # P06 immutability still rejects ordinary deletion before lifecycle starts.
            with pytest.raises(DBAPIError), session.begin_nested():
                session.execute(
                    text("DELETE FROM dlp_policy_versions WHERE org_id=:org"),
                    {"org": str(org_a)},
                )
            session.rollback()

            hold = create_legal_hold(
                session,
                principal_a,
                name="Deletion blocker",
                reason="Synthetic preservation requirement",
                scope_category=None,
            )
            org_name = session.scalar(
                select(ORGANIZATIONS.c.name).where(ORGANIZATIONS.c.id == str(org_a))
            )
            requested = request_organization_deletion(
                session,
                principal_a,
                confirmation_name=str(org_name),
                actual_name=str(org_name),
            )
            assert requested["status"] == "requested"
            blocked = confirm_organization_deletion(
                session,
                principal_a,
                confirmation_name=str(org_name),
                actual_name=str(org_name),
            )
            assert blocked["status"] == "blocked_by_legal_hold"
            release_legal_hold(
                session,
                principal_a,
                hold_id=UUID(str(hold["hold_id"])),
                release_reason="Synthetic release",
            )
            confirmed = confirm_organization_deletion(
                session,
                principal_a,
                confirmation_name=str(org_name),
                actual_name=str(org_name),
            )
            assert confirmed["status"] == "in_progress"

            while confirmed["status"] == "in_progress":
                try:
                    confirmed = execute_organization_deletion(session, principal_a, max_batches=3)
                except LifecycleError as exc:
                    failed = session.execute(
                        select(
                            ORG_DELETION_REQUESTS.c.current_table,
                            ORG_DELETION_REQUESTS.c.failure_code,
                        ).where(ORG_DELETION_REQUESTS.c.org_id == str(org_a))
                    ).one()
                    raise AssertionError(
                        f"deletion failed at {failed.current_table}: {failed.failure_code}"
                    ) from exc
            assert confirmed["status"] == "completed"
            assert "synthetic-encrypted-value" not in json.dumps(confirmed, default=str)

            tombstone = session.execute(
                select(ORGANIZATIONS.c.name, ORGANIZATIONS.c.settings_json).where(
                    ORGANIZATIONS.c.id == str(org_a)
                )
            ).one()
            assert tombstone.name == f"Deleted organization {str(org_a)[:8]}"
            assert tombstone.settings_json == {}
            assert (
                session.scalar(
                    select(ORG_DELETION_REQUESTS.c.status).where(
                        ORG_DELETION_REQUESTS.c.org_id == str(org_a)
                    )
                )
                == "completed"
            )

            for table in (
                APP_SESSIONS,
                API_KEYS,
                VAULT_SECRETS,
                SSO_CONFIGS,
                SSO_IDENTITIES,
                SSO_TRANSACTIONS,
                SSO_REPLAYS,
                SCIM_CREDENTIALS,
                SCIM_USERS,
                SCIM_GROUPS,
                SCIM_GROUP_MEMBERS,
                RETENTION_POLICIES,
                RETENTION_RUNS,
                EXCEPTIONS,
                SUPPRESSIONS,
                ACTIONS,
                APPROVALS,
                POLICIES,
                POLICY_VERSIONS,
            ):
                assert (
                    session.scalar(
                        select(func.count()).select_from(table).where(table.c.org_id == str(org_a))
                    )
                    == 0
                )
                assert (
                    session.scalar(
                        select(func.count()).select_from(table).where(table.c.org_id == str(org_b))
                    )
                    == 1
                )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(text("members"))
                    .where(text("organization_id = :org"))
                    .params(org=str(org_a))
                )
                == 0
            )
            member_b_row = session.execute(
                text("SELECT role,active FROM members WHERE id=:id AND organization_id=:org"),
                {"id": str(member_b), "org": str(org_b)},
            ).one()
            assert member_b_row.role == "owner" and member_b_row.active is True
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(AUDIT_EVENTS)
                    .where(
                        AUDIT_EVENTS.c.organization_id == str(org_a),
                        AUDIT_EVENTS.c.action == "organization.deletion_completed",
                    )
                )
                == 1
            )

            before = session.scalar(
                select(func.count())
                .select_from(AUDIT_EVENTS)
                .where(AUDIT_EVENTS.c.organization_id == str(org_a))
            )
            with pytest.raises(LifecycleError):
                execute_organization_deletion(session, principal_a)
            after = session.scalar(
                select(func.count())
                .select_from(AUDIT_EVENTS)
                .where(AUDIT_EVENTS.c.organization_id == str(org_a))
            )
            assert after == before
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(text("members"))
                    .where(text("organization_id = :org AND auth_subject_id = :subject"))
                    .params(org=str(org_b), subject=subject)
                )
                == 1
            )
            # The same subject still has an active membership and data only in Org B.
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ORGANIZATIONS)
                    .where(ORGANIZATIONS.c.id == str(org_b))
                )
                == 1
            )
            assert principal_b.organization_id == org_b

        monkeypatch.setenv(
            "SUPABASE_JWT_SECRET",
            "synthetic-test-signing-secret-never-use-outside-tests-0123456789",
        )
        monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
        monkeypatch.setenv("JWT_ISSUER", "https://synthetic-project.supabase.co/auth/v1")
        monkeypatch.setenv("JWT_AUDIENCE", "authenticated")
        prior_override = app.dependency_overrides.get(get_session)

        def override_session() -> Generator[Session, None, None]:
            with Session(engine) as request_session:
                yield request_session

        app.dependency_overrides[get_session] = override_session
        try:
            with TestClient(app) as client:
                retained_org = auth_headers(signed_token(subject, org_b))
                deleted_org = auth_headers(signed_token(subject, org_a))
                assert (
                    client.get("/organizations/current/retention", headers=retained_org).status_code
                    == 200
                )
                assert (
                    client.get(
                        "/organizations/current/legal-holds", headers=deleted_org
                    ).status_code
                    == 401
                )
        finally:
            if prior_override is None:
                app.dependency_overrides.pop(get_session, None)
            else:
                app.dependency_overrides[get_session] = prior_override
    finally:
        engine.dispose()


def test_postgres_deletion_of_only_membership_leaves_no_active_organization(
    monkeypatch,
) -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_size=4)
    subject = f"p14-only-org-{uuid4()}"
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_org(session, subject=subject)
            principal = _principal(org_id, member_id)
            org_name = session.scalar(
                select(ORGANIZATIONS.c.name).where(ORGANIZATIONS.c.id == str(org_id))
            )
            request_organization_deletion(
                session,
                principal,
                confirmation_name=str(org_name),
                actual_name=str(org_name),
            )
            confirm_organization_deletion(
                session,
                principal,
                confirmation_name=str(org_name),
                actual_name=str(org_name),
            )
            result = execute_organization_deletion(session, principal, max_batches=20)
            while result["status"] == "in_progress":
                result = execute_organization_deletion(session, principal, max_batches=20)
            assert result["status"] == "completed"
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(text("members"))
                    .where(text("organization_id=:org AND auth_subject_id=:subject"))
                    .params(org=str(org_id), subject=subject)
                )
                == 0
            )
            assert (
                session.scalar(
                    select(ORG_DELETION_REQUESTS.c.status).where(
                        ORG_DELETION_REQUESTS.c.org_id == str(org_id)
                    )
                )
                == "completed"
            )

        monkeypatch.setenv(
            "SUPABASE_JWT_SECRET",
            "synthetic-test-signing-secret-never-use-outside-tests-0123456789",
        )
        monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
        monkeypatch.setenv("JWT_ISSUER", "https://synthetic-project.supabase.co/auth/v1")
        monkeypatch.setenv("JWT_AUDIENCE", "authenticated")
        prior_override = app.dependency_overrides.get(get_session)

        def override_session() -> Generator[Session, None, None]:
            with Session(engine) as request_session:
                yield request_session

        app.dependency_overrides[get_session] = override_session
        try:
            with TestClient(app) as client:
                token = auth_headers(signed_token(subject, org_id))
                response = client.get("/organizations/current/retention", headers=token)
                assert response.status_code == 401
        finally:
            if prior_override is None:
                app.dependency_overrides.pop(get_session, None)
            else:
                app.dependency_overrides[get_session] = prior_override
    finally:
        engine.dispose()


def test_postgres_deletion_retries_after_partial_cleanup_failure() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)

    class FailOnceAdapter:
        name = "synthetic-fail-once"

        def __init__(self) -> None:
            self.calls = 0

        def delete_organization(self, organization_id: UUID) -> None:
            del organization_id
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("synthetic adapter failure")

        def export_subject(self, organization_id: UUID, member_id: UUID) -> dict[str, object]:
            del organization_id, member_id
            return {}

    adapter = FailOnceAdapter()
    try:
        with Session(engine) as session:
            org_id, member_id = _seed_org(session)
            principal = _principal(org_id, member_id)
            now = datetime.now(UTC)
            session.execute(
                APP_SESSIONS.insert().values(**_expired_session(org_id, member_id, expired=False))
            )
            session.execute(
                VAULT_SECRETS.insert().values(
                    id=str(uuid4()),
                    org_id=str(org_id),
                    name="synthetic-vault-item",
                    secret_type="generic_secret",
                    ciphertext=b"synthetic-ciphertext-not-plaintext",
                    nonce=b"v" * 12,
                    key_version=1,
                    enabled=True,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.commit()
            org_name = session.scalar(
                select(ORGANIZATIONS.c.name).where(ORGANIZATIONS.c.id == str(org_id))
            )
            request_organization_deletion(
                session,
                principal,
                confirmation_name=str(org_name),
                actual_name=str(org_name),
            )
            confirm_organization_deletion(
                session,
                principal,
                confirmation_name=str(org_name),
                actual_name=str(org_name),
            )

        register_adapter(adapter)
        with Session(engine) as session:
            with pytest.raises(LifecycleError, match="paused"):
                while True:
                    execute_organization_deletion(session, principal, max_batches=20)
            failed = session.execute(
                select(
                    ORG_DELETION_REQUESTS.c.status,
                    ORG_DELETION_REQUESTS.c.current_table,
                    ORG_DELETION_REQUESTS.c.failure_code,
                ).where(ORG_DELETION_REQUESTS.c.org_id == str(org_id))
            ).one()
            assert failed.status == "failed"
            assert failed.current_table == "external_data"
            assert failed.failure_code == "deletion_batch_failed"
            # Earlier batches committed; retry resumes at the failed phase.
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(APP_SESSIONS)
                    .where(APP_SESSIONS.c.org_id == str(org_id))
                )
                == 0
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(VAULT_SECRETS)
                    .where(VAULT_SECRETS.c.org_id == str(org_id))
                )
                == 0
            )
            state = execute_organization_deletion(session, principal, max_batches=20)
            assert state["status"] == "completed"
            assert adapter.calls == 2
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(text("members"))
                    .where(text("organization_id = :org"))
                    .params(org=str(org_id))
                )
                == 0
            )
            tombstone = session.scalar(
                select(ORGANIZATIONS.c.name).where(ORGANIZATIONS.c.id == str(org_id))
            )
            assert str(tombstone).startswith("Deleted organization ")
            actions = set(
                session.execute(
                    select(AUDIT_EVENTS.c.action).where(
                        AUDIT_EVENTS.c.organization_id == str(org_id)
                    )
                ).scalars()
            )
            assert "organization.deletion_failed" in actions
            assert "organization.deletion_completed" in actions
            event_metadata = session.execute(
                select(AUDIT_EVENTS.c.event_metadata).where(
                    AUDIT_EVENTS.c.organization_id == str(org_id)
                )
            ).scalars()
            assert all(
                "synthetic-ciphertext-not-plaintext" not in str(item) for item in event_metadata
            )
    finally:
        clear_adapters()
        engine.dispose()
