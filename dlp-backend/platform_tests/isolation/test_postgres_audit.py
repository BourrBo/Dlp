"""Real PostgreSQL tenant RLS, append-only, and tamper-evident audit checks."""

import json
import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditService
from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _principal(org_id: UUID, *, api_key: bool = False) -> Principal:
    return Principal(
        organization_id=org_id,
        subject_id="p10-audit-test",
        actor_type=ActorType.SERVICE if api_key else ActorType.USER,
        role=Role.OWNER,
        scopes=(),
        auth_method=AuthMethod.API_KEY if api_key else AuthMethod.JWT,
    )


def _claims(session: Session, org_id: UUID | None) -> None:
    session.execute(text("SET LOCAL ROLE authenticated"))
    claims: dict[str, str] = {"role": "authenticated", "aud": "authenticated", "app_role": "owner"}
    if org_id is not None:
        claims["org_id"] = str(org_id)
    session.execute(
        text("SELECT set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def test_postgres_audit_rls_immutability_chain_and_api_key_actor() -> None:
    assert DATABASE_URL is not None
    from alembic import command
    from alembic.config import Config

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(config, "head")
    engine = create_engine(DATABASE_URL)
    org_a, org_b = uuid4(), uuid4()
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO organizations(id,name) "
                    "VALUES (:a,'P10 Audit A'),(:b,'P10 Audit B')"
                ),
                {"a": str(org_a), "b": str(org_b)},
            )

        audit = AuditService()
        event_a = uuid4()
        with Session(engine) as session:
            _claims(session, org_a)
            event_a = audit.record_event(
                session,
                _principal(org_a),
                action=AuditAction.API_KEY_CREATED,
                resource_type="api_key",
                resource_id="safe-key-id-a",
                metadata={"api_key": "synthetic-secret-token", "label": "automation"},
            ).event_id
            session.commit()
        with Session(engine) as session:
            _claims(session, org_a)
            event_a2 = audit.record_event(
                session,
                _principal(org_a),
                action=AuditAction.API_KEY_REVOKED,
                resource_type="api_key",
                resource_id="safe-key-id-a2",
            ).event_id
            session.commit()
        event_b = uuid4()
        with Session(engine) as session:
            _claims(session, org_b)
            event_b = audit.record_event(
                session,
                _principal(org_b, api_key=True),
                action=AuditAction.API_KEY_CREATED,
                resource_type="api_key",
                resource_id="safe-key-id-b",
            ).event_id
            session.commit()

        with Session(engine) as session:
            _claims(session, org_a)
            rows = audit.list_events(session, org_a)
            assert {row.event_id for row in rows} == {event_a, event_a2}
            assert audit.list_events(session, org_b) == []
            assert audit.verify_chain_result(session, org_b).checked_events == 0
            assert (
                session.execute(
                    text("SELECT event_id FROM audit_events WHERE organization_id=:org"),
                    {"org": str(org_b)},
                )
                .scalars()
                .all()
                == []
            )
            original_event = next(row for row in rows if row.event_id == event_a)
            assert original_event.metadata["api_key"] == "[REDACTED]"
            assert rows[0].actor_type == "user"
            assert audit.verify_chain(session, org_a)
            with pytest.raises(DBAPIError), session.begin_nested():
                session.execute(
                    text(
                        "INSERT INTO audit_events(event_id,organization_id,occurred_at,actor_id,"
                        "actor_type,auth_method,actor_role,action,resource_type,resource_id,outcome,"
                        "event_metadata,sequence_number,previous_hash,event_hash) VALUES "
                        "(:id,:org,now(),'forged','user','jwt','owner','policy.created','policy',"
                        "'forged','success','{}'::jsonb,2,:prev,:hash)"
                    ),
                    {
                        "id": str(uuid4()),
                        "org": str(org_b),
                        "prev": "0" * 64,
                        "hash": "1" * 64,
                    },
                )
            with pytest.raises(DBAPIError), session.begin_nested():
                session.execute(
                    text("UPDATE audit_events SET resource_id='altered' WHERE event_id=:id"),
                    {"id": str(event_a)},
                )
            with pytest.raises(DBAPIError), session.begin_nested():
                session.execute(
                    text("DELETE FROM audit_events WHERE event_id=:id"), {"id": str(event_a)}
                )
            with pytest.raises(DBAPIError), session.begin_nested():
                session.execute(
                    text("UPDATE audit_events SET resource_id='cross-tenant' WHERE event_id=:id"),
                    {"id": str(event_b)},
                )
            with pytest.raises(DBAPIError), session.begin_nested():
                session.execute(
                    text("DELETE FROM audit_events WHERE event_id=:id"),
                    {"id": str(event_b)},
                )

        with Session(engine) as session:
            _claims(session, org_b)
            tenant_b_events = audit.list_events(session, org_b)
            assert [event.event_id for event in tenant_b_events] == [event_b]
            assert tenant_b_events[0].actor_type == "service"
            assert tenant_b_events[0].auth_method == "api_key"

        with Session(engine) as session:
            _claims(session, None)
            assert audit.list_events(session, org_a) == []
            assert session.execute(text("SELECT event_id FROM audit_events")).scalars().all() == []

        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET LOCAL ROLE authenticated"))
                connection.execute(
                    text("SELECT set_config('request.jwt.claims', :claims, true)"),
                    {"claims": json.dumps({"role": "authenticated", "org_id": str(org_a)})},
                )
                visible_events = (
                    connection.execute(text("SELECT event_id FROM audit_events")).scalars().all()
                )
                assert len(visible_events) == 2
            with connection.begin():
                assert (
                    connection.execute(text("SELECT current_user")).scalar_one() != "authenticated"
                )
                connection.execute(text("SET LOCAL ROLE authenticated"))
                connection.execute(text("SELECT set_config('request.jwt.claims', '{}', true)"))
                assert (
                    connection.execute(text("SELECT event_id FROM audit_events")).scalars().all()
                    == []
                )

        # The chain detects an owner-level mutation if the immutability trigger is bypassed.
        with engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("UPDATE audit_events SET event_metadata='{}'::jsonb WHERE event_id=:id"),
                {"id": str(event_a)},
            )
            with Session(bind=connection) as session:
                assert not audit.verify_chain(session, org_a)
            transaction.rollback()

        # Removing an interior/first row leaves a sequence gap detectable by the verifier.
        with engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("DELETE FROM audit_events WHERE event_id=:id"), {"id": str(event_a)}
            )
            with Session(bind=connection) as session:
                assert not audit.verify_chain(session, org_a)
            transaction.rollback()

        # Swapping sequence positions is detected even when the rows remain present.
        with engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("UPDATE audit_events SET sequence_number=99 WHERE event_id=:id"),
                {"id": str(event_a)},
            )
            connection.execute(
                text("UPDATE audit_events SET sequence_number=1 WHERE event_id=:id"),
                {"id": str(event_a2)},
            )
            connection.execute(
                text("UPDATE audit_events SET sequence_number=2 WHERE event_id=:id"),
                {"id": str(event_a)},
            )
            with Session(bind=connection) as session:
                assert not audit.verify_chain(session, org_a)
            transaction.rollback()

        with engine.begin() as connection:
            # Append-only rows intentionally require an owner-level maintenance path to purge tests.
            connection.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("DELETE FROM audit_events WHERE organization_id IN (:a,:b)"),
                {"a": str(org_a), "b": str(org_b)},
            )
            connection.execute(
                text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"),
                {"a": str(org_a), "b": str(org_b)},
            )
    finally:
        engine.dispose()
