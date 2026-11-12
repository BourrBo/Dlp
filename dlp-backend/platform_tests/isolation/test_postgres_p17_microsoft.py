"""PostgreSQL tenant isolation for P17 Microsoft connector rows and OAuth."""

import json
import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from dlp_platform.connectors.oauth import OAuthRejected, PersistentOAuthTransactions
from dlp_platform.contracts.common import AuthMethod, Role
from dlp_platform.tables import ORGANIZATIONS

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _set_tenant(connection, org_id: str | None) -> None:
    connection.execute(text("SET LOCAL ROLE authenticated"))
    claims: dict[str, str] = {"role": "authenticated", "aud": "authenticated", "app_role": "owner"}
    if org_id is not None:
        claims["org_id"] = org_id
    connection.execute(
        text("SELECT set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def test_microsoft_connector_rls_and_persistent_oauth_are_tenant_scoped() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(config, "head")
    org_a, org_b = str(uuid4()), str(uuid4())
    onedrive_id, sharepoint_id = str(uuid4()), str(uuid4())
    now = datetime.now(UTC)
    transaction_service = PersistentOAuthTransactions()
    try:
        with engine.begin() as connection:
            connection.execute(
                ORGANIZATIONS.insert(),
                [
                    {
                        "id": org_a,
                        "name": f"P17 OneDrive {org_a[:8]}",
                        "settings_json": {},
                        "created_at": now,
                        "updated_at": now,
                    },
                    {
                        "id": org_b,
                        "name": f"P17 SharePoint {org_b[:8]}",
                        "settings_json": {},
                        "created_at": now,
                        "updated_at": now,
                    },
                ],
            )
            for org_id, connector_id, provider in (
                (org_a, onedrive_id, "microsoft_onedrive"),
                (org_b, sharepoint_id, "microsoft_sharepoint"),
            ):
                connection.execute(
                    text(
                        "INSERT INTO dlp_connectors "
                        "(id,org_id,provider,name,status,config_json,created_at,updated_at) "
                        "VALUES (:id,:org,:provider,'test','connected','{}',:now,:now)"
                    ),
                    {"id": connector_id, "org": org_id, "provider": provider, "now": now},
                )
                connection.execute(
                    text(
                        "INSERT INTO dlp_connector_state "
                        "(connector_id,org_id,provider,checkpoint,state_json,updated_at) "
                        "VALUES (:id,:org,:provider,'microsoft_graph_delta_v1','{}',:now)"
                    ),
                    {"id": connector_id, "org": org_id, "provider": provider, "now": now},
                )

        with engine.begin() as connection:
            _set_tenant(connection, org_a)
            assert connection.execute(text("SELECT id FROM dlp_connectors")).scalars().all() == [
                onedrive_id
            ]
            assert connection.execute(
                text("SELECT connector_id FROM dlp_connector_state")
            ).scalars().all() == [onedrive_id]
            assert (
                connection.execute(
                    text("UPDATE dlp_connectors SET name='forged' WHERE id=:id"),
                    {"id": sharepoint_id},
                ).rowcount
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "UPDATE dlp_connector_state SET checkpoint='forged' WHERE connector_id=:id"
                    ),
                    {"id": sharepoint_id},
                ).rowcount
                == 0
            )
            assert (
                connection.execute(
                    text("DELETE FROM dlp_connectors WHERE id=:id"), {"id": sharepoint_id}
                ).rowcount
                == 0
            )
            savepoint = connection.begin_nested()
            try:
                connection.execute(
                    text(
                        "INSERT INTO dlp_connectors "
                        "(id,org_id,provider,name,status,config_json,created_at,updated_at) "
                        "VALUES (:id,:org,'microsoft_sharepoint','forged','connected','{}',"
                        ":now,:now)"
                    ),
                    {"id": str(uuid4()), "org": org_b, "now": now},
                )
            except DBAPIError:
                savepoint.rollback()
            else:
                savepoint.commit()
                pytest.fail("cross-tenant Microsoft connector insert was accepted")

        with engine.begin() as connection:
            _set_tenant(connection, None)
            assert connection.execute(text("SELECT id FROM dlp_connectors")).scalars().all() == []
            assert (
                connection.execute(text("SELECT connector_id FROM dlp_connector_state"))
                .scalars()
                .all()
                == []
            )

        with engine.begin() as connection:
            connection.execute(text("SET LOCAL ROLE authenticated"))
            connection.execute(text("SELECT set_config('request.jwt.claims', '{}', true)"))
            assert connection.execute(text("SELECT id FROM dlp_connectors")).scalars().all() == []

        with Session(engine) as session:
            transaction, _ = transaction_service.create(
                session,
                organization_id=UUID(org_a),
                principal_id="p17-owner",
                provider="microsoft_graph",
                redirect_uri="https://dlp.example.test/connectors/oauth/microsoft/callback",
                binding_id=onedrive_id,
                role=Role.OWNER,
                member_id=uuid4(),
                session_id=uuid4(),
                scopes=("connectors:write",),
                auth_method=AuthMethod.SSO,
            )
        with Session(engine) as session, pytest.raises(OAuthRejected):
            transaction_service.consume_callback(
                session, transaction.state, provider="google_drive"
            )
        with Session(engine) as session:
            consumed = transaction_service.consume_callback(
                session, transaction.state, provider="microsoft_graph"
            )
        assert consumed.binding_id == onedrive_id
        assert consumed.organization_id == UUID(org_a)
        with Session(engine) as session, pytest.raises(OAuthRejected):
            transaction_service.consume_callback(
                session, transaction.state, provider="microsoft_graph"
            )
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM dlp_connectors WHERE id IN (:a,:b)"),
                {"a": onedrive_id, "b": sharepoint_id},
            )
            connection.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()
