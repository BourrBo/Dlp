"""Exercise real PostgreSQL P03–P17 migration upgrades and downgrades."""

import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def test_rls_migration_downgrade_then_upgrade_on_postgres(monkeypatch) -> None:
    assert DATABASE_URL is not None
    original_url = make_url(DATABASE_URL)
    admin_url = original_url.set(database="postgres")
    scratch_database = f"dlp_migration_test_{uuid4().hex[:12]}"
    admin_engine = create_engine(admin_url)
    with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'CREATE DATABASE "{scratch_database}"')
    scratch_url = original_url.set(database=scratch_database).render_as_string(hide_password=False)
    monkeypatch.setenv("DATABASE_URL", scratch_url)
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", scratch_url)
    engine = create_engine(scratch_url)
    try:
        # The chain runs in an isolated database so P14's immutable audit history
        # in the shared integration database survives historical downgrade checks.
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DO $$ BEGIN IF NOT EXISTS "
                    "(SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN "
                    "CREATE ROLE authenticated NOLOGIN; END IF; END $$"
                )
            )
            conn.execute(text("CREATE SCHEMA auth"))
            conn.execute(
                text(
                    "CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE "
                    "AS $$ SELECT NULLIF(current_setting('request.jwt.claims', true), '')::jsonb $$"
                )
            )
            conn.execute(text("GRANT USAGE ON SCHEMA auth TO authenticated"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION auth.jwt() TO authenticated"))
        # Start from an empty schema and validate every supported migration step.
        command.upgrade(config, "head")
        command.downgrade(config, "0013_data_lifecycle")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_connectors')")).scalar_one()
                is None
            )
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_connector_state')")).scalar_one()
                is None
            )
            assert (
                conn.execute(
                    text("SELECT to_regclass('public.dlp_oauth_transactions')")
                ).scalar_one()
                is None
            )
        command.upgrade(config, "head")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0017_cloud_storage_connectors"
            )
            provider_check = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname='ck_dlp_connectors_provider'"
                )
            ).scalar_one()
            assert "microsoft_onedrive" in provider_check
            assert "microsoft_sharepoint" in provider_check
            assert "aws_s3" in provider_check
            assert "google_cloud_storage" in provider_check
            audit_check = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname='ck_audit_events_action'"
                )
            ).scalar_one()
            assert "connector.microsoft_library_selected" in audit_check
            connector_check = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname='ck_dlp_connectors_provider'"
                )
            ).scalar_one()
            assert "aws_s3" in connector_check
            assert "google_cloud_storage" in connector_check
            enabled = conn.execute(
                text("SELECT relrowsecurity FROM pg_class WHERE oid='public.events'::regclass")
            ).scalar_one()
            assert enabled is True
            idempotency_rls = conn.execute(
                text(
                    "SELECT relrowsecurity FROM pg_class "
                    "WHERE oid='public.dlp_scan_idempotency'::regclass"
                )
            ).scalar_one()
            assert idempotency_rls is True

            for table in ("dlp_policies", "dlp_destinations"):
                enabled = conn.execute(
                    text(
                        f"SELECT relrowsecurity FROM pg_class WHERE oid='public.{table}'::regclass"
                    )
                ).scalar_one()
                assert enabled is True

            for table in ("dlp_policy_versions", "dlp_exceptions", "dlp_suppressions"):
                enabled = conn.execute(
                    text("SELECT relrowsecurity FROM pg_class WHERE oid=CAST(:table AS regclass)"),
                    {"table": f"public.{table}"},
                ).scalar_one()
                assert enabled is True
            for table in ("dlp_actions", "dlp_approvals"):
                assert (
                    conn.execute(
                        text(
                            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                            "WHERE oid=CAST(:table AS regclass)"
                        ),
                        {"table": f"public.{table}"},
                    ).scalar_one()
                    is True
                )
            assert (
                conn.execute(
                    text(
                        "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                        "WHERE oid='public.dlp_vault_secrets'::regclass"
                    )
                ).scalar_one()
                is True
            )
            for table in ("dlp_connectors", "dlp_connector_state", "dlp_oauth_transactions"):
                assert (
                    conn.execute(
                        text(
                            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                            "WHERE oid=CAST(:table AS regclass)"
                        ),
                        {"table": f"public.{table}"},
                    ).scalar_one()
                    is True
                )

            for table in (
                "dlp_retention_policies",
                "dlp_legal_holds",
                "dlp_org_deletion_requests",
                "dlp_retention_runs",
            ):
                assert (
                    conn.execute(
                        text(
                            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                            "WHERE oid=CAST(:table AS regclass)"
                        ),
                        {"table": f"public.{table}"},
                    ).scalar_one()
                    is True
                )

            for table in (
                "dlp_sso_configs",
                "dlp_sso_identities",
                "dlp_sso_transactions",
                "dlp_sso_replays",
            ):
                assert (
                    conn.execute(
                        text(
                            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                            "WHERE oid=CAST(:table AS regclass)"
                        ),
                        {"table": f"public.{table}"},
                    ).scalar_one()
                    is True
                )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_constraint "
                        "WHERE conname IN ('uq_members_id_org','uq_dlp_vault_secrets_id_org')"
                    )
                ).scalar_one()
                == 2
            )

            assert (
                conn.execute(
                    text(
                        "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                        "WHERE oid='public.audit_events'::regclass"
                    )
                ).scalar_one()
                is True
            )
            for table in (
                "dlp_app_sessions",
                "dlp_ip_allowlist_settings",
                "dlp_ip_allowlist_entries",
            ):
                assert (
                    conn.execute(
                        text(
                            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                            "WHERE oid=CAST(:table AS regclass)"
                        ),
                        {"table": f"public.{table}"},
                    ).scalar_one()
                    is True
                )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
                        "AND policyname IN ('member_self_membership_select', "
                        "'organization_self_membership_select')"
                    )
                ).scalar_one()
                == 2
            )
            for table in ("dlp_scim_users", "dlp_scim_groups", "dlp_scim_group_members"):
                assert (
                    conn.execute(
                        text(
                            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                            "WHERE oid=CAST(:table AS regclass)"
                        ),
                        {"table": f"public.{table}"},
                    ).scalar_one()
                    is True
                )
            assert (
                conn.execute(
                    text(
                        "SELECT relrowsecurity FROM pg_class "
                        "WHERE oid='public.dlp_scim_credentials'::regclass"
                    )
                ).scalar_one()
                is True
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_name='members' AND column_name='active'"
                    )
                ).scalar_one()
                == 1
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_indexes WHERE schemaname='public' "
                        "AND tablename='audit_events'"
                    )
                ).scalar_one()
                >= 6
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_trigger "
                        "WHERE tgrelid='public.audit_events'::regclass "
                        "AND NOT tgisinternal"
                    )
                ).scalar_one()
                == 1
            )

        command.downgrade(config, "0012_identity_management")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_legal_holds')")).scalar_one()
                is None
            )
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0012_identity_management"
            )
        command.upgrade(config, "head")

        command.downgrade(config, "0008_secret_vault")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.audit_events')")).scalar_one() is None
            )
        command.upgrade(config, "head")

        # Exercise P13 downgrade and re-upgrade without removing earlier phases.
        command.downgrade(config, "0011_scim")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_app_sessions')")).scalar_one()
                is None
            )
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0011_scim"
            )
        command.upgrade(config, "head")

        # Exercise P12 downgrade and re-upgrade independently from earlier phases.
        command.downgrade(config, "0010_sso")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_scim_users')")).scalar_one()
                is None
            )
            assert (
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name='members' AND column_name='active'"
                    )
                ).scalar_one_or_none()
                is None
            )
        command.upgrade(config, "head")

        # Exercise P11 downgrade and re-upgrade independently from earlier phases.
        command.downgrade(config, "0009_audit_log")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_sso_configs')")).scalar_one()
                is None
            )
            assert (
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name='members' AND column_name='email'"
                    )
                ).scalar_one_or_none()
                is None
            )
        command.upgrade(config, "head")

        command.downgrade(config, "0007_advanced_actions_approvals")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_vault_secrets')")).scalar_one()
                is None
            )
        command.upgrade(config, "head")

        command.downgrade(config, "0006_exceptions_versions")
        with engine.connect() as conn:
            for table in ("dlp_actions", "dlp_approvals"):
                assert (
                    conn.execute(
                        text("SELECT to_regclass(:name)"), {"name": f"public.{table}"}
                    ).scalar_one()
                    is None
                )
        command.upgrade(config, "head")

        command.downgrade(config, "0005_policy_engine_core")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0005_policy_engine_core"
            )
            for table in ("dlp_policy_versions", "dlp_exceptions", "dlp_suppressions"):
                assert (
                    conn.execute(
                        text("SELECT to_regclass(:name)"), {"name": f"public.{table}"}
                    ).scalar_one()
                    is None
                )

        command.downgrade(config, "0004_scan_idempotency")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0004_scan_idempotency"
            )
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_policies')")).scalar_one() is None
            )
            assert (
                conn.execute(text("SELECT to_regclass('public.dlp_destinations')")).scalar_one()
                is None
            )

        command.downgrade(config, "0002_api_keys")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0002_api_keys"
            )
            enabled = conn.execute(
                text("SELECT relrowsecurity FROM pg_class WHERE oid='public.events'::regclass")
            ).scalar_one()
            assert enabled is False
            policy_count = conn.execute(
                text("SELECT count(*) FROM pg_policies WHERE schemaname='public'")
            ).scalar_one()
            assert policy_count == 0

        # Seed a P05 policy before the P06 revision to verify migration backfill.
        command.upgrade(config, "0005_policy_engine_core")
        backfill_org = "99999999-9999-4999-8999-999999999999"
        backfill_member = "99999999-9999-4999-8999-999999999998"
        backfill_policy = "99999999-9999-4999-8999-999999999997"
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO organizations (id,name) VALUES (:id,'P06 backfill') "
                    "ON CONFLICT DO NOTHING"
                ),
                {"id": backfill_org},
            )
            conn.execute(
                text(
                    "INSERT INTO members (id,organization_id,auth_subject_id,role) "
                    "VALUES (:id,:org,'p06-backfill','owner') ON CONFLICT DO NOTHING"
                ),
                {"id": backfill_member, "org": backfill_org},
            )
            conn.execute(
                text(
                    "INSERT INTO dlp_policies "
                    "(id,org_id,name,enabled,priority,conditions,action,version,created_by) "
                    "VALUES (:id,:org,'Backfilled policy',true,42,"
                    "'{\"channel\":\"api\"}'::jsonb,'warn',3,:member)"
                ),
                {"id": backfill_policy, "org": backfill_org, "member": backfill_member},
            )

        command.upgrade(config, "head")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0017_cloud_storage_connectors"
            )
            provider_check = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname='ck_dlp_connectors_provider'"
                )
            ).scalar_one()
            assert "microsoft_onedrive" in provider_check
            assert "microsoft_sharepoint" in provider_check
            assert "aws_s3" in provider_check
            assert "google_cloud_storage" in provider_check
            audit_check = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname='ck_audit_events_action'"
                )
            ).scalar_one()
            assert "connector.microsoft_library_selected" in audit_check
            enabled = conn.execute(
                text("SELECT relrowsecurity FROM pg_class WHERE oid='public.events'::regclass")
            ).scalar_one()
            assert enabled is True
            idempotency_rls = conn.execute(
                text(
                    "SELECT relrowsecurity FROM pg_class "
                    "WHERE oid='public.dlp_scan_idempotency'::regclass"
                )
            ).scalar_one()
            assert idempotency_rls is True
            assert (
                conn.execute(
                    text(
                        "SELECT relrowsecurity FROM pg_class "
                        "WHERE oid='public.dlp_policies'::regclass"
                    )
                ).scalar_one()
                is True
            )
        command.downgrade(config, "0015_oauth_transactions")
        command.upgrade(config, "0016_microsoft_connectors")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0016_microsoft_connectors"
            )
            for table in ("dlp_policy_versions", "dlp_exceptions", "dlp_suppressions"):
                assert (
                    conn.execute(
                        text(
                            "SELECT relrowsecurity FROM pg_class WHERE oid=CAST(:table AS regclass)"
                        ),
                        {"table": f"public.{table}"},
                    ).scalar_one()
                    is True
                )
            snapshot = conn.execute(
                text("SELECT version,snapshot FROM dlp_policy_versions WHERE policy_id=:policy"),
                {"policy": backfill_policy},
            ).one()
            assert snapshot.version == 3
            assert snapshot.snapshot["name"] == "Backfilled policy"
        command.upgrade(config, "head")
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0017_cloud_storage_connectors"
            )
            connector_check = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname='ck_dlp_connectors_provider'"
                )
            ).scalar_one()
            assert "aws_s3" in connector_check
            assert "google_cloud_storage" in connector_check
            assert snapshot.snapshot["conditions"] == {"channel": "api"}
            assert (
                conn.execute(
                    text(
                        "SELECT relrowsecurity FROM pg_class "
                        "WHERE oid='public.dlp_destinations'::regclass"
                    )
                ).scalar_one()
                is True
            )
    finally:
        engine.dispose()
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.exec_driver_sql(f'DROP DATABASE "{scratch_database}"')
        admin_engine.dispose()
