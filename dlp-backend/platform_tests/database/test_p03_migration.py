"""P03 migration must fail closed on dialects without Supabase RLS."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


def test_postgresql_rls_migration_refuses_sqlite(tmp_path: Path) -> None:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{(tmp_path / 'migration.db').as_posix()}")
    with pytest.raises(RuntimeError, match="requires PostgreSQL"):
        command.upgrade(config, "head")


def test_postgresql_migration_generates_offline_sql(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://dlp:example@localhost/dlp")
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", "postgresql+psycopg://dlp:example@localhost/dlp")
    command.upgrade(config, "head", sql=True)


def test_postgresql_migration_downgrade_generates_offline_sql(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://dlp:example@localhost/dlp")
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", "postgresql+psycopg://dlp:example@localhost/dlp")
    command.downgrade(config, "0003_tenant_rls:0002_api_keys", sql=True)
