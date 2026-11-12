"""P02 migration adds only the API-key table and rolls back independently."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_api_key_migration_adds_required_fields_and_downgrades(tmp_path: Path) -> None:
    database_path = (tmp_path / "p02.sqlite3").as_posix()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    command.upgrade(config, "0001_baseline")
    command.upgrade(config, "0002_api_keys")

    engine = create_engine(f"sqlite:///{database_path}")
    inspector = inspect(engine)
    assert "dlp_api_keys" in inspector.get_table_names()
    assert {
        "id",
        "org_id",
        "name",
        "prefix",
        "key_hash",
        "scopes",
        "created_by",
        "created_at",
        "last_used_at",
        "revoked_at",
    } <= {column["name"] for column in inspector.get_columns("dlp_api_keys")}
    assert {"ix_dlp_api_keys_prefix", "ix_dlp_api_keys_org_id"} <= {
        index["name"] for index in inspector.get_indexes("dlp_api_keys")
    }
    assert inspector.get_foreign_keys("dlp_api_keys")
    engine.dispose()

    command.downgrade(config, "0001_baseline")
    engine = create_engine(f"sqlite:///{database_path}")
    assert "dlp_api_keys" not in inspect(engine).get_table_names()
    assert "organizations" in inspect(engine).get_table_names()
    engine.dispose()
