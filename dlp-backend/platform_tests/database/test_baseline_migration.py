from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_baseline_migration_applies_and_reverts_on_empty_database(tmp_path: Path) -> None:
    database_path = (tmp_path / "baseline.sqlite3").as_posix()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")

    command.upgrade(config, "0001_baseline")
    engine = create_engine(f"sqlite:///{database_path}")
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {
        "alembic_version",
        "organizations",
        "members",
        "channels",
        "events",
    }
    event_columns = {column["name"] for column in inspector.get_columns("events")}
    assert "raw_content" not in event_columns
    assert "request_body" not in event_columns
    assert {"organization_id", "request_id", "decision"} <= event_columns
    engine.dispose()

    command.downgrade(config, "base")
    engine = create_engine(f"sqlite:///{database_path}")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    engine.dispose()
