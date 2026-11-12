"""Alembic environment; DATABASE_URL is read from the process environment."""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

database_url = os.environ.get("DATABASE_URL")
configured_url = config.get_main_option("sqlalchemy.url")
# The process environment supplies the URL for the normal CLI configuration.
# A caller that explicitly sets `sqlalchemy.url` (such as an isolated migration
# test database) takes precedence so a test or maintenance command cannot be
# silently redirected by an unrelated process-level URL.
if database_url and configured_url in {None, "", "sqlite:///./dlp-dev.db"}:
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
