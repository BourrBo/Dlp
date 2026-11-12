"""Database session provider; schema changes are applied only through Alembic."""

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from dlp_platform.auth.settings import AuthSettings


@lru_cache(maxsize=4)
def _session_factory(database_url: str) -> sessionmaker[Session]:
    engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    factory = _session_factory(AuthSettings.from_env().database_url)
    with factory() as session:
        yield session
