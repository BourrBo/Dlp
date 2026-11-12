"""Database selection fails closed outside explicit SQLite development/unit modes."""

import pytest

from dlp_platform.auth.settings import AuthSettings, DatabaseConfigurationError


def test_missing_environment_fails_explicitly(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./dlp-dev.db")
    with pytest.raises(DatabaseConfigurationError, match="APP_ENV is required"):
        AuthSettings.from_env()


def test_production_without_database_url_fails_explicitly(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(DatabaseConfigurationError, match="DATABASE_URL is required"):
        AuthSettings.from_env()


def test_production_cannot_use_sqlite_as_a_fallback_or_explicit_database(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./dlp-dev.db")
    with pytest.raises(DatabaseConfigurationError, match="requires a PostgreSQL"):
        AuthSettings.from_env()


def test_unit_test_must_explicitly_select_sqlite(monkeypatch):
    monkeypatch.setenv("APP_ENV", "unit-test")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./dlp-test.db")
    assert AuthSettings.from_env().database_url == "sqlite:///./dlp-test.db"


def test_unit_test_without_explicit_database_url_does_not_fallback(monkeypatch):
    monkeypatch.setenv("APP_ENV", "unit-test")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(DatabaseConfigurationError, match="DATABASE_URL is required"):
        AuthSettings.from_env()


def test_integration_test_accepts_the_explicit_postgres_test_url(monkeypatch):
    monkeypatch.setenv("APP_ENV", "integration-test")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test:test@127.0.0.1:5432/dlp_test")
    assert AuthSettings.from_env().database_url.startswith("postgresql+psycopg://")


def test_integration_test_rejects_sqlite_even_when_explicit(monkeypatch):
    monkeypatch.setenv("APP_ENV", "integration-test")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./dlp-test.db")
    with pytest.raises(DatabaseConfigurationError, match="requires a PostgreSQL"):
        AuthSettings.from_env()
