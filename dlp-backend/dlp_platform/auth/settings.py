"""Environment-backed authentication settings with explicit database selection."""

import os
from dataclasses import dataclass


class DatabaseConfigurationError(ValueError):
    """Database configuration is absent or incompatible with the selected mode."""


_ENVIRONMENTS = {"development", "unit-test", "integration-test", "production"}


@dataclass(frozen=True)
class AuthSettings:
    database_url: str
    supabase_url: str | None
    jwt_secret: str | None
    jwks_url: str | None
    jwt_issuer: str | None
    jwt_audience: str
    jwt_leeway_seconds: int
    sso_token_secret: str | None = None
    sso_token_issuer: str = "dlp-sso"
    sso_token_audience: str = "dlp-api"

    @classmethod
    def from_env(cls) -> "AuthSettings":
        environment = os.getenv("APP_ENV", "").strip().lower()
        if environment not in _ENVIRONMENTS:
            raise DatabaseConfigurationError(
                "APP_ENV is required and must name a supported environment"
            )
        database_url = os.getenv("DATABASE_URL", "").strip()
        if not database_url:
            raise DatabaseConfigurationError(
                "DATABASE_URL is required; select SQLite explicitly for development or tests"
            )
        is_postgres = database_url.startswith(("postgresql://", "postgresql+psycopg://"))
        is_sqlite = database_url.startswith("sqlite:")
        if environment in {"production", "integration-test"} and not is_postgres:
            raise DatabaseConfigurationError(
                f"{environment} requires a PostgreSQL DATABASE_URL for tenant RLS"
            )
        if is_sqlite and environment not in {"development", "unit-test"}:
            raise DatabaseConfigurationError(
                "SQLite is permitted only when explicitly selected in development or unit-test mode"
            )
        if not (is_postgres or is_sqlite):
            raise DatabaseConfigurationError("DATABASE_URL must use PostgreSQL or explicit SQLite")
        supabase_url = os.getenv("SUPABASE_URL") or None
        jwt_secret = os.getenv("SUPABASE_JWT_SECRET") or None
        jwks_url = os.getenv("SUPABASE_JWKS_URL") or None
        issuer = os.getenv("JWT_ISSUER")
        if issuer is None and supabase_url:
            issuer = f"{supabase_url.rstrip('/')}/auth/v1"
        return cls(
            database_url=database_url,
            supabase_url=supabase_url,
            jwt_secret=jwt_secret,
            jwks_url=jwks_url,
            jwt_issuer=issuer,
            jwt_audience=os.getenv("JWT_AUDIENCE", "authenticated"),
            jwt_leeway_seconds=max(0, min(int(os.getenv("JWT_LEEWAY_SECONDS", "30")), 120)),
            sso_token_secret=os.getenv("DLP_SSO_TOKEN_SECRET") or None,
            sso_token_issuer=os.getenv("DLP_SSO_TOKEN_ISSUER", "dlp-sso"),
            sso_token_audience=os.getenv("DLP_SSO_TOKEN_AUDIENCE", "dlp-api"),
        )
