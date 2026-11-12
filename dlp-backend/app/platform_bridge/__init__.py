"""Bridge between the main backend and the vendored P2 platform (``dlp_platform``).

The platform is optional and enabled by setting ``PLATFORM_DATABASE_URL``. When
enabled it is mounted at ``/platform`` (API keys, policies, destinations,
exceptions, approvals, connectors, vault, SSO/SCIM, audit, public API) and its
scan pipeline is wired to this backend's extractors, detectors and alerting.
"""

import logging
import os

from fastapi import FastAPI

from app.config import get_settings

logger = logging.getLogger(__name__)


def platform_enabled() -> bool:
    return bool(get_settings().platform_database_url)


def export_platform_environment() -> None:
    """The platform reads plain environment variables; mirror our settings."""
    s = get_settings()
    values = {
        "DATABASE_URL": s.platform_database_url,
        "APP_ENV": s.app_env if s.app_env in {"development", "unit-test", "integration-test", "production"} else "production",
        "SUPABASE_URL": s.supabase_url,
        "SUPABASE_JWT_SECRET": s.supabase_jwt_secret,
        "SUPABASE_JWKS_URL": s.supabase_jwks_url,
    }
    for key, value in values.items():
        if value:
            os.environ[key] = value


def mount_platform(app: FastAPI) -> bool:
    """Mount the platform sub-application; returns False when it is disabled."""
    if not platform_enabled():
        logger.info("Platform is disabled (PLATFORM_DATABASE_URL is not set)")
        return False
    export_platform_environment()
    from dlp_platform.main import app as platform_app

    from app.platform_bridge.pipeline import install_pipeline

    install_pipeline()
    app.mount("/platform", platform_app)
    return True
