from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    supabase_url: str = ""
    supabase_publishable_key: str = ""
    supabase_service_role_key: str = ""

    app_env: str = "development"
    # Optional platform (P2) integration; enabled when a database URL is given.
    platform_database_url: str = ""
    supabase_jwt_secret: str = ""
    supabase_jwks_url: str = ""
    allowed_origins: str = "http://localhost:5173"

    google_oauth_client_id: str = ""
    google_oauth_client_secret: str = ""

    slack_webhook_url: str = ""
    dlp_admin_api_key: str = ""
    gcp_project_id: str = ""
    gmail_pubsub_subscription_id: str = ""
    dlp_backend_base_url: str = "http://127.0.0.1:8000"
    scan_jobs_db_path: str = "./data/scan-jobs.sqlite3"
    scan_jobs_encryption_key: str = ""
    scan_jobs_previous_encryption_keys: str = ""
    github_webhook_secret: str = ""
    devices_db_path: str = "./data/devices.sqlite3"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
