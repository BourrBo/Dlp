from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    supabase_url: str = ""
    supabase_service_role_key: str = ""
    supabase_anon_key: str = ""

    app_env: str = "development"
    allowed_origins: str = "http://localhost:5173"

    google_oauth_client_id: str = ""
    google_oauth_client_secret: str = ""

    slack_webhook_url: str = ""

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
