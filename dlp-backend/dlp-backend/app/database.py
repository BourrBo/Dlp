from functools import lru_cache

from supabase import Client, create_client

from app.config import get_settings


@lru_cache
def get_supabase() -> Client:
    """
    Service-role client for backend use. Frontend talks to Supabase directly
    with the anon key + RLS, same split as SecureFlow.
    """
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_role_key:
        raise RuntimeError(
            "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set. "
            "Copy .env.example to .env and fill in the project's Supabase credentials."
        )
    return create_client(settings.supabase_url, settings.supabase_service_role_key)
