"""
Console client — talks to the secured routes Lovable built into the
dashboard app (src/routes/api/public/dlp-scan-event.ts and
dlp-get-policy.ts), instead of connecting to Supabase directly.

Why: Lovable Cloud projects don't expose their service-role key outside
Lovable's own UI, so a direct supabase-py client with service-role access
isn't possible from this external service. These two routes run inside
the Lovable app (which does have full DB access) and are gated by a
shared secret (DLP_BACKEND_SECRET) instead.
"""

import httpx

from app.config import get_settings


def _headers() -> dict:
    settings = get_settings()
    if not settings.dlp_console_base_url or not settings.dlp_backend_secret:
        raise RuntimeError(
            "DLP_CONSOLE_BASE_URL / DLP_BACKEND_SECRET not set. "
            "Set these in .env to the Lovable app's URL and the secret you "
            "saved in Project Settings -> Secrets."
        )
    return {"x-dlp-secret": settings.dlp_backend_secret, "Content-Type": "application/json"}


def post_scan_event(event: dict) -> dict:
    settings = get_settings()
    url = f"{settings.dlp_console_base_url}/api/public/dlp-scan-event"
    resp = httpx.post(url, json=event, headers=_headers(), timeout=10.0)
    resp.raise_for_status()
    return resp.json()


def get_policy(org_id: str, data_type: str, channel: str) -> dict | None:
    settings = get_settings()
    url = f"{settings.dlp_console_base_url}/api/public/dlp-get-policy"
    resp = httpx.get(
        url,
        params={"org_id": org_id, "data_type": data_type, "channel": channel},
        headers=_headers(),
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()  # null (-> None) if no match, per the route's contract
