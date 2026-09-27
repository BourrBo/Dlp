"""
Deprecated: event listing is handled by the Lovable dashboard, which reads
dlp_events directly from Supabase under the signed-in user's own RLS policy.
This backend has no service-role access to Supabase (see app/database.py),
so it has no privileged read path to duplicate that here. Kept as a stub
so the import doesn't break anything that still references this module.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/events", tags=["events"])
