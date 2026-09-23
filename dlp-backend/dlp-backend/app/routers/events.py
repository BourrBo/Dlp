from uuid import UUID

from fastapi import APIRouter, Query

from app.database import get_supabase

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("")
def list_events(org_id: UUID, limit: int = Query(default=50, le=200)):
    supabase = get_supabase()
    result = (
        supabase.table("dlp_events")
        .select("*")
        .eq("org_id", str(org_id))
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return result.data
