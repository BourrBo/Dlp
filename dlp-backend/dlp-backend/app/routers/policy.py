from uuid import UUID

from fastapi import APIRouter

from app.database import get_supabase
from app.models.policy import Policy

router = APIRouter(prefix="/api/policies", tags=["policies"])


@router.get("")
def list_policies(org_id: UUID):
    supabase = get_supabase()
    result = supabase.table("dlp_policies").select("*").eq("org_id", str(org_id)).execute()
    return result.data


@router.post("")
def create_policy(policy: Policy):
    supabase = get_supabase()
    supabase.table("dlp_policies").insert(policy.model_dump(mode="json")).execute()
    return policy
