"""
Deprecated: policy CRUD is handled by the Lovable dashboard's Policies page,
which reads/writes dlp_policies directly against Supabase under RLS. The
backend still reads policies for /api/scan's decisions (see
app/services/policy_engine.py), via the console's dlp-get-policy route —
it just doesn't need its own CRUD surface for the dashboard to use.
Kept as a stub so the import doesn't break anything that still references
this module.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/policies", tags=["policies"])
