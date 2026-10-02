"""
Classification rule management — Person B's module.

Minimal admin surface so the EDM and fingerprint detectors have a way to be
seeded: register a known-sensitive value (hashed) or reference document
(fingerprinted) for an org. Custom regex rules are just inserted directly
into dlp_classifications (pattern_type='regex') by whoever builds the
policy-editor UI — no hashing/fingerprinting step needed for those, so no
endpoint is duplicated here for them.

This administrative surface requires a separate shared key. Keep the key
server-side; user-facing authorization should move to verified user tokens
and organization membership when the platform auth work is ready.
"""

import secrets
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app.config import get_settings
from app.services.person_b import edm_service, fingerprint_service


def require_admin_key(
    supplied: Annotated[str | None, Header(alias="X-DLP-Admin-Key")] = None,
) -> None:
    expected = get_settings().dlp_admin_api_key
    if not expected:
        raise HTTPException(status_code=503, detail="Classification admin API is disabled")
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid admin key")


router = APIRouter(
    prefix="/api/classifications",
    tags=["classifications"],
    dependencies=[Depends(require_admin_key)],
)


class RegisterEdmRequest(BaseModel):
    org_id: UUID
    label: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=1, max_length=4096)  # hashed before storage
    sensitivity_level: Literal["public", "internal", "confidential", "restricted"] = "confidential"


class RegisterFingerprintRequest(BaseModel):
    org_id: UUID
    label: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=262144)
    sensitivity_level: Literal["public", "internal", "confidential", "restricted"] = "confidential"


class RegisterResponse(BaseModel):
    id: UUID


@router.post("/edm", response_model=RegisterResponse)
def register_edm(request: RegisterEdmRequest) -> RegisterResponse:
    rule_id = edm_service.register_known_value(
        request.org_id, request.label, request.value, request.sensitivity_level
    )
    if rule_id is None:
        raise HTTPException(status_code=500, detail="Failed to register EDM rule")
    return RegisterResponse(id=rule_id)


@router.post("/fingerprint", response_model=RegisterResponse)
def register_fingerprint(request: RegisterFingerprintRequest) -> RegisterResponse:
    rule_id = fingerprint_service.register_reference_document(
        request.org_id, request.label, request.content, request.sensitivity_level
    )
    if rule_id is None:
        raise HTTPException(
            status_code=503,
            detail="ssdeep not installed on this server — cannot fingerprint documents",
        )
    return RegisterResponse(id=rule_id)
