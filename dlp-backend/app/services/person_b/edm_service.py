"""
Exact Data Match (EDM) — Stage 3 of the detection pipeline.

Compares content against an org's known-sensitive records (e.g. an exported
list of customer SSNs or emails) without ever storing those records in
plaintext: only a SHA-256 hash of each known value is kept, in
dlp_classifications with pattern_type='edm'. At scan time we extract
candidate tokens from the content (emails, long digit runs), hash each
candidate the same way, and check for a match. The raw sensitive dataset
never needs to live in this service or its database.

Seed EDM rules with hash_value() below — never insert a raw value into
dlp_classifications.pattern_value.
"""

import hashlib
import re
from uuid import UUID

from app.database import get_supabase
from app.models.finding import DataType, Finding
from app.services.person_b.rule_cache import cached
from app.services.person_b.text_utils import redact

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DIGIT_RUN_RE = re.compile(r"\b\d{6,16}\b")

_EDM_CONFIDENCE = 0.97  # exact match — the highest-confidence signal in the pipeline


def hash_value(value: str) -> str:
    """Normalize + hash a known-sensitive value before storing it as an EDM rule."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _candidates(content: str) -> set[str]:
    found = set(_EMAIL_RE.findall(content)) | set(_DIGIT_RUN_RE.findall(content))
    return {c.strip().lower() for c in found}


def _load_edm_rules(org_id: UUID) -> dict[str, tuple[UUID, str, str]]:
    """hash -> (rule_id, label, sensitivity_level) for this org's EDM rules."""
    supabase = get_supabase()
    result = (
        supabase.table("dlp_classifications")
        .select("id,label,pattern_value,sensitivity_level")
        .eq("org_id", str(org_id))
        .eq("pattern_type", "edm")
        .execute()
    )
    return {
        row["pattern_value"]: (UUID(row["id"]), row["label"], row["sensitivity_level"])
        for row in (result.data or [])
    }


def detect(content: str, org_id: UUID) -> list[Finding]:
    rules = cached("edm", str(org_id), lambda: _load_edm_rules(org_id))
    if not rules:
        return []

    findings: list[Finding] = []
    for candidate in _candidates(content):
        hit = rules.get(hash_value(candidate))
        if hit is None:
            continue
        rule_id, label, sensitivity_level = hit
        findings.append(
            Finding(
                data_type=DataType.CUSTOM,
                confidence=_EDM_CONFIDENCE,
                matched_snippet=redact(candidate),
                sensitivity_level=sensitivity_level,
                matched_rule_id=rule_id,
                label=f"EDM: {label}",
            )
        )
    return findings


def register_known_value(org_id: UUID, label: str, value: str, sensitivity_level: str = "confidential") -> UUID | None:
    """Utility for an onboarding/admin flow to seed a known-sensitive value (hashed, never raw)."""
    supabase = get_supabase()
    result = (
        supabase.table("dlp_classifications")
        .insert(
            {
                "org_id": str(org_id),
                "label": label,
                "pattern_type": "edm",
                "pattern_value": hash_value(value),
                "sensitivity_level": sensitivity_level,
            }
        )
        .execute()
    )
    from app.services.person_b.rule_cache import invalidate

    invalidate("edm", str(org_id))
    return UUID(result.data[0]["id"]) if result.data else None
