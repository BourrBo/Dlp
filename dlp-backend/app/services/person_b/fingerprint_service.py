"""
Document fingerprinting — Stage 4 of the detection pipeline.

Uses ssdeep (context-triggered piecewise hashing / fuzzy hashing) so a
confidential document is still caught if it's renamed or lightly edited
before upload — something exact hashing (sha256) would miss entirely.

Reference fingerprints are stored per-org in dlp_classifications with
pattern_type='fingerprint'. This stage only runs when ScanRequest.filename
is set (a whole-file upload) — fingerprinting a short clipboard paste
doesn't carry the same meaning as fingerprinting a document.

Install (needs the libfuzzy C library):
    apt-get install -y libfuzzy-dev   # or brew install ssdeep on macOS
    pip install ssdeep
"""

import logging
from uuid import UUID

from app.database import get_supabase
from app.models.finding import DataType, Finding
from app.services.person_b.rule_cache import cached

logger = logging.getLogger(__name__)

_MATCH_THRESHOLD = 70  # ssdeep similarity score (0-100) treated as a match


def _ssdeep():
    try:
        import ssdeep
    except ImportError:
        logger.warning(
            "ssdeep not installed — document fingerprint matching disabled. "
            "Install libfuzzy-dev, then `pip install ssdeep`."
        )
        return None
    return ssdeep


def compute_fingerprint(content: str) -> str | None:
    ssdeep = _ssdeep()
    if ssdeep is None:
        return None
    return ssdeep.hash(content.encode("utf-8", errors="ignore"))


def _load_org_fingerprints(org_id: UUID) -> list[tuple[UUID, str, str, str]]:
    """(rule_id, label, fingerprint, sensitivity_level) for this org's reference docs."""
    supabase = get_supabase()
    result = (
        supabase.table("dlp_classifications")
        .select("id,label,pattern_value,sensitivity_level")
        .eq("org_id", str(org_id))
        .eq("pattern_type", "fingerprint")
        .execute()
    )
    return [
        (UUID(row["id"]), row["label"], row["pattern_value"], row["sensitivity_level"])
        for row in (result.data or [])
    ]


def detect(content: str, org_id: UUID, filename: str | None = None) -> list[Finding]:
    if not filename:
        return []  # only whole-document uploads are fingerprint-checked

    ssdeep = _ssdeep()
    if ssdeep is None:
        return []

    incoming_hash = compute_fingerprint(content)
    if not incoming_hash:
        return []

    references = cached("fingerprint", str(org_id), lambda: _load_org_fingerprints(org_id))
    findings: list[Finding] = []
    for rule_id, label, reference_hash, sensitivity_level in references:
        try:
            score = ssdeep.compare(incoming_hash, reference_hash)
        except ssdeep.InternalError:
            continue  # hashes too structurally different to compare — not a match
        if score >= _MATCH_THRESHOLD:
            findings.append(
                Finding(
                    data_type=DataType.DOCUMENT_MATCH,
                    confidence=round(score / 100, 2),
                    matched_snippet=f"[{filename}]",
                    sensitivity_level=sensitivity_level,
                    matched_rule_id=rule_id,
                    label=f"Fingerprint match: {label} ({score}% similar)",
                )
            )
    return findings


def register_reference_document(
    org_id: UUID, label: str, content: str, sensitivity_level: str = "confidential"
) -> UUID | None:
    """Utility for an onboarding/admin flow to add a known-sensitive reference document."""
    fingerprint = compute_fingerprint(content)
    if not fingerprint:
        return None
    supabase = get_supabase()
    result = (
        supabase.table("dlp_classifications")
        .insert(
            {
                "org_id": str(org_id),
                "label": label,
                "pattern_type": "fingerprint",
                "pattern_value": fingerprint,
                "sensitivity_level": sensitivity_level,
            }
        )
        .execute()
    )
    from app.services.person_b.rule_cache import invalidate

    invalidate("fingerprint", str(org_id))
    return UUID(result.data[0]["id"]) if result.data else None
