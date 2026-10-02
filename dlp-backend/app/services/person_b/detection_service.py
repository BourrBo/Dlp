"""
Detection Engine — Person B's module.

Orchestrates the full detection pipeline in ascending cost order, so cheap
checks short-circuit expensive ones:

  Stage 1 — built-in regex (credit card, API key, email — always runs)
  Stage 1b — org's custom regex rules (dlp_classifications, pattern_type='regex')
  Stage 2 — Presidio/spaCy NER for unstructured PII (names, addresses, phones)
  Stage 3 — EDM: hashed exact-match against the org's known-sensitive records
  Stage 4 — ssdeep document fingerprinting (whole-file uploads only)

Public contract the Policy Engine and routers depend on: detect(content,
org_id, filename) -> list[Finding]. org_id is optional so ad-hoc/test calls
still get the built-in regex baseline; every org-scoped stage (custom
rules, EDM, fingerprinting) is skipped without it, since there is no org to
scope them to.
"""

import logging
import re
from uuid import UUID

from app.database import get_supabase
from app.models.finding import DataType, Finding
from app.services.person_b import edm_service, fingerprint_service, ner_service
from app.services.person_b.rule_cache import cached
from app.services.person_b.text_utils import redact as _redact  # kept as _redact — do not remove

logger = logging.getLogger(__name__)

_PATTERNS: list[tuple[DataType, re.Pattern, float]] = [
    (DataType.CREDIT_CARD, re.compile(r"\b(?:\d[ -]*?){13,16}\b"), 0.85),
    (
        DataType.API_KEY,
        re.compile(r"\b(sk|pk|api|key|token)[_-][A-Za-z0-9]{16,}\b", re.IGNORECASE),
        0.9,
    ),
    (
        DataType.EMAIL_PII,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.6,
    ),
]

# Content already carrying a finding at or above this confidence is treated
# as "clearly sensitive" for short pastes — Stage 2 (NER) is skipped to keep
# the common case (someone pastes a card number) fast, since a slower NER
# pass wouldn't change the outcome. Longer content always gets the full
# pipeline, since it's more likely to carry unstructured PII the regex
# stage can't see.
_BLOCK_TIER_CONFIDENCE = 0.85
_ALWAYS_RUN_NER_ABOVE_CHARS = 500


def detect(content: str, org_id: UUID | None = None, filename: str | None = None) -> list[Finding]:
    findings = _detect_builtin_regex(content)

    if org_id is not None:
        findings += _detect_custom_regex(content, org_id)

    already_high_confidence = any(f.confidence >= _BLOCK_TIER_CONFIDENCE for f in findings)
    if not already_high_confidence or len(content) > _ALWAYS_RUN_NER_ABOVE_CHARS:
        findings += ner_service.detect(content)

    if org_id is not None:
        findings += edm_service.detect(content, org_id)
        findings += fingerprint_service.detect(content, org_id, filename)

    return findings


def _detect_builtin_regex(content: str) -> list[Finding]:
    findings: list[Finding] = []
    for data_type, pattern, confidence in _PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                Finding(
                    data_type=data_type,
                    confidence=confidence,
                    matched_snippet=_redact(match.group(0)),
                )
            )
    return findings


def _detect_custom_regex(content: str, org_id: UUID) -> list[Finding]:
    rules = cached("custom_regex", str(org_id), lambda: _load_custom_regex_rules(org_id))
    findings: list[Finding] = []
    for rule_id, label, pattern, sensitivity_level in rules:
        for match in pattern.finditer(content):
            findings.append(
                Finding(
                    data_type=DataType.CUSTOM,
                    confidence=0.8,
                    matched_snippet=_redact(match.group(0)),
                    sensitivity_level=sensitivity_level,
                    matched_rule_id=rule_id,
                    label=label,
                )
            )
    return findings


def _load_custom_regex_rules(org_id: UUID) -> list[tuple[UUID, str, re.Pattern, str]]:
    supabase = get_supabase()
    result = (
        supabase.table("dlp_classifications")
        .select("id,label,pattern_value,sensitivity_level")
        .eq("org_id", str(org_id))
        .eq("pattern_type", "regex")
        .execute()
    )
    rules: list[tuple[UUID, str, re.Pattern, str]] = []
    for row in result.data or []:
        try:
            pattern = re.compile(row["pattern_value"], re.IGNORECASE)
        except re.error:
            logger.warning("Skipping invalid regex rule %s for org %s", row["id"], org_id)
            continue
        rules.append((UUID(row["id"]), row["label"], pattern, row["sensitivity_level"]))
    return rules
