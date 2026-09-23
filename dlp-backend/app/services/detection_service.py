"""
Detection Engine — Person B's module.

Ships with working regex detectors so the backend is runnable end-to-end
from day one. Extend detect() with:
  - Presidio/NER for person names, addresses (unstructured PII)
  - Exact Data Match against a known-records table (customer/employee CSV)
  - Document fingerprinting (ssdeep) for whole-document matches

Keep the public contract stable: detect(content) -> list[Finding]. The
Policy Engine and routers depend only on this signature.
"""

import re

from app.models.finding import DataType, Finding

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


def detect(content: str) -> list[Finding]:
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


def _redact(value: str) -> str:
    """Never persist the raw match — store enough to triage, not to exfiltrate."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
