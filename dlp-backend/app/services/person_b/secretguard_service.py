"""Adapter from the Secret Guard engine (secrets, entropy, Indian identifiers)
to the backend's normalized ``Finding`` shape.

Secret Guard emits redacted evidence only, so nothing raw reaches the API.
"""

import logging
from functools import lru_cache

from app.models.finding import DataType, Finding

logger = logging.getLogger(__name__)

_TYPE_BY_RULE = {
    "secret": DataType.API_KEY,
    "india.aadhaar": DataType.NATIONAL_ID,
    "india.pan": DataType.NATIONAL_ID,
    "india.gstin": DataType.NATIONAL_ID,
    "india.mobile": DataType.PHONE_NUMBER,
}
_LABELS = {
    "secret": "Secret / credential",
    "india.aadhaar": "Aadhaar number",
    "india.pan": "PAN",
    "india.gstin": "GSTIN",
    "india.ifsc": "IFSC code",
    "india.bank_account": "Bank account number",
    "india.upi": "UPI ID",
    "india.mobile": "Indian mobile number",
}
_SENSITIVITY = {"CRITICAL": "restricted", "HIGH": "restricted", "MEDIUM": "confidential"}


@lru_cache(maxsize=1)
def _scanner():
    from secretguard.detectors import default_detectors
    from secretguard.scanner import Scanner

    return Scanner(default_detectors())


def _data_type(rule_id: str) -> DataType:
    if rule_id.startswith("secret"):
        return DataType.API_KEY
    return _TYPE_BY_RULE.get(rule_id, DataType.CUSTOM)


def _label(rule_id: str) -> str:
    if rule_id.startswith("secret."):
        return "Secret: " + rule_id.split(".", 1)[1].replace("_", " ")
    return _LABELS.get(rule_id, rule_id)


def _offset(lines: list[str], line: int, column: int) -> int:
    return sum(len(x) + 1 for x in lines[: max(line - 1, 0)]) + max(column - 1, 0)


def detect(content: str, filename: str | None = None) -> list[Finding]:
    try:
        sg_findings = _scanner().scan_text(content, name=filename or "<text>")
    except Exception:  # detection must never take the scan path down
        logger.exception("Secret Guard scan failed")
        return []
    lines = content.split("\n")
    results: list[Finding] = []
    for f in sg_findings:
        start = _offset(lines, f.line, f.column)
        results.append(
            Finding(
                data_type=_data_type(f.rule_id),
                confidence=min(max(float(f.confidence), 0.0), 1.0),
                matched_snippet=f.evidence,
                sensitivity_level=_SENSITIVITY.get(f.severity.name, "internal"),
                label=_label(f.rule_id),
                start=start,
                end=start + max(len(f.evidence), 1),
            )
        )
    return results
