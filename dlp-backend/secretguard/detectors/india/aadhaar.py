"""Aadhaar: 12 digits, first digit 2-9, Verhoeff checksum, degenerate-pattern
and timestamp exclusions, label-driven confidence."""
from __future__ import annotations

import re
from typing import List

from ...models import Hit, Severity
from ..base import Detector
from . import verhoeff
from .common import (AADHAAR_WEAK_LABEL, all_same, analyse, clamp,
                     is_repeating_block, longest_run, looks_like_timestamp)

AADHAAR_RE = re.compile(
    r"(?<![\w.])(?<!\d[\s-])([2-9]\d{3})([\s-]?)(\d{4})\2(\d{4})(?!\w|[.,]\d|[\s-]\d)"
)


class AadhaarDetector(Detector):
    rule_id = "india.aadhaar"
    category = "india_pii"
    description = "Aadhaar number (Verhoeff-validated)"
    base_severity = Severity.CRITICAL

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        for m in AADHAAR_RE.finditer(text):
            digits = m.group(1) + m.group(3) + m.group(4)
            if not verhoeff.is_valid(digits):
                continue
            if all_same(digits) or is_repeating_block(digits) or longest_run(digits) >= 6:
                continue
            reasons = ["12 digits, first digit 2-9", "Verhoeff checksum valid"]

            ctx = analyse("aadhaar", text, m.start(), m.end(), hint)
            tier = "strong" if ctx.labeled else None
            if not ctx.labeled:
                weak = analyse("aadhaar", text, m.start(), m.end(), hint, own=AADHAAR_WEAK_LABEL)
                if weak.labeled:
                    ctx, tier = weak, "weak"
            if ctx.datetime:
                continue
            if tier is None and looks_like_timestamp(digits):
                continue

            grouped = bool(m.group(2))
            if tier == "strong":
                conf = 0.95
                reasons.append("Aadhaar label in context")
            elif tier == "weak":
                conf = 0.75
                reasons.append("UID label in context")
            else:
                conf = 0.60 if grouped else 0.45
                reasons.append("no label: checksum-only evidence")
                if grouped:
                    reasons.append("4-4-4 grouping")
                if ctx.reference:
                    conf -= 0.25
                    reasons.append("reference/ID-style context")
            hits.append(Hit(self.rule_id, m.start(), m.end(), digits, clamp(conf), reasons))
        return hits

    def redact(self, value: str) -> str:
        return "XXXX XXXX " + value[-4:]
