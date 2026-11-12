"""PAN: AAAPL1234C structure with valid 4th-character holder category."""
from __future__ import annotations

import re
from typing import List

from ...models import Hit, Severity
from ..base import Detector
from .common import analyse, clamp

# 4th char: A=AOP, B=BOI, C=Company, F=Firm/LLP, G=Govt, H=HUF, J=Artificial
# juridical person, K=Krish, L=Local authority, P=Person, T=Trust
PAN_CATEGORIES = "ABCFGHJKLPT"
PAN_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z]{3})([%s])([A-Za-z])(\d{4})([A-Za-z])(?![A-Za-z0-9_])"
    % PAN_CATEGORIES,
    re.IGNORECASE,
)


class PanDetector(Detector):
    rule_id = "india.pan"
    category = "india_pii"
    description = "Permanent Account Number (structure + category)"
    base_severity = Severity.HIGH

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        for m in PAN_RE.finditer(text):
            value = m.group(0)
            ctx = analyse("pan", text, m.start(), m.end(), hint)
            if ctx.datetime:
                continue
            reasons = ["AAAAA9999A structure", "valid holder-category character"]
            if ctx.labeled:
                conf = 0.95
                reasons.append("PAN / tax-ID label in context")
            else:
                if value != value.upper():
                    continue  # lowercase PAN-shaped strings need a label
                conf = 0.55
                reasons.append("no label: structure-only evidence")
                if ctx.reference:
                    conf -= 0.25
                    reasons.append("reference/ID-style context")
            hits.append(Hit(self.rule_id, m.start(), m.end(), value.upper(), clamp(conf), reasons))
        return hits

    def redact(self, value: str) -> str:
        return value[:2] + "X" * (len(value) - 3) + value[-1]
