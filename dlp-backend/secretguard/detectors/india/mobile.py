"""Indian mobile numbers: 10 digits starting 6-9, optional +91 / 0091 / 0 prefix."""
from __future__ import annotations

import re
from typing import List

from ...models import Hit, Severity
from ..base import Detector
from .common import (all_same, analyse, clamp, digits_only, is_repeating_block,
                     longest_run, looks_like_timestamp)

MOBILE_RE = re.compile(
    r"(?<![\w.])(?<!\d[\s-])((?:\+|00)91[\s-]?|91[\s-]|0)?([6-9]\d{4}[\s-]?\d{5})(?!\w|[.,]\d)"
)
# 12 solid digits "91XXXXXXXXXX": accepted only with an explicit phone label
MOBILE_CC_RE = re.compile(r"(?<![\w.])(?<!\d[\s-])91([6-9]\d{9})(?!\w|[.,]\d)")


class MobileDetector(Detector):
    rule_id = "india.mobile"
    category = "india_pii"
    description = "Indian mobile number (confidence driven by phone context)"
    base_severity = Severity.MEDIUM

    def _score(self, number: str, has_cc: bool, ctx, solid_cc: bool = False):
        if all_same(number) or is_repeating_block(number):
            return None
        sequential = longest_run(number) >= 7
        reasons = ["10 digits starting 6-9"]
        if ctx.labeled:
            conf = 0.90 + (0.05 if has_cc else 0.0)
            reasons.append("phone/mobile label in context")
            if sequential:
                conf = 0.60
                reasons.append("sequential digits")
        else:
            if solid_cc or sequential or looks_like_timestamp(number):
                return None
            conf = 0.40 + (0.25 if has_cc else 0.0)
            reasons.append("no phone label: lower confidence")
            if ctx.reference:
                conf -= 0.25
                reasons.append("reference/ID-style context")
        if has_cc:
            reasons.append("+91 country code")
        return clamp(conf), reasons

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        for m in MOBILE_RE.finditer(text):
            number = digits_only(m.group(2))
            has_cc = bool(m.group(1)) and "91" in m.group(1)
            ctx = analyse("mobile", text, m.start(), m.end(), hint)
            if ctx.datetime:
                continue
            scored = self._score(number, has_cc, ctx)
            if scored:
                value = ("+91 " if has_cc else "") + number
                hits.append(Hit(self.rule_id, m.start(), m.end(), value, scored[0], scored[1]))
        for m in MOBILE_CC_RE.finditer(text):
            number = m.group(1)
            ctx = analyse("mobile", text, m.start(), m.end(), hint)
            if ctx.datetime or not ctx.labeled:
                continue
            scored = self._score(number, True, ctx, solid_cc=True)
            if scored:
                hits.append(Hit(self.rule_id, m.start(), m.end(), "+91 " + number, scored[0], scored[1]))
        return hits

    def redact(self, value: str) -> str:
        prefix = "+91 " if value.startswith("+91") else ""
        return prefix + "X" * 6 + value[-4:]
