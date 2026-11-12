"""GSTIN: state code, embedded PAN, entity char, literal Z, mod-36 checksum."""
from __future__ import annotations

import re
from typing import List

from ...models import Hit, Severity
from ..base import Detector
from .common import analyse, clamp
from .pan import PAN_CATEGORIES

_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
VALID_STATE_CODES = {"%02d" % i for i in range(1, 39)} | {"97", "99"}
GSTIN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(\d{2})([A-Za-z]{5}\d{4}[A-Za-z])([1-9A-Za-z])(Z)([0-9A-Za-z])(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def check_char(first14: str) -> str:
    total = 0
    for i, ch in enumerate(first14):
        v = _CHARS.index(ch) * (2 if i % 2 else 1)
        total += v // 36 + v % 36
    return _CHARS[(36 - total % 36) % 36]


def is_valid(gstin: str) -> bool:
    g = gstin.upper()
    if len(g) != 15 or any(c not in _CHARS for c in g):
        return False
    return (g[:2] in VALID_STATE_CODES and g[5] in PAN_CATEGORIES
            and g[12] != "0" and g[13] == "Z" and check_char(g[:14]) == g[14])


class GstinDetector(Detector):
    rule_id = "india.gstin"
    category = "india_business_id"
    description = "GSTIN (state, embedded PAN, entity, Z, checksum)"
    base_severity = Severity.LOW  # business identifier, public by design

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        for m in GSTIN_RE.finditer(text):
            value = m.group(0)
            if not is_valid(value):
                continue
            if value != value.upper() and not analyse("gstin", text, m.start(), m.end(), hint).labeled:
                continue
            ctx = analyse("gstin", text, m.start(), m.end(), hint)
            if ctx.datetime:
                continue
            reasons = ["valid state code", "embedded PAN structure valid",
                       "entity character + 'Z'", "mod-36 checksum valid"]
            if ctx.labeled:
                conf = 0.98
                reasons.append("GSTIN label in context")
            else:
                conf = 0.85
            hits.append(Hit(self.rule_id, m.start(), m.end(), value.upper(), clamp(conf), reasons))
        return hits

    def redact(self, value: str) -> str:
        return value[:2] + "X" * 10 + value[-3:]
