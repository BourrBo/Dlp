"""Bank account numbers: 9-18 digits, diversity checks, MANDATORY context."""
from __future__ import annotations

import re
from typing import List

from ...models import Hit, Severity
from ..base import Detector
from .common import (all_same, analyse, clamp, is_repeating_block, longest_run,
                     mask_keep_last)

BANK_RE = re.compile(r"(?<![\w.])(?<!\d[\s-])(\d{9,18})(?!\w|[.,]\d)")


class BankAccountDetector(Detector):
    rule_id = "india.bank_account"
    category = "india_financial"
    description = "Bank account number (context-required)"
    base_severity = Severity.HIGH

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        for m in BANK_RE.finditer(text):
            digits = m.group(1)
            ctx = analyse("bank_account", text, m.start(), m.end(), hint)
            if not ctx.labeled:
                continue  # never flagged on digit count alone
            if ctx.datetime:
                continue
            if (len(set(digits)) < 4 or all_same(digits) or is_repeating_block(digits)
                    or longest_run(digits) >= 6 or not digits.strip("0")):
                continue
            hits.append(Hit(
                self.rule_id, m.start(), m.end(), digits, clamp(0.85),
                ["9-18 digits", "digit-diversity checks passed", "bank-account label in context"],
            ))
        return hits

    def redact(self, value: str) -> str:
        return mask_keep_last(value, 4)
