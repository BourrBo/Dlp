"""IFSC: 4 letters + '0' + 6 alphanumerics, with bank-prefix and label scoring."""
from __future__ import annotations

import re
from typing import List, Optional, Set

from ...models import Hit, Severity
from ..base import Detector
from .common import analyse, clamp

# Non-exhaustive list of common bank codes; extend via the constructor.
KNOWN_BANK_CODES = {
    "SBIN", "HDFC", "ICIC", "UTIB", "PUNB", "BARB", "CNRB", "KKBK", "IDIB", "YESB",
    "UBIN", "BKID", "INDB", "FDRL", "IOBA", "MAHB", "CBIN", "SIBL", "KARB", "KVBL",
    "TMBL", "RATN", "AUBL", "DBSS", "SCBL", "HSBC", "CITI", "IDFB", "JAKA", "DLXB",
    "ESFB", "UCBA", "USFB", "BDBL", "PSIB", "SRCB", "PYTM", "AIRP", "FINO", "NSPB",
}
IFSC_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z]{4})0([A-Za-z0-9]{6})(?![A-Za-z0-9_])", re.IGNORECASE
)


class IfscDetector(Detector):
    rule_id = "india.ifsc"
    category = "india_bank_id"
    description = "IFSC code (structure + bank prefix + label)"
    base_severity = Severity.LOW  # branch identifier, public

    def __init__(self, extra_bank_codes: Optional[Set[str]] = None) -> None:
        self.bank_codes = set(KNOWN_BANK_CODES) | {c.upper() for c in (extra_bank_codes or set())}

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        for m in IFSC_RE.finditer(text):
            value = m.group(0)
            ctx = analyse("ifsc", text, m.start(), m.end(), hint)
            if ctx.datetime:
                continue
            known = m.group(1).upper() in self.bank_codes
            reasons = ["11 characters, 5th character is 0"]
            if ctx.labeled:
                conf = 0.95
                reasons.append("IFSC / branch label in context")
            else:
                if value != value.upper():
                    continue
                conf = 0.60 if known else 0.25
                reasons.append("no label")
                reasons.append("recognised bank code" if known else "unknown bank code")
                if known and not any(c.isdigit() for c in value[5:]):
                    conf -= 0.2
                    reasons.append("branch part has no digits")
            hits.append(Hit(self.rule_id, m.start(), m.end(), value.upper(), clamp(conf), reasons))
        return hits

    def redact(self, value: str) -> str:
        return value[:5] + "X" * 6
