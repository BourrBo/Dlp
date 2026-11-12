"""UPI IDs (VPAs): name@handle where handle is a recognised PSP/bank handle.
Ordinary e-mail addresses (person@gmail.com) are never classified as UPI."""
from __future__ import annotations

import re
from typing import List, Optional, Set

from ...models import Hit, Severity
from ..base import Detector
from .common import analyse, clamp

DEFAULT_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm", "ptsbi",
    "pthdfc", "ptyes", "ptaxis", "apl", "upi", "sbi", "hdfcbank", "icici", "axisbank",
    "axisb", "yesbank", "kotak", "ikwik", "fbl", "federal", "barodampay", "pnb", "cnrb",
    "unionbank", "boi", "idfcfirst", "indus", "aubank", "rbl", "freecharge", "jupiteraxis",
    "slice", "postbank", "okbizaxis", "yapl", "waicici", "wahdfcbank", "wasbi", "waaxis",
}
UPI_RE = re.compile(
    r"(?<![\w.%+-])([A-Za-z0-9][\w.-]{1,48})@([A-Za-z][A-Za-z0-9]{1,24})(?!\w|@|\.[A-Za-z0-9])"
)


class UpiDetector(Detector):
    rule_id = "india.upi"
    category = "india_financial"
    description = "UPI ID / VPA (PSP handle allowlist)"
    base_severity = Severity.MEDIUM

    def __init__(self, extra_handles: Optional[Set[str]] = None) -> None:
        self.handles = set(DEFAULT_HANDLES) | {h.lower() for h in (extra_handles or set())}

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        for m in UPI_RE.finditer(text):
            handle = m.group(2).lower()
            if handle not in self.handles:
                continue
            ctx = analyse("upi", text, m.start(), m.end(), hint)
            if ctx.datetime:
                continue
            reasons = ["name@handle structure", "recognised PSP handle"]
            if ctx.labeled:
                conf = 0.95
                reasons.append("UPI / VPA label in context")
            else:
                conf = 0.70
            hits.append(Hit(self.rule_id, m.start(), m.end(), m.group(0), clamp(conf), reasons))
        return hits

    def redact(self, value: str) -> str:
        local, _, handle = value.partition("@")
        return local[:2] + "****@" + handle
