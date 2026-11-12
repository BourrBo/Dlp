"""Shared helpers: context analysis, exclusions and masking."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional


def digits_only(s: str) -> str:
    return re.sub(r"\D", "", s)


def mask_keep_last(value: str, keep: int, mask_char: str = "X") -> str:
    """Mask all but the last ``keep`` characters; never reveal a whole value."""
    if keep >= len(value):
        return mask_char * len(value)
    return mask_char * (len(value) - keep) + value[-keep:]


# ---------------------------------------------------------------- structure
def all_same(d: str) -> bool:
    return len(set(d)) == 1


def is_repeating_block(d: str) -> bool:
    n = len(d)
    return any(n % p == 0 and d == d[:p] * (n // p) for p in range(1, n // 2 + 1))


def longest_run(d: str) -> int:
    """Longest ascending or descending (mod 10) run of consecutive digits."""
    best = run = 1
    direction = 0
    for a, b in zip(d, d[1:]):
        diff = (int(b) - int(a)) % 10
        step = 1 if diff == 1 else -1 if diff == 9 else 0
        if step != 0 and step == direction:
            run += 1
        elif step != 0:
            run = 2
        else:
            run = 1
        direction = step
        best = max(best, run)
    return best


def looks_like_timestamp(d: str) -> bool:
    """Compact date/time (YYYYMMDD[HHMM[SS]]) or unix epoch (s / ms)."""
    n = len(d)
    if n in (8, 12, 14) and d[:2] in ("19", "20"):
        y, mo, da = int(d[:4]), int(d[4:6]), int(d[6:8])
        if 1970 <= y <= 2100 and 1 <= mo <= 12 and 1 <= da <= 31:
            if n == 8:
                return True
            if int(d[8:10]) <= 23 and int(d[10:12]) <= 59:
                return n == 12 or int(d[12:14]) <= 59
    if n in (10, 13):
        v = int(d)
        if n == 13:
            v //= 1000
        return 946684800 <= v <= 4102444800  # 2000-01-01 .. 2100-01-01
    return False


# ------------------------------------------------------------------ context
def _compile(pattern: str) -> "re.Pattern[str]":
    return re.compile(r"(?<![A-Za-z])(?:%s)(?![A-Za-z])" % pattern, re.IGNORECASE)


LABEL_PATTERNS: Dict[str, str] = {
    "aadhaar": r"aadhaar|aadhar|adhaar|adhar|uidai|uid[\s_-]*(?:no|num|number)",
    "pan": r"pan(?:[\s_-]*(?:card|no|num|number))?|permanent[\s_-]*account[\s_-]*number|tax[\s_-]*id|income[\s_-]*tax",
    "gstin": r"gstin|gst[\s_-]*(?:no|num|number|id|in)?|goods[\s_-]*and[\s_-]*services[\s_-]*tax",
    "ifsc": r"ifsc(?:[\s_-]*code)?|bank[\s_-]*branch|branch[\s_-]*(?:ifsc|code)",
    "bank_account": r"bank[\s_-]*(?:a/?c|acct|account)|(?:a/?c|acct|account|acc)[\s_.-]*(?:no|num|number|nbr|#)",
    "upi": r"upi(?:[\s_-]*(?:id|handle))?|vpa|virtual[\s_-]*payment[\s_-]*address|payment[\s_-]*address|bhim|gpay|phonepe|paytm",
    "mobile": r"mobile|mob|phone|ph|tel|telephone|contact|cell|whatsapp|msisdn|sms",
}
LABELS = {k: _compile(v) for k, v in LABEL_PATTERNS.items()}
_OTHERS = {
    k: _compile("|".join(v for kk, v in LABEL_PATTERNS.items() if kk != k))
    for k in LABEL_PATTERNS
}
AADHAAR_WEAK_LABEL = _compile(r"uid")

DATETIME_RE = _compile(
    r"timestamp|epoch|unix[\s_-]*time|datetime|date|time|ts|"
    r"created(?:[\s_-]*(?:at|on))?|updated(?:[\s_-]*(?:at|on))?|modified|"
    r"logged[\s_-]*at|expires?|expiry"
)
REFERENCE_RE = _compile(
    r"order|invoice|inv|txn|transaction|ref|reference|tracking|awb|consignment|"
    r"serial|sku|batch|job|ticket|case|request|req|session|trace|correlation|id"
)


@dataclass
class Context:
    labeled: bool
    datetime: bool
    reference: bool


def _last_end(rx: "re.Pattern[str]", s: str) -> int:
    last = -1
    for m in rx.finditer(s):
        last = m.end()
    return last


def _first_start(rx: "re.Pattern[str]", s: str) -> int:
    m = rx.search(s)
    return m.start() if m else -1


def analyse(
    kind: str,
    text: str,
    start: int,
    end: int,
    hint: str = "",
    own: Optional["re.Pattern[str]"] = None,
    before_window: int = 40,
    after_window: int = 24,
) -> Context:
    """Classify the context around a match.

    A value counts as *labeled* only if the nearest identifier label is of the
    detector's own kind, so ``Aadhaar: 1234.., PAN: ...`` does not let the
    Aadhaar label "leak" onto the PAN or vice versa. ``hint`` (such as a CSV
    header) is treated as text immediately preceding the value.
    """
    own_re = own or LABELS[kind]
    other_re = _OTHERS[kind]
    before = (hint + " : " if hint else "") + text[max(0, start - before_window):start]
    after = text[end:end + after_window]

    lab = _last_end(own_re, before)
    oth = _last_end(other_re, before)
    labeled = lab >= 0 and lab > oth
    if not labeled and lab < 0:
        own_after = _first_start(own_re, after)
        oth_after = _first_start(other_re, after)
        if own_after >= 0 and (oth_after < 0 or own_after < oth_after):
            labeled = oth < 0
    anchor = max(lab, oth)
    return Context(
        labeled=labeled,
        datetime=_last_end(DATETIME_RE, before) > anchor,
        reference=_last_end(REFERENCE_RE, before) > anchor,
    )


def clamp(x: float) -> float:
    return round(min(max(x, 0.0), 1.0), 2)
