"""Offline detectors with exact line and column positions.

Detectors never return or store the raw value. ``Match.value`` exists only
long enough to compute a fingerprint and a masked preview, then is dropped.

P1's frozen offline core can replace this module: set ``detector_module`` in
``.dlp.toml`` to a module exposing ``RULES`` (list of ``Rule``) or
``detect_line(line) -> list[Match]``.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, Optional

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    data_type: str
    severity: str
    confidence: float
    description: str
    pattern: re.Pattern
    group: int = 0
    validator: Optional[Callable[[str], bool]] = None
    guidance: str = "Remove the value and use a secret manager or synthetic test data."


@dataclass(frozen=True)
class Match:
    rule: Rule
    start: int  # 0-based column in the line
    end: int
    value: str


# --------------------------------------------------------------- validators


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _card_ok(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    if not 13 <= len(digits) <= 19 or not luhn_ok(digits):
        return False
    p2, p4 = int(digits[:2]), int(digits[:4])
    if digits[0] == "4":
        return len(digits) in (13, 16, 19)
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:
        return len(digits) == 16
    if p2 in (34, 37):
        return len(digits) == 15
    if p4 == 6011 or p2 == 65 or 644 <= int(digits[:3]) <= 649:
        return len(digits) in (16, 19)
    if p2 in (60, 81, 82) or digits[:3] == "508":  # RuPay
        return len(digits) == 16
    if 3528 <= p4 <= 3589:
        return 16 <= len(digits) <= 19
    if p2 in (36, 38, 30):
        return 14 <= len(digits) <= 19
    return False


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][ord(ch) - 48]]
    return c == 0


def _aadhaar_ok(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    return len(digits) == 12 and digits[0] in "23456789" and verhoeff_ok(digits)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


_PLACEHOLDERS = ("example", "changeme", "change_me", "your_", "your-", "xxxx", "placeholder",
                 "dummy", "sample", "<", "${", "{{", "process.env", "getenv", "redacted")


def _secret_value_ok(value: str) -> bool:
    low = value.lower()
    if any(p in low for p in _PLACEHOLDERS):
        return False
    return shannon_entropy(value) >= 3.0 and len(set(value)) >= 6


# -------------------------------------------------------------------- rules

RULES: list[Rule] = [
    Rule("DLP001", "private_key", "critical", 0.99, "Private key block",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
         guidance="Rotate this key now: removing it from the code does not remove it from history."),
    Rule("DLP002", "aws_access_key", "critical", 0.97, "AWS access key ID",
         re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
         guidance="Deactivate the key in IAM and issue a new one."),
    Rule("DLP003", "aws_secret_key", "critical", 0.9, "AWS secret access key",
         re.compile(r"(?i)aws.{0,20}secret.{0,20}?[=:]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
         group=1, guidance="Deactivate the key in IAM and issue a new one."),
    Rule("DLP004", "github_token", "critical", 0.97, "GitHub token",
         re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"),
         guidance="Revoke the token in GitHub settings and create a new one."),
    Rule("DLP005", "slack_token", "high", 0.95, "Slack token",
         re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}"),
         guidance="Revoke the token in the Slack admin console."),
    Rule("DLP006", "google_api_key", "high", 0.9, "Google API key",
         re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
         guidance="Restrict or regenerate the key in Google Cloud console."),
    Rule("DLP007", "api_key", "high", 0.9, "Prefixed API key or token",
         re.compile(r"\b(?:sk|pk|api|key|token)[_-](?:(?:live|test|prod)[_-])?[A-Za-z0-9]{16,}\b", re.IGNORECASE),
         validator=_secret_value_ok),
    Rule("DLP008", "hardcoded_secret", "medium", 0.7, "Hard-coded password or secret assignment",
         re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
                    r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"),
         group=1, validator=_secret_value_ok),
    Rule("DLP009", "credit_card", "high", 0.9, "Payment card number",
         re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])"),
         validator=_card_ok, guidance="Use a documented test card number or remove the data."),
    Rule("DLP010", "aadhaar", "high", 0.85, "Aadhaar number",
         re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)"),
         validator=_aadhaar_ok, guidance="Remove the number or replace it with synthetic data."),
    Rule("DLP011", "pan", "medium", 0.75, "Indian PAN",
         re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b"),
         guidance="Remove the number or replace it with synthetic data."),
    Rule("DLP012", "email_pii", "low", 0.6, "Email address",
         re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
         guidance="Check that this is not a customer or employee address."),
]


def mask(value: str) -> str:
    """Enough to triage, never enough to reuse."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def detect_line(line: str, rules: Optional[list[Rule]] = None) -> list[Match]:
    """Run all rules on one line. Overlaps keep the most severe, earliest match."""
    active = RULES if rules is None else rules
    found: list[Match] = []
    for rule in active:
        for m in rule.pattern.finditer(line):
            value = m.group(rule.group)
            if rule.validator and not rule.validator(value):
                continue
            start, end = m.span(rule.group)
            found.append(Match(rule, start, end, value))
    found.sort(key=lambda x: (-SEVERITY_ORDER[x.rule.severity], x.start))
    kept: list[Match] = []
    for cand in found:
        if not any(cand.start < k.end and k.start < cand.end for k in kept):
            kept.append(cand)
    kept.sort(key=lambda x: x.start)
    return kept
