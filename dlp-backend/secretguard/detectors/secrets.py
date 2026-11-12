"""Secret and entropy detectors merged from Secret Guard milestones 2 and 3.

Findings never retain or print the matched value. Reports contain a short
SHA-256 fingerprint so an operator can correlate repeats without exposing it.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import List

from ..models import Hit, Severity
from .base import Detector

_PATTERNS = [
    ("secret.aws_access_key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"), 0.98, Severity.HIGH),
    ("secret.private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), 0.99, Severity.CRITICAL),
    ("secret.github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{30,})\b"), 0.98, Severity.HIGH),
    ("secret.slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0.96, Severity.HIGH),
    ("secret.stripe_live_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), 0.99, Severity.CRITICAL),
    ("secret.stripe_test_key", re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b"), 0.95, Severity.LOW),
    ("secret.google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.96, Severity.HIGH),
    ("secret.database_uri", re.compile(r"""\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@[^\s/"']+""", re.I), 0.98, Severity.CRITICAL),
    ("secret.jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.80, Severity.MEDIUM),
]
_GENERIC = re.compile(
    r"""(?i)(?:api[_-]?key|secret|token|passwd|password|pwd|auth)[\w-]*\s*[:=]\s*['\"]?([A-Za-z0-9/+=_\-.!@#$%^&*]{12,})['\"]?"""
)
_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{24,}(?![A-Za-z0-9])")
_PLACEHOLDER = re.compile(r"(?i)example|changeme|placeholder|your[_-]|xxxx|<.*>|\$\{|dummy|sample")
_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock", "uv.lock", "gemfile.lock"}
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$", re.I)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum(count / size * math.log2(count / size) for count in counts.values())


def _jwt_severity(token: str) -> tuple[str, Severity, float, list[str]]:
    """Decode JWT claims for a conservative role warning; never verify a token."""
    try:
        import base64

        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, UnicodeError, json.JSONDecodeError, IndexError):
        return "secret.jwt", Severity.MEDIUM, 0.80, ["JWT-shaped value; signature is not verified"]
    if isinstance(claims, dict) and claims.get("role") == "service_role":
        return "secret.supabase_service_role_jwt", Severity.CRITICAL, 1.0, ["decoded JWT claim has role=service_role; signature is not verified"]
    return "secret.jwt", Severity.MEDIUM, 0.80, ["decoded JWT structure; signature is not verified"]


class SecretDetector(Detector):
    rule_id = "secret"
    category = "secret"
    description = "Credential signatures, JWT risk labels and entropy-based assignments"
    base_severity = Severity.HIGH

    def detect(self, text: str, hint: str = "") -> List[Hit]:
        hits: List[Hit] = []
        spans: set[tuple[int, int]] = set()
        for rule, pattern, confidence, severity in _PATTERNS:
            for match in pattern.finditer(text):
                if rule == "secret.jwt":
                    rule, severity, confidence, reasons = _jwt_severity(match.group(0))
                else:
                    reasons = ["known credential format"]
                hits.append(Hit(rule, match.start(), match.end(), match.group(0), confidence, reasons, severity))
                spans.add(match.span())

        for match in _GENERIC.finditer(text):
            value = match.group(1)
            entropy = shannon_entropy(value)
            if entropy < 3.5 or _PLACEHOLDER.search(value):
                continue
            confidence = min(0.60 + (entropy - 3.5) * 0.10, 0.90)
            hits.append(Hit("secret.high_entropy", match.start(1), match.end(1), value, round(confidence, 2),
                            ["credential-like assignment", "entropy %.2f bits/char" % entropy], Severity.HIGH))
            spans.add(match.span(1))

        if hint.rsplit("/", 1)[-1].lower() not in _LOCKFILES:
            for match in _CANDIDATE.finditer(text):
                value = match.group().strip("=")
                if len(value) < 24 or _SHA.fullmatch(value) or _UUID.fullmatch(value):
                    continue
                if any(start < match.end() and end > match.start() for start, end in spans):
                    continue
                if re.fullmatch(r"[0-9a-fA-F]+", value):
                    threshold, kind = 3.5, "hex"
                elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", match.group()) and any(c in value for c in "+/="):
                    threshold, kind = 4.5, "base64"
                else:
                    threshold, kind = 4.2, "generic"
                entropy = shannon_entropy(value)
                if entropy >= threshold and not _PLACEHOLDER.search(value):
                    hits.append(Hit("secret.entropy_" + kind, match.start(), match.end(), match.group(), 0.65,
                                    ["%s entropy %.2f >= %.2f" % (kind, entropy, threshold)], Severity.MEDIUM))
        return hits

    def redact(self, value: str) -> str:
        fingerprint = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
        return "sha256:" + fingerprint
