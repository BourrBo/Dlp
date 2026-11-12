"""Small validation for user-entered approval text, not scan-content classification."""

import re

_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bdlp_[a-f0-9]{12}\.[A-Za-z0-9_-]{40,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)


def safe_justification(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if any(ord(char) < 32 and char not in "\n\r\t" for char in normalized):
        raise ValueError("Text contains unsupported control characters")
    if any(pattern.search(normalized) for pattern in _CREDENTIAL_PATTERNS):
        raise ValueError("Text contains credential-like content")
    return normalized or None
