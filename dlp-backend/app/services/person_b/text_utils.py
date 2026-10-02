"""
Shared text helpers for the detection pipeline. Kept tiny and dependency-free
so every detector (regex, NER, EDM, fingerprint) redacts the same way.
"""


def redact(value: str) -> str:
    """Never persist or return a raw match — keep enough to triage, not to exfiltrate."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
