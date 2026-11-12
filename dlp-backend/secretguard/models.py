"""Core data model: severities, transient hits and (redacted) findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError("unknown severity: %r" % name)

    def lowered(self, steps: int = 1) -> "Severity":
        """Return a lower severity, never below LOW."""
        return Severity(max(int(self) - steps, int(Severity.LOW)))


@dataclass
class Hit:
    """A detector match. Lives only inside the scan loop.

    ``value`` holds the raw matched text so the detector can redact it. It is
    excluded from repr and is never copied into a Finding.
    """

    detector: str
    start: int
    end: int
    value: str = field(repr=False)
    confidence: float = 0.0
    reasons: List[str] = field(default_factory=list)
    severity: Optional[Severity] = None


@dataclass(frozen=True)
class Finding:
    """A reportable result. Contains redacted evidence only, never raw values."""

    rule_id: str
    category: str
    severity: Severity
    confidence: float
    file: str
    line: int
    column: int
    evidence: str
    reasons: Tuple[str, ...] = ()
    field_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "field": self.field_name,
            "evidence": self.evidence,
            "reasons": list(self.reasons),
        }
