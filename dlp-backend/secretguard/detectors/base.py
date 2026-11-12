"""Detector interface. Any scanner (including a Milestone 2 engine) can be
wrapped as a Detector and registered with the Scanner."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..models import Hit, Severity


class Detector(ABC):
    rule_id: str = ""
    category: str = ""
    description: str = ""
    base_severity: Severity = Severity.MEDIUM

    @abstractmethod
    def detect(self, text: str, hint: str = "") -> List[Hit]:
        """Return hits in ``text``. ``hint`` is optional structural context,
        e.g. the CSV column header the text came from."""

    @abstractmethod
    def redact(self, value: str) -> str:
        """Return a safe-to-print representation of a matched value."""

    def severity_for(self, confidence: float) -> Severity:
        sev = self.base_severity
        if confidence < 0.40:
            return sev.lowered(2)
        if confidence < 0.60:
            return sev.lowered(1)
        return sev
