from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ExtractedChunk:
    """Text safe to pass to detectors, paired with a source location."""

    text: str
    location: dict[str, Any]


@dataclass
class ExtractionResult:
    path: str
    chunks: list[ExtractedChunk] = field(default_factory=list)
    skipped_reason: str | None = None
    encoding: str | None = None

    @property
    def extracted_chars(self) -> int:
        return sum(len(chunk.text) for chunk in self.chunks)
