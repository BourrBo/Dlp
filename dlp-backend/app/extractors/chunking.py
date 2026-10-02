from collections.abc import Iterator
from typing import Any

from app.extractors.limits import CHUNK_OVERLAP_CHARS, MAX_CHUNK_CHARS
from app.extractors.models import ExtractedChunk


def chunk_text(
    text: str,
    *,
    path: str,
    file_type: str,
    max_chars: int = MAX_CHUNK_CHARS,
    overlap: int = CHUNK_OVERLAP_CHARS,
    location: dict[str, Any] | None = None,
) -> Iterator[ExtractedChunk]:
    """Yield bounded overlapping chunks and source offsets/line information."""
    if max_chars < 1 or overlap < 0 or overlap >= max_chars:
        raise ValueError("Require max_chars > overlap >= 0")
    if not text:
        return

    start = 0
    index = 0
    line_cursor = 0
    line_number = 1
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            newline = text.rfind("\n", start + max_chars // 2, end)
            if newline > start:
                end = newline + 1
        if end <= start:
            end = min(start + max_chars, len(text))

        chunk_location: dict[str, Any] = {
            "path": path,
            "file_type": file_type,
            "chunk_index": index,
            "char_start": start,
            "char_end": end,
        }
        if location:
            chunk_location.update(location)
        if not location or "line_start" in location:
            # Advance a small cursor instead of recounting from the beginning
            # for every chunk (which becomes quadratic for large files).
            line_number += text.count("\n", line_cursor, start)
            line_cursor = start
            chunk_location["line_start"] = line_number
            chunk_location["line_end"] = line_number + text.count("\n", start, end)

        yield ExtractedChunk(text=text[start:end], location=chunk_location)
        if end == len(text):
            break
        start = max(start + 1, end - overlap)
        index += 1
