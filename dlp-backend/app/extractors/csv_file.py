import csv
import io
import json

from app.extractors.chunking import chunk_text
from app.extractors.models import ExtractionResult
from app.extractors.text import decode_text


def extract_csv(data: bytes, *, path: str) -> ExtractionResult:
    text, encoding, reason = decode_text(data)
    result = ExtractionResult(path=path, encoding=encoding, skipped_reason=reason)
    if text is None:
        return result

    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        for row_number, row in enumerate(reader, start=2):
            rendered = json.dumps(row, ensure_ascii=False, default=str)
            result.chunks.extend(
                chunk_text(
                    rendered,
                    path=path,
                    file_type="csv",
                    location={"row": row_number},
                )
            )
    except (csv.Error, UnicodeError) as exc:
        result.chunks.clear()
        result.skipped_reason = f"Invalid CSV: {exc}"
    return result
