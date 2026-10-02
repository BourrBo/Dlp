import json
from typing import Any

from app.extractors.chunking import chunk_text
from app.extractors.models import ExtractionResult
from app.extractors.text import decode_text


def _leaves(value: Any, path: str = "$", depth: int = 0):
    if depth > 100:
        raise ValueError("JSON nesting exceeds the 100-level limit")
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _leaves(child, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaves(child, f"{path}[{index}]", depth + 1)
    else:
        yield path, value


def extract_json(data: bytes, *, path: str) -> ExtractionResult:
    text, encoding, reason = decode_text(data)
    result = ExtractionResult(path=path, encoding=encoding, skipped_reason=reason)
    if text is None:
        return result

    try:
        document = json.loads(text)
        for json_path, value in _leaves(document):
            rendered = f"{json_path} = {json.dumps(value, ensure_ascii=False)}"
            result.chunks.extend(
                chunk_text(
                    rendered,
                    path=path,
                    file_type="json",
                    location={"json_path": json_path},
                )
            )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        result.chunks.clear()
        result.skipped_reason = f"Invalid JSON: {exc}"
    return result
