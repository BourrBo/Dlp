from pathlib import Path
from typing import Callable

from app.extractors.csv_file import extract_csv
from app.extractors.json_file import extract_json
from app.extractors.limits import MAX_FILE_BYTES
from app.extractors.models import ExtractionResult
from app.extractors.text import extract_text_bytes
from app.extractors.xml_file import extract_xml

TEXT_EXTENSIONS = {
    ".txt", ".md", ".log", ".py", ".js", ".jsx", ".ts", ".tsx", ".java",
    ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".sql", ".sh",
    ".ps1", ".yaml", ".yml", ".toml", ".ini", ".conf", ".html", ".css",
}

_STRUCTURED_EXTRACTORS: dict[str, Callable[..., ExtractionResult]] = {
    ".csv": extract_csv,
    ".json": extract_json,
    ".xml": extract_xml,
}


def extract_file(file_path: str | Path, *, display_path: str | None = None) -> ExtractionResult:
    """Extract a supported file without importing database or network code."""
    path = Path(file_path)
    shown_path = display_path or path.name
    try:
        size = path.stat().st_size
    except OSError as exc:
        return ExtractionResult(path=shown_path, skipped_reason=f"Could not access file: {exc}")
    if size > MAX_FILE_BYTES:
        return ExtractionResult(
            path=shown_path,
            skipped_reason=f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit",
        )

    extension = path.suffix.lower()
    if extension not in TEXT_EXTENSIONS and extension not in _STRUCTURED_EXTRACTORS:
        return ExtractionResult(path=shown_path, skipped_reason=f"Unsupported file type: {extension or '(no extension)'}")
    try:
        with path.open("rb") as source:
            data = source.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        return ExtractionResult(path=shown_path, skipped_reason=f"Could not read file: {exc}")
    if len(data) > MAX_FILE_BYTES:
        return ExtractionResult(
            path=shown_path,
            skipped_reason=f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit",
        )

    extractor = _STRUCTURED_EXTRACTORS.get(extension)
    if extractor:
        result = extractor(data, path=shown_path)
    else:
        result = extract_text_bytes(data, path=shown_path, file_type=extension.lstrip("."))
    if not result.chunks and not result.skipped_reason:
        result.skipped_reason = "No text content found"
    return result
