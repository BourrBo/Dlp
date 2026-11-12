"""Bounded, read-only XLSX text extraction with cell-level locations."""

from io import BytesIO

from openpyxl import load_workbook

from app.extractors.chunking import chunk_text
from app.extractors.limits import MAX_DOCUMENT_TEXT_CHARS
from app.extractors.models import ExtractionResult
from app.extractors.office_package import validate_ooxml_package

MAX_WORKBOOK_SHEETS = 250
MAX_WORKBOOK_CELLS = 250_000


def extract_xlsx(data: bytes, *, path: str) -> ExtractionResult:
    result = ExtractionResult(path=path)
    package_error = validate_ooxml_package(data, required_part="xl/workbook.xml", label="XLSX")
    if package_error:
        result.skipped_reason = package_error
        return result
    workbook = None
    try:
        workbook = load_workbook(BytesIO(data), read_only=True, data_only=True)
        if len(workbook.worksheets) > MAX_WORKBOOK_SHEETS:
            result.skipped_reason = f"XLSX exceeds the {MAX_WORKBOOK_SHEETS}-sheet limit"
            return result
        cells_seen = 0
        chars_seen = 0
        for sheet in workbook.worksheets:
            for row_number, row in enumerate(sheet.iter_rows(), start=1):
                values = []
                for cell in row:
                    cells_seen += 1
                    if cells_seen > MAX_WORKBOOK_CELLS:
                        result.chunks.clear()
                        result.skipped_reason = f"XLSX exceeds the {MAX_WORKBOOK_CELLS}-cell scan limit"
                        return result
                    value = cell.value
                    if value is None:
                        continue
                    text = str(value)
                    if text:
                        values.append(f"{cell.coordinate}={text}")
                if not values:
                    continue
                line = " | ".join(values)
                chars_seen += len(line)
                if chars_seen > MAX_DOCUMENT_TEXT_CHARS:
                    result.chunks.clear()
                    result.skipped_reason = "XLSX extracted text exceeds the 5 MiB processing limit"
                    return result
                result.chunks.extend(
                    chunk_text(
                        line,
                        path=path,
                        file_type="xlsx",
                        location={"sheet": sheet.title, "row": row_number},
                    )
                )
    except Exception as exc:
        result.chunks.clear()
        result.skipped_reason = f"Could not extract XLSX ({type(exc).__name__})"
        return result
    finally:
        if workbook is not None:
            workbook.close()
    if not result.chunks:
        result.skipped_reason = "XLSX has no text content"
    return result
