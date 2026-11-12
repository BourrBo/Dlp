"""PowerPoint slide and notes extraction with source slide locations."""

from io import BytesIO

from pptx import Presentation
from pptx.shapes.group import GroupShape

from app.extractors.chunking import chunk_text
from app.extractors.limits import MAX_DOCUMENT_TEXT_CHARS
from app.extractors.models import ExtractionResult
from app.extractors.office_package import validate_ooxml_package

MAX_PRESENTATION_SLIDES = 500
MAX_PRESENTATION_SHAPES = 100_000


def _shape_text(shape) -> list[str]:
    texts = []
    if getattr(shape, "has_text_frame", False):
        text = shape.text_frame.text.strip()
        if text:
            texts.append(text)
    if getattr(shape, "has_table", False):
        for row in shape.table.rows:
            text = " | ".join(cell.text.strip() for cell in row.cells)
            if text.strip(" |"):
                texts.append(text)
    return texts


def _walk_shapes(shapes):
    for shape in shapes:
        yield shape
        if isinstance(shape, GroupShape):
            yield from _walk_shapes(shape.shapes)


def extract_pptx(data: bytes, *, path: str) -> ExtractionResult:
    result = ExtractionResult(path=path)
    package_error = validate_ooxml_package(data, required_part="ppt/presentation.xml", label="PPTX")
    if package_error:
        result.skipped_reason = package_error
        return result
    try:
        presentation = Presentation(BytesIO(data))
        if len(presentation.slides) > MAX_PRESENTATION_SLIDES:
            result.skipped_reason = f"PPTX exceeds the {MAX_PRESENTATION_SLIDES}-slide limit"
            return result
        chars_seen = 0
        shapes_seen = 0
        for slide_number, slide in enumerate(presentation.slides, start=1):
            texts = []
            for shape in _walk_shapes(slide.shapes):
                shapes_seen += 1
                if shapes_seen > MAX_PRESENTATION_SHAPES:
                    result.chunks.clear()
                    result.skipped_reason = f"PPTX exceeds the {MAX_PRESENTATION_SHAPES}-shape scan limit"
                    return result
                texts.extend(_shape_text(shape))
            for text, kind in (("\n".join(texts), "slide"),):
                if text:
                    chars_seen += len(text)
                    if chars_seen > MAX_DOCUMENT_TEXT_CHARS:
                        result.chunks.clear()
                        result.skipped_reason = "PPTX extracted text exceeds the 5 MiB processing limit"
                        return result
                    result.chunks.extend(
                        chunk_text(text, path=path, file_type="pptx", location={"slide": slide_number, "content": kind})
                    )
            if slide.has_notes_slide:
                notes_frame = slide.notes_slide.notes_text_frame
                notes = notes_frame.text.strip() if notes_frame else ""
                if notes:
                    chars_seen += len(notes)
                    if chars_seen > MAX_DOCUMENT_TEXT_CHARS:
                        result.chunks.clear()
                        result.skipped_reason = "PPTX extracted text exceeds the 5 MiB processing limit"
                        return result
                    result.chunks.extend(
                        chunk_text(notes, path=path, file_type="pptx", location={"slide": slide_number, "content": "notes"})
                    )
    except Exception as exc:
        result.chunks.clear()
        result.skipped_reason = f"Could not extract PPTX ({type(exc).__name__})"
        return result
    if not result.chunks:
        result.skipped_reason = "PPTX has no text content"
    return result
