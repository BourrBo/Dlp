from io import BytesIO
import math

import pypdfium2 as pdfium
import pytesseract
from PIL import ImageOps

from pypdf import PdfReader

from app.extractors.chunking import chunk_text
from app.extractors.limits import (
    MAX_DOCUMENT_PAGES,
    MAX_DOCUMENT_TEXT_CHARS,
    MAX_OCR_PAGES,
    MAX_OCR_PIXELS,
    OCR_PAGE_TIMEOUT_SECONDS,
)
from app.extractors.models import ExtractionResult


class OcrUnavailable(RuntimeError):
    pass


def _available_ocr_languages() -> list[str]:
    try:
        installed = set(pytesseract.get_languages(config=""))
    except pytesseract.TesseractNotFoundError as exc:
        raise OcrUnavailable("Tesseract OCR is not installed") from exc
    languages = [language for language in ("eng", "hin") if language in installed]
    if not languages:
        raise OcrUnavailable("Tesseract OCR has no supported English or Hindi language data installed")
    return languages


def _ocr_page(page) -> str:
    try:
        width, height = page.get_size()
        if width <= 0 or height <= 0:
            return ""
        scale = min(2.0, math.sqrt(MAX_OCR_PIXELS / (width * height)))
        image = page.render(scale=scale).to_pil()
        prepared = ImageOps.autocontrast(image.convert("L"))
        return pytesseract.image_to_string(
            prepared,
            lang="+".join(_available_ocr_languages()),
            timeout=OCR_PAGE_TIMEOUT_SECONDS,
        )
    except pytesseract.TesseractNotFoundError as exc:
        raise OcrUnavailable("Tesseract OCR is not installed") from exc


def extract_pdf(data: bytes, *, path: str) -> ExtractionResult:
    """Extract text and OCR image-only pages with one-based source locations."""
    result = ExtractionResult(path=path)
    try:
        reader = PdfReader(BytesIO(data), strict=False)
        if reader.is_encrypted:
            result.skipped_reason = "Password-protected PDF is not supported"
            return result
        if len(reader.pages) > MAX_DOCUMENT_PAGES:
            result.skipped_reason = f"PDF exceeds the {MAX_DOCUMENT_PAGES}-page limit"
            return result

        total_chars = 0
        pages_needing_ocr = []
        for page_number, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            total_chars += len(text)
            if total_chars > MAX_DOCUMENT_TEXT_CHARS:
                result.chunks.clear()
                result.skipped_reason = "PDF extracted text exceeds the 5 MiB processing limit"
                return result
            if text.strip():
                result.chunks.extend(
                    chunk_text(
                        text,
                        path=path,
                        file_type="pdf",
                        location={"page": page_number},
                    )
                )
            else:
                pages_needing_ocr.append(page_number - 1)

        if len(pages_needing_ocr) > MAX_OCR_PAGES:
            result.chunks.clear()
            result.skipped_reason = f"PDF has more than {MAX_OCR_PAGES} pages requiring OCR"
            return result
        if pages_needing_ocr:
            rendered = pdfium.PdfDocument(data)
            try:
                for page_index in pages_needing_ocr:
                    ocr_text = _ocr_page(rendered[page_index])
                    total_chars += len(ocr_text)
                    if total_chars > MAX_DOCUMENT_TEXT_CHARS:
                        result.chunks.clear()
                        result.skipped_reason = "PDF extracted text exceeds the 5 MiB processing limit"
                        return result
                    if ocr_text.strip():
                        result.chunks.extend(
                            chunk_text(
                                ocr_text,
                                path=path,
                                file_type="pdf",
                                location={"page": page_index + 1, "ocr": True},
                            )
                        )
            except OcrUnavailable as exc:
                result.chunks.clear()
                result.skipped_reason = f"PDF has pages requiring OCR; {exc}"
                return result
            finally:
                rendered.close()
    except Exception as exc:  # malformed PDFs vary across parser exceptions
        result.chunks.clear()
        result.skipped_reason = f"Could not extract PDF ({type(exc).__name__})"
        return result

    if not result.chunks:
        result.skipped_reason = "PDF has no extractable text"
    return result
