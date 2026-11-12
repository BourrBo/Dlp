from io import BytesIO
from zipfile import ZipFile
import xml.etree.ElementTree as ElementTree

from docx import Document
from docx.document import Document as DocumentObject
from docx.table import Table, _Cell
from docx.text.paragraph import Paragraph
from docx.oxml.table import CT_Tbl
from docx.oxml.text.paragraph import CT_P

from app.extractors.chunking import chunk_text
from app.extractors.limits import (
    MAX_DOCUMENT_TEXT_CHARS,
)
from app.extractors.models import ExtractionResult
from app.extractors.office_package import validate_ooxml_package

_WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _preflight_package(data: bytes) -> str | None:
    return validate_ooxml_package(data, required_part="word/document.xml", label="DOCX")


def _iter_blocks(parent):
    if isinstance(parent, DocumentObject):
        parent_element = parent.element.body
    elif isinstance(parent, _Cell):
        parent_element = parent._tc
    else:
        parent_element = getattr(parent, "_element", None)
        if parent_element is None:
            return
    for child in parent_element.iterchildren():
        if isinstance(child, CT_P):
            yield Paragraph(child, parent)
        elif isinstance(child, CT_Tbl):
            yield Table(child, parent)


def _append_text(result: ExtractionResult, text: str, location: dict, *, path: str) -> int:
    if not text.strip():
        return 0
    remaining = MAX_DOCUMENT_TEXT_CHARS - result.extracted_chars
    if remaining <= 0 or len(text) > remaining:
        return -1
    chunks = list(chunk_text(text, path=path, file_type="docx", location=location))
    result.chunks.extend(chunks)
    return len(text)


def extract_docx(data: bytes, *, path: str) -> ExtractionResult:
    """Extract DOCX paragraphs, tables, headers and comments with source locations."""
    result = ExtractionResult(path=path)
    package_error = _preflight_package(data)
    if package_error:
        result.skipped_reason = package_error
        return result

    try:
        document = Document(BytesIO(data))
        paragraph_number = 0
        table_number = 0
        for block in _iter_blocks(document):
            if isinstance(block, Paragraph):
                paragraph_number += 1
                if _append_text(
                    result,
                    block.text,
                    {"paragraph": paragraph_number},
                    path=path,
                ) < 0:
                    result.chunks.clear()
                    result.skipped_reason = "DOCX extracted text exceeds the 5 MiB processing limit"
                    return result
            else:
                table_number += 1
                for row_number, row in enumerate(block.rows, start=1):
                    text = " | ".join(cell.text for cell in row.cells)
                    if _append_text(
                        result,
                        text,
                        {"table": table_number, "row": row_number},
                        path=path,
                    ) < 0:
                        result.chunks.clear()
                        result.skipped_reason = "DOCX extracted text exceeds the 5 MiB processing limit"
                        return result

        for section_number, section in enumerate(document.sections, start=1):
            for header_type, header in (
                ("header", section.header),
                ("first_header", section.first_page_header),
                ("even_header", section.even_page_header),
            ):
                if header.is_linked_to_previous:
                    continue
                header_paragraph = 0
                header_table = 0
                for block in _iter_blocks(header):
                    if isinstance(block, Paragraph):
                        header_paragraph += 1
                        if _append_text(
                            result,
                            block.text,
                            {header_type: section_number, "paragraph": header_paragraph},
                            path=path,
                        ) < 0:
                            result.chunks.clear()
                            result.skipped_reason = "DOCX extracted text exceeds the 5 MiB processing limit"
                            return result
                    else:
                        header_table += 1
                        for row_number, row in enumerate(block.rows, start=1):
                            if _append_text(
                                result,
                                " | ".join(cell.text for cell in row.cells),
                                {header_type: section_number, "table": header_table, "row": row_number},
                                path=path,
                            ) < 0:
                                result.chunks.clear()
                                result.skipped_reason = "DOCX extracted text exceeds the 5 MiB processing limit"
                                return result

        with ZipFile(BytesIO(data)) as package:
            if "word/comments.xml" in package.namelist():
                comments_xml = package.read("word/comments.xml")
                lowered = comments_xml.lower()
                if b"<!doctype" in lowered or b"<!entity" in lowered:
                    result.chunks.clear()
                    result.skipped_reason = "DOCX comments contain unsupported XML declarations"
                    return result
                comments = ElementTree.fromstring(comments_xml)
                for comment in comments.findall(f"{_WORD_NS}comment"):
                    comment_id = comment.attrib.get(f"{_WORD_NS}id", "unknown")
                    text = "".join(comment.itertext())
                    if _append_text(
                        result,
                        text,
                        {"comment_id": comment_id},
                        path=path,
                    ) < 0:
                        result.chunks.clear()
                        result.skipped_reason = "DOCX extracted text exceeds the 5 MiB processing limit"
                        return result
    except Exception as exc:  # malformed OOXML packages surface varied parser errors
        result.chunks.clear()
        result.skipped_reason = f"Could not extract DOCX ({type(exc).__name__})"
        return result

    if not result.chunks:
        result.skipped_reason = "No text content found"
    return result
