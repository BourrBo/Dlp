from io import BytesIO
from xml.etree import ElementTree

from app.extractors.chunking import chunk_text
from app.extractors.models import ExtractionResult
from app.extractors.text import decode_text


def _local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def extract_xml(data: bytes, *, path: str) -> ExtractionResult:
    text, encoding, reason = decode_text(data)
    result = ExtractionResult(path=path, encoding=encoding, skipped_reason=reason)
    if text is None:
        return result
    if "<!doctype" in text.lower() or "<!entity" in text.lower():
        result.skipped_reason = "XML DTDs and entity declarations are not supported"
        return result

    stack: list[str] = []
    try:
        for event, element in ElementTree.iterparse(BytesIO(data), events=("start", "end")):
            name = _local_name(element.tag)
            if event == "start":
                stack.append(name)
                element_path = "/" + "/".join(stack)
                for attribute, value in element.attrib.items():
                    rendered = f"{_local_name(attribute)} = {value}"
                    result.chunks.extend(
                        chunk_text(
                            rendered,
                            path=path,
                            file_type="xml",
                            location={"xml_path": f"{element_path}/@{_local_name(attribute)}"},
                        )
                    )
            else:
                element_path = "/" + "/".join(stack)
                if element.text and element.text.strip():
                    result.chunks.extend(
                        chunk_text(
                            element.text,
                            path=path,
                            file_type="xml",
                            location={"xml_path": element_path},
                        )
                    )
                if element.tail and element.tail.strip():
                    parent_path = "/" + "/".join(stack[:-1])
                    result.chunks.extend(
                        chunk_text(
                            element.tail,
                            path=path,
                            file_type="xml",
                            location={"xml_path": parent_path or "/"},
                        )
                    )
                stack.pop()
                element.clear()
    except (ElementTree.ParseError, ValueError) as exc:
        result.chunks.clear()
        result.skipped_reason = f"Invalid XML: {exc}"
    return result
