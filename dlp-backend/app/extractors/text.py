from app.extractors.chunking import chunk_text
from app.extractors.limits import MAX_FILE_BYTES
from app.extractors.models import ExtractionResult


def decode_text(data: bytes) -> tuple[str | None, str | None, str | None]:
    """Decode common text encodings; return a clear reason for binary input."""
    if len(data) > MAX_FILE_BYTES:
        return None, None, f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit"

    bom_encodings = (
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    )
    for bom, encoding in bom_encodings:
        if data.startswith(bom):
            try:
                return data.decode(encoding), encoding, None
            except UnicodeDecodeError:
                return None, None, "File has an invalid Unicode byte sequence"

    if b"\x00" in data:
        return None, None, "File appears to be binary"
    controls = sum(byte < 0x20 and byte not in (0x09, 0x0A, 0x0C, 0x0D) for byte in data)
    if data and controls / len(data) > 0.02:
        return None, None, "File appears to be binary"

    try:
        return data.decode("utf-8"), "utf-8", None
    except UnicodeDecodeError:
        # Windows exports commonly use Windows-1252. This fallback is
        # lossless for that encoding and avoids inserting replacement bytes.
        try:
            return data.decode("cp1252"), "cp1252", None
        except UnicodeDecodeError:
            return None, None, "File encoding is not supported"


def extract_text_bytes(data: bytes, *, path: str, file_type: str) -> ExtractionResult:
    text, encoding, reason = decode_text(data)
    result = ExtractionResult(path=path, encoding=encoding, skipped_reason=reason)
    if text is not None:
        result.chunks.extend(chunk_text(text, path=path, file_type=file_type))
    return result
