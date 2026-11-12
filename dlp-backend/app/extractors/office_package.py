"""Preflight OOXML ZIP packages before handing them to document parsers."""

from io import BytesIO
from zipfile import BadZipFile, ZipFile

from app.extractors.limits import (
    MAX_ARCHIVE_COMPRESSION_RATIO,
    MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    MAX_OFFICE_ARCHIVE_FILES,
)


def validate_ooxml_package(data: bytes, *, required_part: str, label: str) -> str | None:
    if data.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
        return f"Encrypted/password-protected {label} is not supported"
    try:
        with ZipFile(BytesIO(data)) as package:
            entries = package.infolist()
            if len(entries) > MAX_OFFICE_ARCHIVE_FILES:
                return f"{label} package has too many parts"
            total_size = 0
            for entry in entries:
                if entry.flag_bits & 0x1:
                    return f"Encrypted {label} package is not supported"
                total_size += entry.file_size
                if entry.file_size > max(entry.compress_size, 1) * MAX_ARCHIVE_COMPRESSION_RATIO:
                    return f"{label} package exceeds the 100:1 expansion ratio limit"
            if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                return f"{label} package exceeds the 200 MiB expanded-size limit"
            if required_part not in package.namelist():
                return f"File is not a valid {label} document"
            for entry in entries:
                if not entry.filename.lower().endswith((".xml", ".rels")):
                    continue
                previous = b""
                with package.open(entry) as xml_part:
                    while block := xml_part.read(64 * 1024):
                        check = (previous + block).lower()
                        if b"<!doctype" in check or b"<!entity" in check:
                            return f"{label} XML declarations and entities are not supported"
                        previous = check[-16:]
    except (BadZipFile, OSError, ValueError):
        return f"File is not a valid {label} document"
    return None
