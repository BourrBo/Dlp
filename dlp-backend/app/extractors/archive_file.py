"""In-memory ZIP/TAR/GZIP ingestion with shared expansion and file budgets."""

from dataclasses import dataclass
from gzip import BadGzipFile, GzipFile
from io import BytesIO
from pathlib import PurePosixPath, PureWindowsPath
import stat
import tarfile
from zipfile import BadZipFile, ZipFile

from app.extractors.limits import (
    MAX_ARCHIVE_COMPRESSION_RATIO,
    MAX_ARCHIVE_DEPTH,
    MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    MAX_FILE_BYTES,
    MAX_FILES_PER_SCAN,
)
from app.extractors.models import ExtractionResult

ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".gz")
READ_BLOCK_BYTES = 64 * 1024


@dataclass
class ArchiveBudget:
    files: int = 0
    uncompressed_bytes: int = 0

    def consume(self, size: int) -> str | None:
        self.files += 1
        self.uncompressed_bytes += size
        if self.files > MAX_FILES_PER_SCAN:
            return f"Archive scan exceeds the {MAX_FILES_PER_SCAN}-file limit"
        if self.uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            return "Archive scan exceeds the 200 MiB expanded-size limit"
        return None


def is_archive_path(path: str) -> bool:
    return path.lower().endswith(ARCHIVE_SUFFIXES)


def _safe_member(name: str) -> str | None:
    if not name or "\x00" in name:
        return "Archive contains an invalid empty or NUL-containing member path"
    normalized = name.replace("\\", "/")
    windows_path = PureWindowsPath(name)
    posix_path = PurePosixPath(normalized)
    if windows_path.is_absolute() or windows_path.drive or posix_path.is_absolute():
        return f"Archive contains an absolute member path: {name[:120]}"
    if any(part == ".." for part in normalized.split("/")):
        return f"Archive contains a traversal member path: {name[:120]}"
    return None


def _read_member(stream, *, limit: int) -> bytes:
    output = BytesIO()
    while block := stream.read(min(READ_BLOCK_BYTES, limit + 1 - output.tell())):
        output.write(block)
        if output.tell() > limit:
            raise ValueError("member exceeds the per-file limit")
    return output.getvalue()


def _archive_error(path: str, reason: str) -> ExtractionResult:
    return ExtractionResult(path=path, skipped_reason=reason)


def extract_archive_bytes(
    data: bytes,
    *,
    path: str,
    depth: int = 0,
    budget: ArchiveBudget | None = None,
) -> ExtractionResult:
    """Extract all supported members without creating files on disk.

    A single unsafe or unscannable member invalidates the archive result so
    callers never mistake a partial scan for a clean archive.
    """
    budget = budget or ArchiveBudget()
    if depth > MAX_ARCHIVE_DEPTH:
        return _archive_error(path, f"Nested archives exceed the depth-{MAX_ARCHIVE_DEPTH} limit")

    lower = path.lower()
    if lower.endswith(".zip"):
        return _extract_zip(data, path=path, depth=depth, budget=budget)
    if lower.endswith((".tar", ".tar.gz", ".tgz")):
        return _extract_tar(data, path=path, depth=depth, budget=budget, compressed=not lower.endswith(".tar"))
    return _extract_gzip(data, path=path, depth=depth, budget=budget)


def _scan_member(data: bytes, *, member_path: str, depth: int, budget: ArchiveBudget) -> ExtractionResult:
    if is_archive_path(member_path):
        result = extract_archive_bytes(data, path=member_path, depth=depth + 1, budget=budget)
    else:
        from app.extractors.registry import extract_bytes

        result = extract_bytes(data, display_path=member_path)
        if result.skipped_reason:
            return result
    if result.skipped_reason:
        return result
    for chunk in result.chunks:
        chunk.location.setdefault("archive_member", member_path)
    return result


def _extract_zip(data: bytes, *, path: str, depth: int, budget: ArchiveBudget) -> ExtractionResult:
    result = ExtractionResult(path=path)
    try:
        with ZipFile(BytesIO(data)) as package:
            entries = package.infolist()
            if len(entries) > MAX_FILES_PER_SCAN - budget.files:
                return _archive_error(path, f"Archive scan exceeds the {MAX_FILES_PER_SCAN}-file limit")
            regular_entries = []
            expanded_bytes = 0
            seen_names = set()
            for entry in entries:
                unsafe = _safe_member(entry.filename)
                if unsafe:
                    return _archive_error(path, unsafe)
                collision_key = entry.filename.casefold()
                if collision_key in seen_names:
                    return _archive_error(path, f"Archive contains a duplicate or case-colliding member path: {entry.filename[:120]}")
                seen_names.add(collision_key)
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode):
                    return _archive_error(path, f"Archive contains a symbolic link: {entry.filename[:120]}")
                if entry.is_dir():
                    continue
                file_kind = stat.S_IFMT(mode)
                if file_kind and file_kind != stat.S_IFREG:
                    return _archive_error(path, f"Archive contains a special file: {entry.filename[:120]}")
                if entry.flag_bits & 0x1:
                    return _archive_error(path, "Encrypted ZIP members are not supported")
                if entry.file_size > MAX_FILE_BYTES:
                    return _archive_error(path, f"Archive member exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB per-file limit")
                if entry.file_size > max(entry.compress_size, 1) * MAX_ARCHIVE_COMPRESSION_RATIO:
                    return _archive_error(path, "Archive member exceeds the 100:1 compression ratio limit")
                expanded_bytes += entry.file_size
                regular_entries.append(entry)
            if expanded_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                return _archive_error(path, "Archive exceeds the 200 MiB expanded-size limit")
            if len(regular_entries) > MAX_FILES_PER_SCAN - budget.files:
                return _archive_error(path, f"Archive scan exceeds the {MAX_FILES_PER_SCAN}-file limit")
            for entry in regular_entries:
                member_path = f"{path}/{entry.filename}"
                try:
                    with package.open(entry) as source:
                        member_data = _read_member(source, limit=MAX_FILE_BYTES)
                except (RuntimeError, OSError, ValueError) as exc:
                    return _archive_error(path, f"Could not safely read ZIP member ({type(exc).__name__})")
                budget_error = budget.consume(len(member_data))
                if budget_error:
                    return _archive_error(path, budget_error)
                member_result = _scan_member(member_data, member_path=member_path, depth=depth, budget=budget)
                if member_result.skipped_reason:
                    return _archive_error(path, f"Archive member was not fully scanned: {member_result.skipped_reason}")
                result.chunks.extend(member_result.chunks)
    except (BadZipFile, OSError, ValueError) as exc:
        return _archive_error(path, f"Invalid or unsafe ZIP archive ({type(exc).__name__})")
    if not result.chunks:
        result.skipped_reason = "Archive contains no supported text content"
    return result


def _extract_tar(data: bytes, *, path: str, depth: int, budget: ArchiveBudget, compressed: bool) -> ExtractionResult:
    try:
        if compressed:
            stream = GzipFile(fileobj=BytesIO(data), mode="rb")
            try:
                tar_bytes = _read_member(stream, limit=MAX_ARCHIVE_UNCOMPRESSED_BYTES)
            finally:
                stream.close()
            if len(tar_bytes) > max(len(data), 1) * MAX_ARCHIVE_COMPRESSION_RATIO:
                return _archive_error(path, "Archive exceeds the 100:1 compression ratio limit")
            package = tarfile.open(fileobj=BytesIO(tar_bytes), mode="r:")
        else:
            package = tarfile.open(fileobj=BytesIO(data), mode="r:")
    except (BadGzipFile, OSError, EOFError, tarfile.TarError, ValueError) as exc:
        return _archive_error(path, f"Invalid or unsafe TAR/GZIP archive ({type(exc).__name__})")

    result = ExtractionResult(path=path)
    with package:
        try:
            regular_entries = []
            expanded_bytes = 0
            seen_names = set()
            for entry in package:
                unsafe = _safe_member(entry.name)
                if unsafe:
                    return _archive_error(path, unsafe)
                collision_key = entry.name.casefold()
                if collision_key in seen_names:
                    return _archive_error(path, f"Archive contains a duplicate or case-colliding member path: {entry.name[:120]}")
                seen_names.add(collision_key)
                if entry.isdir():
                    continue
                if not entry.isfile():
                    return _archive_error(path, f"Archive contains a link or special file: {entry.name[:120]}")
                if len(regular_entries) >= MAX_FILES_PER_SCAN - budget.files:
                    return _archive_error(path, f"Archive scan exceeds the {MAX_FILES_PER_SCAN}-file limit")
                if entry.size > MAX_FILE_BYTES:
                    return _archive_error(path, f"Archive member exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB per-file limit")
                expanded_bytes += entry.size
                regular_entries.append(entry)
            if expanded_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                return _archive_error(path, "Archive exceeds the 200 MiB expanded-size limit")
            if len(regular_entries) > MAX_FILES_PER_SCAN - budget.files:
                return _archive_error(path, f"Archive scan exceeds the {MAX_FILES_PER_SCAN}-file limit")
            for entry in regular_entries:
                source = package.extractfile(entry)
                if source is None:
                    return _archive_error(path, "Could not read TAR member")
                with source:
                    member_data = _read_member(source, limit=MAX_FILE_BYTES)
                budget_error = budget.consume(len(member_data))
                if budget_error:
                    return _archive_error(path, budget_error)
                member_path = f"{path}/{entry.name}"
                member_result = _scan_member(member_data, member_path=member_path, depth=depth, budget=budget)
                if member_result.skipped_reason:
                    return _archive_error(path, f"Archive member was not fully scanned: {member_result.skipped_reason}")
                result.chunks.extend(member_result.chunks)
        except (OSError, tarfile.TarError, ValueError) as exc:
            return _archive_error(path, f"Invalid or unsafe TAR archive ({type(exc).__name__})")
    if not result.chunks:
        result.skipped_reason = "Archive contains no supported text content"
    return result


def _extract_gzip(data: bytes, *, path: str, depth: int, budget: ArchiveBudget) -> ExtractionResult:
    try:
        stream = GzipFile(fileobj=BytesIO(data), mode="rb")
        try:
            payload = _read_member(stream, limit=MAX_ARCHIVE_UNCOMPRESSED_BYTES)
        finally:
            stream.close()
    except (BadGzipFile, OSError, EOFError, ValueError) as exc:
        return _archive_error(path, f"Invalid or unsafe GZIP archive ({type(exc).__name__})")
    if len(payload) > max(len(data), 1) * MAX_ARCHIVE_COMPRESSION_RATIO:
        return _archive_error(path, "Archive exceeds the 100:1 compression ratio limit")
    output_name = path[:-3] if path.lower().endswith(".gz") else path
    if output_name.lower().endswith(".tar"):
        return _extract_tar(payload, path=output_name, depth=depth, budget=budget, compressed=False)
    budget_error = budget.consume(len(payload))
    if budget_error:
        return _archive_error(path, budget_error)
    member_result = _scan_member(payload, member_path=output_name, depth=depth, budget=budget)
    if member_result.skipped_reason:
        return _archive_error(path, f"GZIP payload was not fully scanned: {member_result.skipped_reason}")
    member_result.path = path
    return member_result
