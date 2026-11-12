"""Run untrusted document parsers in a killable process with a hard deadline."""

from multiprocessing import get_context
from multiprocessing.connection import Connection
import os
from time import monotonic

from app.extractors.limits import FILE_TIMEOUT_SECONDS, MAX_FILE_BYTES
from app.extractors.models import ExtractionResult
from app.extractors.registry import extract_bytes


def _extract_in_child(connection: Connection, data: bytes, filename: str) -> None:
    try:
        if os.name != "nt":
            import resource

            memory_limit = 768 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        connection.send((True, extract_bytes(data, display_path=filename)))
    except BaseException as exc:
        # Return only the exception type; parser exceptions may include document text.
        try:
            connection.send((False, type(exc).__name__))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()


def extract_bytes_with_timeout(data: bytes, *, display_path: str) -> ExtractionResult:
    """Parse one bounded upload in a subprocess that is terminated at timeout."""
    if len(data) > MAX_FILE_BYTES:
        return extract_bytes(data, display_path=display_path)

    parent, child = get_context("spawn").Pipe(duplex=False)
    process = get_context("spawn").Process(
        target=_extract_in_child,
        args=(child, data, display_path),
        daemon=True,
    )
    started = monotonic()
    try:
        process.start()
        child.close()
        remaining = max(0.0, FILE_TIMEOUT_SECONDS - (monotonic() - started))
        if not parent.poll(remaining):
            return ExtractionResult(
                path=display_path,
                skipped_reason=f"Extraction exceeded the {FILE_TIMEOUT_SECONDS}-second time limit",
            )
        try:
            ok, value = parent.recv()
        except (EOFError, OSError):
            return ExtractionResult(path=display_path, skipped_reason="Extractor stopped unexpectedly")
        if ok:
            return value
        return ExtractionResult(path=display_path, skipped_reason=f"Could not extract file ({value})")
    finally:
        parent.close()
        child.close()
        if process.pid is not None:
            process.join(timeout=0.25)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
