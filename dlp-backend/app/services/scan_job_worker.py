"""Single-process background worker for durable scan jobs."""

from threading import Event, Thread
from uuid import UUID, uuid5

from app.extractors.runner import extract_bytes_with_timeout
from app.models.finding import Channel, ScanRequest
from app.models.scan_job import ScanJobStatus
from app.models.scan_upload import UploadedChunkResult, UploadedFileResult, UploadScanResult
from app.routers.detect import scan_for_verified_user
from app.services.scan_job_store import ScanJobStore


def _complete_or_cancel(store: ScanJobStore, job_id: UUID, result: UploadScanResult) -> bool:
    if store.complete(job_id, result):
        return True
    if store.is_cancel_requested(job_id):
        store.cancel_running(job_id)
        return False
    raise RuntimeError("Scan job state changed before completion")


def process_job(store: ScanJobStore, job: dict) -> None:
    job_id = UUID(job["id"])
    try:
        if store.is_cancel_requested(job_id):
            store.cancel_running(job_id)
            return
        encrypted_payload = job.get("encrypted_payload")
        if encrypted_payload is None:
            raise ValueError("Job upload payload is missing")
        data = store.decrypt_payload(encrypted_payload)
        extracted = extract_bytes_with_timeout(data, display_path=job["filename"])
        output = UploadedFileResult(
            filename=job["filename"],
            size_bytes=job["size_bytes"],
            extracted_chars=extracted.extracted_chars,
            encoding=extracted.encoding,
            skipped_reason=extracted.skipped_reason,
        )
        result = UploadScanResult(files=[output])
        if store.is_cancel_requested(job_id):
            store.cancel_running(job_id)
            return
        if extracted.skipped_reason:
            _complete_or_cancel(store, job_id, result)
            return

        prior = store.partial_result(job_id)
        if prior and prior.files:
            output.chunks.extend(prior.files[0].chunks)
        total_chunks = len(extracted.chunks)
        store.save_partial(job_id, result, phase="scanning", progress=25)
        for index, chunk in enumerate(extracted.chunks):
            if index < len(output.chunks):
                continue
            if store.is_cancel_requested(job_id):
                store.cancel_running(job_id)
                return
            scan_result = scan_for_verified_user(
                ScanRequest(
                    org_id=UUID(job["org_id"]),
                    user_id=UUID(job["user_id"]),
                    channel=Channel.API,
                    destination=job["destination"],
                    content=chunk.text,
                    filename=job["filename"],
                    event_id=uuid5(job_id, f"chunk:{index}"),
                ),
                UUID(job["user_id"]),
            )
            output.chunks.append(
                UploadedChunkResult(
                    location=chunk.location,
                    findings=scan_result.findings,
                    decision=scan_result.decision,
                    reason=scan_result.reason,
                )
            )
            progress = 25 + int((index + 1) / max(total_chunks, 1) * 70)
            store.save_partial(job_id, result, phase="scanning", progress=progress)

        if store.is_cancel_requested(job_id):
            store.cancel_running(job_id)
            return
        _complete_or_cancel(store, job_id, result)
    except Exception as exc:
        store.fail(job_id, type(exc).__name__)


class ScanJobWorker:
    def __init__(self, store: ScanJobStore, *, poll_seconds: float = 0.5):
        self.store = store
        self.poll_seconds = poll_seconds
        self._stop = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.store.recover_interrupted()
        self._stop.clear()
        self._thread = Thread(target=self._run, name="dlp-scan-jobs", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            job = self.store.claim_next()
            if job is None:
                self._stop.wait(self.poll_seconds)
                continue
            process_job(self.store, job)
