import base64
import hashlib
import hmac
from pathlib import Path
from contextlib import closing
from tempfile import TemporaryDirectory
from io import BytesIO
import sqlite3
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4, uuid5

from cryptography.fernet import Fernet

from app.models.finding import DataType, Decision, Finding, ScanResult
from app.auth import AuthenticatedPrincipal
from app.models.scan_job import ScanJobStatus
from app.models.scan_upload import UploadedChunkResult, UploadedFileResult, UploadScanResult
from app.extractors.models import ExtractedChunk, ExtractionResult
from app.services.scan_job_store import ScanJobStore, ScanQueueFull, get_job_cipher
from app.services.scan_job_worker import process_job
from app.routers.scan_jobs import cancel_scan_job, get_scan_job, list_scan_jobs, submit_scan_job
from starlette.datastructures import UploadFile


ORG_ID = UUID("22222222-2222-2222-2222-222222222222")
USER_ID = UUID("33333333-3333-3333-3333-333333333333")
PRINCIPAL = AuthenticatedPrincipal(user_id=USER_ID, org_id=ORG_ID, access_token="verified-token")


class ScanJobStoreTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[1] / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.directory = TemporaryDirectory(dir=scratch)
        self.db_path = Path(self.directory.name) / "jobs.sqlite3"
        self.cipher = Fernet(Fernet.generate_key())
        self.store = ScanJobStore(self.db_path, self.cipher)

    def tearDown(self):
        self.directory.cleanup()

    def create_job(self, data=b"private@example.com"):
        return self.store.create(
            org_id=ORG_ID,
            user_id=USER_ID,
            filename="customers.txt",
            destination="external.example",
            data=data,
        )

    def test_upload_payload_is_encrypted_in_persistent_sqlite(self):
        raw = b"private@example.com"
        job = self.create_job(raw)
        with closing(sqlite3.connect(self.db_path)) as connection:
            stored = connection.execute("SELECT encrypted_payload FROM scan_jobs WHERE id=?", (str(job.id),)).fetchone()[0]
        self.assertNotIn(raw, stored)
        self.assertEqual(self.store.decrypt_payload(stored), raw)

    def test_dedicated_encryption_key_reads_legacy_queue_during_migration(self):
        legacy_secret = "legacy-service-key"
        legacy_material = hmac.new(
            legacy_secret.encode(), b"dlp-guardian:scan-job-upload:v1", hashlib.sha256
        ).digest()
        legacy_cipher = Fernet(base64.urlsafe_b64encode(legacy_material))
        old_token = legacy_cipher.encrypt(b"queued upload")
        dedicated_key = Fernet.generate_key()
        settings = type("SettingsStub", (), {
            "scan_jobs_encryption_key": dedicated_key.decode("ascii"),
            "scan_jobs_previous_encryption_keys": "",
            "supabase_service_role_key": legacy_secret,
        })()
        with patch("app.services.scan_job_store.get_settings", return_value=settings):
            cipher = get_job_cipher()
            self.assertEqual(cipher.decrypt(old_token), b"queued upload")
            new_token = cipher.encrypt(b"new upload")
            self.assertEqual(Fernet(dedicated_key).decrypt(new_token), b"new upload")

    def test_previous_encryption_key_supports_controlled_rotation(self):
        previous_key = Fernet.generate_key()
        current_key = Fernet.generate_key()
        previous_token = Fernet(previous_key).encrypt(b"still queued")
        settings = type("SettingsStub", (), {
            "scan_jobs_encryption_key": current_key.decode("ascii"),
            "scan_jobs_previous_encryption_keys": previous_key.decode("ascii"),
            "supabase_service_role_key": "",
        })()
        with patch("app.services.scan_job_store.get_settings", return_value=settings):
            cipher = get_job_cipher()
            self.assertEqual(cipher.decrypt(previous_token), b"still queued")
            self.assertEqual(Fernet(current_key).decrypt(cipher.encrypt(b"new")), b"new")

    def test_queue_enforces_per_user_pending_job_limit_atomically(self):
        with patch("app.services.scan_job_store.MAX_PENDING_SCAN_JOBS_PER_USER", 1):
            self.create_job(b"first")
            with self.assertRaises(ScanQueueFull):
                self.create_job(b"second")

    def test_queue_enforces_pending_upload_byte_limit(self):
        with patch("app.services.scan_job_store.MAX_PENDING_UPLOAD_BYTES", 5):
            self.create_job(b"12345")
            with self.assertRaises(ScanQueueFull):
                self.create_job(b"x")

    def test_queued_cancel_erases_encrypted_upload(self):
        job = self.create_job()
        cancelled = self.store.request_cancel(job.id, ORG_ID, USER_ID)
        self.assertEqual(cancelled.status, ScanJobStatus.CANCELLED)
        with closing(sqlite3.connect(self.db_path)) as connection:
            payload = connection.execute("SELECT encrypted_payload FROM scan_jobs WHERE id=?", (str(job.id),)).fetchone()[0]
        self.assertIsNone(payload)

    def test_restart_preserves_queued_job_for_worker(self):
        job = self.create_job()
        self.store.recover_interrupted()
        queued = self.store.get(job.id, ORG_ID, USER_ID)
        self.assertEqual(queued.status, ScanJobStatus.QUEUED)
        claimed = self.store.claim_next()
        self.assertEqual(claimed["id"], str(job.id))

    def test_restart_marks_running_job_interrupted_keeps_partial_results_and_erases_upload(self):
        job = self.create_job()
        claimed = self.store.claim_next()
        partial = UploadScanResult(files=[UploadedFileResult(filename="customers.txt", size_bytes=job.size_bytes)])
        partial.files[0].chunks.append(
            UploadedChunkResult(location={"line_start": 1}, findings=[], decision=Decision.ALLOW, reason="test")
        )
        self.store.save_partial(job.id, partial, phase="scanning", progress=50)
        self.store.recover_interrupted()
        recovered = self.store.get(job.id, ORG_ID, USER_ID)
        self.assertEqual(recovered.status, ScanJobStatus.INTERRUPTED)
        self.assertEqual(recovered.progress, 50)
        self.assertEqual(len(recovered.result.files[0].chunks), 1)
        self.assertIn("upload a new file", recovered.error_message)
        self.assertIsNone(self.store.claim_next())
        with closing(sqlite3.connect(self.db_path)) as connection:
            payload = connection.execute("SELECT encrypted_payload FROM scan_jobs WHERE id=?", (str(job.id),)).fetchone()[0]
        self.assertIsNone(payload)
        self.assertEqual(claimed["id"], str(job.id))

    def test_worker_completes_job_with_deterministic_event_id_and_clears_upload(self):
        job = self.create_job()
        claimed = self.store.claim_next()
        extraction = ExtractionResult(
            path="customers.txt",
            chunks=[ExtractedChunk(text="private@example.com", location={"line_start": 1})],
        )
        scan_result = ScanResult(findings=[], decision=Decision.ALLOW, reason="test")
        with (
            patch("app.services.scan_job_worker.extract_bytes_with_timeout", return_value=extraction),
            patch("app.services.scan_job_worker.scan_for_verified_user", return_value=scan_result) as scan,
        ):
            process_job(self.store, claimed)
        completed = self.store.get(job.id, ORG_ID, USER_ID)
        self.assertEqual(completed.status, ScanJobStatus.COMPLETED)
        self.assertEqual(completed.progress, 100)
        self.assertEqual(scan.call_args.args[0].event_id, uuid5(job.id, "chunk:0"))
        with closing(sqlite3.connect(self.db_path)) as connection:
            payload = connection.execute("SELECT encrypted_payload FROM scan_jobs WHERE id=?", (str(job.id),)).fetchone()[0]
        self.assertIsNone(payload)

    def test_running_cancel_is_observed_by_worker(self):
        job = self.create_job()
        claimed = self.store.claim_next()
        self.store.request_cancel(job.id, ORG_ID, USER_ID)
        process_job(self.store, claimed)
        cancelled = self.store.get(job.id, ORG_ID, USER_ID)
        self.assertEqual(cancelled.status, ScanJobStatus.CANCELLED)


class IdempotentEventTests(unittest.TestCase):
    def test_duplicate_job_event_does_not_send_duplicate_alert(self):
        from app.routers.detect import scan
        from app.models.finding import Channel, ScanRequest

        event_id = uuid4()
        request = ScanRequest(
            org_id=ORG_ID,
            user_id=USER_ID,
            channel=Channel.API,
            destination="external.example",
            content="contact private@example.com",
            event_id=event_id,
        )
        with (
            patch(
                "app.routers.detect.detection_service.detect",
                return_value=[Finding(data_type=DataType.EMAIL_PII, confidence=0.9, matched_snippet="pr***********om")],
            ),
            patch("app.routers.detect.policy_engine.evaluate", return_value=(Decision.BLOCK, None, "blocked")),
            patch("app.routers.detect.database.post_scan_event", return_value={}) as persist,
            patch("app.routers.detect.send_alert") as alert,
            patch("app.routers.detect.resolve_org", side_effect=lambda principal, org_id: org_id or principal.org_id),
        ):
            result = scan(request, PRINCIPAL)
        self.assertTrue(result.findings)
        self.assertEqual(persist.call_args.args[0]["id"], str(event_id))
        alert.assert_not_called()


class ScanJobApiTests(unittest.TestCase):
    def test_submit_list_poll_and_cancel_job(self):
        scratch = Path(__file__).resolve().parents[1] / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        with TemporaryDirectory(dir=scratch) as temporary:
            store = ScanJobStore(Path(temporary) / "jobs.sqlite3", Fernet(Fernet.generate_key()))
            upload = UploadFile(file=BytesIO(b"customer@example.com"), filename="C:\\reports\\customer.txt")
            with (
                patch("app.routers.scan_jobs._store", return_value=store),
                patch("app.routers.scan_jobs.resolve_org", side_effect=lambda principal, org_id: org_id or principal.org_id),
            ):
                created = submit_scan_job(
                    principal=PRINCIPAL,
                    file=upload,
                    org_id=ORG_ID,
                    destination="external.example",
                )
                self.assertEqual(created.filename, "customer.txt")
                self.assertEqual(created.status, ScanJobStatus.QUEUED)
                self.assertEqual(list_scan_jobs(PRINCIPAL, ORG_ID, limit=25).jobs[0].id, created.id)
                self.assertEqual(get_scan_job(created.id, principal=PRINCIPAL, org_id=ORG_ID).id, created.id)
                cancelled = cancel_scan_job(created.id, principal=PRINCIPAL, org_id=ORG_ID)
        self.assertEqual(cancelled.status, ScanJobStatus.CANCELLED)


if __name__ == "__main__":
    unittest.main()
