"""SQLite persistence for resumable scan jobs and encrypted upload payloads."""

import base64
from contextlib import closing
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, MultiFernet

from app.config import get_settings
from app.models.scan_job import ScanJobStatus, ScanJobView
from app.models.scan_upload import UploadScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    destination TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    progress INTEGER NOT NULL,
    encrypted_payload BLOB,
    result_json TEXT,
    error_message TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_jobs_owner_created_idx
ON scan_jobs(org_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS scan_jobs_queue_idx
ON scan_jobs(status, created_at);
"""

MAX_PENDING_SCAN_JOBS = 100
MAX_PENDING_SCAN_JOBS_PER_ORG = 25
MAX_PENDING_SCAN_JOBS_PER_USER = 5
MAX_PENDING_UPLOAD_BYTES = 512 * 1024 * 1024


class ScanQueueFull(RuntimeError):
    """The scan queue reached a configured safety bound."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_job_cipher() -> Fernet | MultiFernet:
    """Load a dedicated queue key with a bounded decryption key ring.

    The service-role-derived key remains a legacy fallback for existing local
    queues. New production deployments should set a random dedicated Fernet
    key and use the previous-key list during rotations.
    """
    settings = get_settings()
    keys: list[Fernet] = []
    if settings.scan_jobs_encryption_key:
        try:
            keys.append(Fernet(settings.scan_jobs_encryption_key.encode("ascii")))
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError("SCAN_JOBS_ENCRYPTION_KEY must be a valid Fernet key") from exc

    previous = [value.strip() for value in settings.scan_jobs_previous_encryption_keys.split(",") if value.strip()]
    if len(previous) > 8:
        raise RuntimeError("At most eight previous scan-job encryption keys may be configured")
    for key in previous:
        try:
            keys.append(Fernet(key.encode("ascii")))
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError("A previous scan-job encryption key is invalid") from exc

    legacy_secret = settings.supabase_service_role_key
    if legacy_secret:
        material = hmac.new(
            legacy_secret.encode("utf-8"),
            b"dlp-guardian:scan-job-upload:v1",
            hashlib.sha256,
        ).digest()
        legacy_key = Fernet(base64.urlsafe_b64encode(material))
        if not keys:
            return legacy_key
        keys.append(legacy_key)

    if not keys:
        raise RuntimeError("A scan-job encryption key is required")
    return keys[0] if len(keys) == 1 else MultiFernet(keys)


class ScanJobStore:
    def __init__(self, path: str | Path, cipher: Fernet):
        self.path = str(path)
        self.cipher = cipher
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        if self.path != ":memory:":
            db_path = Path(self.path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(db_path.parent, 0o700)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        if not self._initialized:
            connection.executescript(_SCHEMA)
            self._initialized = True
            if self.path != ":memory:" and os.name != "nt":
                os.chmod(self.path, 0o600)
        return connection

    def create(
        self,
        *,
        org_id: UUID,
        user_id: UUID,
        filename: str,
        destination: str,
        data: bytes,
    ) -> ScanJobView:
        job_id = uuid4()
        now = _utc_now()
        encrypted = self.cipher.encrypt(data)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            pending = connection.execute(
                """SELECT COUNT(*) AS jobs, COALESCE(SUM(size_bytes), 0) AS bytes
                FROM scan_jobs WHERE status IN ('queued','running')"""
            ).fetchone()
            owner_pending = connection.execute(
                """SELECT COUNT(*) AS jobs, COALESCE(SUM(size_bytes), 0) AS bytes
                FROM scan_jobs WHERE status IN ('queued','running') AND org_id=? AND user_id=?""",
                (str(org_id), str(user_id)),
            ).fetchone()
            org_pending = connection.execute(
                """SELECT COUNT(*) AS jobs FROM scan_jobs
                WHERE status IN ('queued','running') AND org_id=?""",
                (str(org_id),),
            ).fetchone()
            if (
                pending["jobs"] >= MAX_PENDING_SCAN_JOBS
                or pending["bytes"] + len(data) > MAX_PENDING_UPLOAD_BYTES
                or org_pending["jobs"] >= MAX_PENDING_SCAN_JOBS_PER_ORG
                or owner_pending["jobs"] >= MAX_PENDING_SCAN_JOBS_PER_USER
            ):
                connection.rollback()
                raise ScanQueueFull("The scan queue is at capacity")
            connection.execute(
                """INSERT INTO scan_jobs
                (id,org_id,user_id,filename,destination,size_bytes,status,phase,progress,encrypted_payload,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(job_id), str(org_id), str(user_id), filename, destination,
                    len(data), ScanJobStatus.QUEUED.value, "queued", 0,
                    encrypted, now, now,
                ),
            )
            connection.commit()
        return self.get(job_id, org_id, user_id)

    def _view(self, row: sqlite3.Row) -> ScanJobView:
        result = UploadScanResult.model_validate_json(row["result_json"]) if row["result_json"] else None
        return ScanJobView(
            id=UUID(row["id"]),
            status=ScanJobStatus(row["status"]),
            phase=row["phase"],
            progress=row["progress"],
            filename=row["filename"],
            size_bytes=row["size_bytes"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            cancel_requested=bool(row["cancel_requested"]),
            error_message=row["error_message"],
            result=result,
        )

    def get(self, job_id: UUID, org_id: UUID, user_id: UUID) -> ScanJobView | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE id=? AND org_id=? AND user_id=?",
                (str(job_id), str(org_id), str(user_id)),
            ).fetchone()
        return self._view(row) if row else None

    def list(self, org_id: UUID, user_id: UUID, *, limit: int = 25) -> list[ScanJobView]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM scan_jobs WHERE org_id=? AND user_id=? ORDER BY created_at DESC LIMIT ?",
                (str(org_id), str(user_id), max(1, min(limit, 100))),
            ).fetchall()
        return [self._view(row) for row in rows]

    def recover_interrupted(self) -> None:
        """Mark in-flight work interrupted and erase its retained upload after restart."""
        now = _utc_now()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE scan_jobs SET status='cancelled', phase='cancelled',
                encrypted_payload=NULL, cancel_requested=0, updated_at=?
                WHERE status='running' AND cancel_requested=1""",
                (now,),
            )
            connection.execute(
                """UPDATE scan_jobs SET status='interrupted', phase='interrupted',
                encrypted_payload=NULL, cancel_requested=0,
                error_message='Backend restarted while this scan was running. Partial results were retained; upload a new file to scan again.',
                updated_at=? WHERE status='running' AND cancel_requested=0""",
                (now,),
            )
            connection.commit()

    def claim_next(self) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE status='queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row:
                connection.execute(
                    "UPDATE scan_jobs SET status='running',phase='extracting',progress=5,updated_at=? WHERE id=? AND status='queued'",
                    (_utc_now(), row["id"]),
                )
            connection.commit()
        return dict(row) if row else None

    def decrypt_payload(self, token: bytes) -> bytes:
        return self.cipher.decrypt(token)

    def partial_result(self, job_id: UUID) -> UploadScanResult | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT result_json FROM scan_jobs WHERE id=?", (str(job_id),)).fetchone()
        return UploadScanResult.model_validate_json(row["result_json"]) if row and row["result_json"] else None

    def save_partial(self, job_id: UUID, result: UploadScanResult, *, phase: str, progress: int) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "UPDATE scan_jobs SET result_json=?,phase=?,progress=?,updated_at=? WHERE id=? AND status='running'",
                (result.model_dump_json(), phase, max(0, min(progress, 99)), _utc_now(), str(job_id)),
            )

    def is_cancel_requested(self, job_id: UUID) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT cancel_requested FROM scan_jobs WHERE id=?", (str(job_id),)).fetchone()
        return bool(row and row["cancel_requested"])

    def request_cancel(self, job_id: UUID, org_id: UUID, user_id: UUID) -> ScanJobView | None:
        now = _utc_now()
        with closing(self._connect()) as connection:
            connection.execute(
                """UPDATE scan_jobs SET
                status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,
                phase=CASE WHEN status='queued' THEN 'cancelled' ELSE phase END,
                encrypted_payload=CASE WHEN status='queued' THEN NULL ELSE encrypted_payload END,
                cancel_requested=CASE WHEN status='running' THEN 1 ELSE cancel_requested END,
                updated_at=? WHERE id=? AND org_id=? AND user_id=? AND status IN ('queued','running')""",
                (now, str(job_id), str(org_id), str(user_id)),
            )
        return self.get(job_id, org_id, user_id)

    def complete(self, job_id: UUID, result: UploadScanResult) -> bool:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """UPDATE scan_jobs SET status='completed',phase='completed',progress=100,
                encrypted_payload=NULL,result_json=?,error_message=NULL,cancel_requested=0,updated_at=?
                WHERE id=? AND status='running' AND cancel_requested=0""",
                (result.model_dump_json(), _utc_now(), str(job_id)),
            )
            return cursor.rowcount == 1

    def cancel_running(self, job_id: UUID) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """UPDATE scan_jobs SET status='cancelled',phase='cancelled',encrypted_payload=NULL,
                cancel_requested=0,updated_at=? WHERE id=? AND status='running'""",
                (_utc_now(), str(job_id)),
            )

    def fail(self, job_id: UUID, error_class: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """UPDATE scan_jobs SET status='failed',phase='failed',encrypted_payload=NULL,
                error_message=?,updated_at=? WHERE id=? AND status='running'""",
                (f"Processing failed ({error_class})", _utc_now(), str(job_id)),
            )


@lru_cache(maxsize=1)
def get_scan_job_store() -> ScanJobStore:
    settings = get_settings()
    return ScanJobStore(settings.scan_jobs_db_path, get_job_cipher())
