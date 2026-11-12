"""Durable, metadata-only queue for verified GitHub App webhook deliveries."""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3

from app.config import get_settings


_SCHEMA = """
CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
    delivery_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    action TEXT,
    installation_id INTEGER NOT NULL,
    repository_id INTEGER,
    repository_full_name TEXT,
    visibility TEXT,
    ref TEXT,
    before_sha TEXT,
    after_sha TEXT,
    deleted INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    received_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS github_webhook_queue_idx
ON github_webhook_deliveries(state, received_at);
CREATE UNIQUE INDEX IF NOT EXISTS github_webhook_idempotency_idx
ON github_webhook_deliveries(idempotency_key);
"""
MAX_QUEUED_WEBHOOKS = 10_000


class WebhookQueueFull(RuntimeError):
    """The durable webhook queue has reached its configured storage bound."""


@dataclass(frozen=True)
class WebhookDelivery:
    delivery_id: str
    event_type: str
    action: str | None
    installation_id: int
    idempotency_key: str = ""
    repository_id: int | None = None
    repository_full_name: str | None = None
    visibility: str | None = None
    ref: str | None = None
    before_sha: str | None = None
    after_sha: str | None = None
    deleted: bool = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GitHubWebhookStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
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

    def accept(self, delivery: WebhookDelivery) -> bool:
        """Persist the dedupe key and safe routing metadata in one transaction."""
        now = _now()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM github_webhook_deliveries WHERE delivery_id=? OR idempotency_key=? LIMIT 1",
                (delivery.delivery_id, delivery.idempotency_key or delivery.delivery_id),
            ).fetchone()
            if existing:
                connection.commit()
                return False
            pending = connection.execute(
                "SELECT COUNT(*) FROM github_webhook_deliveries WHERE state IN ('queued','processing')"
            ).fetchone()[0]
            if pending >= MAX_QUEUED_WEBHOOKS:
                connection.rollback()
                raise WebhookQueueFull("GitHub webhook queue is full")
            cursor = connection.execute(
                """INSERT OR IGNORE INTO github_webhook_deliveries
                (delivery_id,idempotency_key,event_type,action,installation_id,repository_id,
                 repository_full_name,visibility,ref,before_sha,after_sha,deleted,
                 state,received_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'queued',?,?)""",
                (
                    delivery.delivery_id, delivery.idempotency_key or delivery.delivery_id,
                    delivery.event_type, delivery.action,
                    delivery.installation_id, delivery.repository_id,
                    delivery.repository_full_name, delivery.visibility, delivery.ref,
                    delivery.before_sha, delivery.after_sha, int(delivery.deleted), now, now,
                ),
            )
            connection.commit()
            return cursor.rowcount == 1

    def claim_next(self) -> WebhookDelivery | None:
        """Atomically claim one queued delivery for a later repository worker."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM github_webhook_deliveries WHERE state='queued' ORDER BY received_at LIMIT 1"
            ).fetchone()
            if row:
                connection.execute(
                    "UPDATE github_webhook_deliveries SET state='processing',attempts=attempts+1,updated_at=? WHERE delivery_id=? AND state='queued'",
                    (_now(), row["delivery_id"]),
                )
            connection.commit()
        if not row:
            return None
        return WebhookDelivery(
            delivery_id=row["delivery_id"], event_type=row["event_type"], action=row["action"],
            installation_id=row["installation_id"], repository_id=row["repository_id"],
            idempotency_key=row["idempotency_key"],
            repository_full_name=row["repository_full_name"], visibility=row["visibility"],
            ref=row["ref"], before_sha=row["before_sha"], after_sha=row["after_sha"],
            deleted=bool(row["deleted"]),
        )

    def finish(self, delivery_id: str, *, retry: bool = False) -> bool:
        """Mark complete or return a failed item to the durable queue."""
        state = "queued" if retry else "completed"
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "UPDATE github_webhook_deliveries SET state=?,updated_at=? WHERE delivery_id=? AND state='processing'",
                (state, _now(), delivery_id),
            )
            return cursor.rowcount == 1

    def recover_processing(self) -> int:
        """Return deliveries abandoned by a process restart to the durable queue."""
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "UPDATE github_webhook_deliveries SET state='queued',updated_at=? WHERE state='processing'",
                (_now(),),
            )
            return cursor.rowcount


def get_github_webhook_store() -> GitHubWebhookStore:
    return GitHubWebhookStore(get_settings().scan_jobs_db_path)
