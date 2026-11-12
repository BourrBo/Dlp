"""SQLite store for endpoint-agent devices: enrolment, keys, heartbeat, events, config.

Secrets (enrolment tokens, device keys) are shown once and stored only as
SHA-256 hashes. Events carry masked metadata only; the schema has no column
for file content or raw matched values.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.config import get_settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_enrolment_tokens (
    token_hash TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    os_name TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    tamper_flags TEXT NOT NULL DEFAULT '[]',
    tamper_at TEXT,
    queue_depth INTEGER NOT NULL DEFAULT 0,
    config_version INTEGER NOT NULL DEFAULT 0,
    enrolled_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS devices_org_idx ON devices(org_id, enrolled_at);
CREATE TABLE IF NOT EXISTS device_events (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    decision TEXT NOT NULL,
    folder_class TEXT NOT NULL,
    filename TEXT,
    data_types TEXT NOT NULL,
    findings_count INTEGER NOT NULL,
    quarantined INTEGER NOT NULL,
    detail TEXT,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS device_events_org_idx ON device_events(org_id, received_at DESC);
CREATE INDEX IF NOT EXISTS device_events_device_idx ON device_events(device_id, received_at DESC);
CREATE TABLE IF NOT EXISTS device_org_config (
    org_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

DEFAULT_CONFIG: dict[str, Any] = {
    "watch_folders": ["~/Downloads", "~/Desktop", "~/Documents"],
    "stable_seconds": 3,
    "max_file_bytes": 25 * 1024 * 1024,
    "unscannable_action": "warn",       # allow | warn | block
    "scan_removable_drives": True,
    "quarantine_on_block": True,
    "clipboard_monitoring": False,
    "heartbeat_seconds": 60,
}
MAX_EVENTS_PER_DEVICE = 100_000  # oldest rows are pruned beyond this


@dataclass(frozen=True)
class Device:
    device_id: str
    org_id: str
    hostname: str
    os_name: str
    agent_version: str
    state: str
    tamper_flags: list[str]
    tamper_at: str | None
    queue_depth: int
    config_version: int
    enrolled_at: str
    last_seen_at: str | None
    revoked_at: str | None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a normalised config or raise ValueError."""
    unknown = set(config) - set(DEFAULT_CONFIG)
    if unknown:
        raise ValueError(f"Unknown config keys: {', '.join(sorted(unknown))}")
    merged = {**DEFAULT_CONFIG, **config}
    folders = merged["watch_folders"]
    if not isinstance(folders, list) or not 1 <= len(folders) <= 20 or not all(
        isinstance(f, str) and 1 <= len(f) <= 260 and "\x00" not in f for f in folders
    ):
        raise ValueError("watch_folders must be 1-20 folder paths of up to 260 characters")
    ranges = {"stable_seconds": (1, 3600), "max_file_bytes": (1024, 100 * 1024 * 1024), "heartbeat_seconds": (30, 3600)}
    for key, (low, high) in ranges.items():
        value = merged[key]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{key} must be an integer between {low} and {high}")
    if merged["unscannable_action"] not in {"allow", "warn", "block"}:
        raise ValueError("unscannable_action must be allow, warn or block")
    for key in ("scan_removable_drives", "quarantine_on_block", "clipboard_monitoring"):
        if not isinstance(merged[key], bool):
            raise ValueError(f"{key} must be true or false")
    return merged


class DeviceStore:
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

    # ------------------------------------------------------------ enrolment
    def create_enrolment_token(self, org_id: str, ttl_seconds: int = 86_400) -> tuple[str, str]:
        token = "dlpe_" + secrets.token_urlsafe(24)
        now = _now()
        with closing(self._connect()) as db:
            db.execute(
                "INSERT INTO device_enrolment_tokens(token_hash,org_id,expires_at,created_at) VALUES (?,?,?,?)",
                (hash_secret(token), org_id, _iso(now + timedelta(seconds=ttl_seconds)), _iso(now)),
            )
        return token, _iso(now + timedelta(seconds=ttl_seconds))

    def enrol(self, token: str, hostname: str, os_name: str, agent_version: str) -> tuple[Device, str] | None:
        """Consume a single-use token atomically; return the device and its one-time key."""
        now = _now()
        key = "dlpd_" + secrets.token_urlsafe(32)
        device_id = str(uuid4())
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT org_id, expires_at, used_at FROM device_enrolment_tokens WHERE token_hash=?",
                (hash_secret(token),),
            ).fetchone()
            if not row or row["used_at"] or row["expires_at"] < _iso(now):
                db.rollback()
                return None
            db.execute("UPDATE device_enrolment_tokens SET used_at=? WHERE token_hash=?", (_iso(now), hash_secret(token)))
            config_version = self._config_version(db, row["org_id"])
            db.execute(
                """INSERT INTO devices(device_id,org_id,key_hash,hostname,os_name,agent_version,
                   config_version,enrolled_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                (device_id, row["org_id"], hash_secret(key), hostname, os_name, agent_version,
                 config_version, _iso(now), _iso(now)),
            )
            db.commit()
        return self.get(device_id), key  # type: ignore[return-value]

    # ----------------------------------------------------------------- auth
    def authenticate(self, device_key: str) -> Device | None:
        """Active devices only: a revoked key is rejected on its very next request."""
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM devices WHERE key_hash=? AND state='active'", (hash_secret(device_key),)).fetchone()
        return self._device(row) if row else None

    def get(self, device_id: str) -> Device | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        return self._device(row) if row else None

    def list_devices(self, org_id: str) -> list[Device]:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM devices WHERE org_id=? ORDER BY enrolled_at DESC", (org_id,)).fetchall()
        return [self._device(r) for r in rows]

    def revoke(self, device_id: str) -> bool:
        with closing(self._connect()) as db:
            cur = db.execute(
                "UPDATE devices SET state='revoked', revoked_at=? WHERE device_id=? AND state='active'",
                (_iso(_now()), device_id),
            )
        return cur.rowcount == 1

    # ------------------------------------------------------------ heartbeat
    def heartbeat(self, device_id: str, agent_version: str, queue_depth: int, tamper: list[str], config_version: int) -> None:
        now = _iso(_now())
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT tamper_flags, tamper_at FROM devices WHERE device_id=?", (device_id,)).fetchone()
            flags = sorted(set(json.loads(current["tamper_flags"])) | set(tamper)) if current else sorted(set(tamper))
            tamper_at = now if tamper and not (current and current["tamper_at"]) else (current["tamper_at"] if current else None)
            db.execute(
                """UPDATE devices SET last_seen_at=?, agent_version=?, queue_depth=?, tamper_flags=?,
                   tamper_at=?, config_version=? WHERE device_id=?""",
                (now, agent_version, queue_depth, json.dumps(flags), tamper_at, config_version, device_id),
            )
            db.commit()

    def acknowledge_tamper(self, device_id: str) -> bool:
        with closing(self._connect()) as db:
            cur = db.execute("UPDATE devices SET tamper_flags='[]', tamper_at=NULL WHERE device_id=?", (device_id,))
        return cur.rowcount == 1

    # --------------------------------------------------------------- config
    @staticmethod
    def _config_version(db: sqlite3.Connection, org_id: str) -> int:
        row = db.execute("SELECT version FROM device_org_config WHERE org_id=?", (org_id,)).fetchone()
        return row["version"] if row else 0

    def get_config(self, org_id: str) -> tuple[int, dict[str, Any]]:
        with closing(self._connect()) as db:
            row = db.execute("SELECT version, config_json FROM device_org_config WHERE org_id=?", (org_id,)).fetchone()
        if not row:
            return 0, dict(DEFAULT_CONFIG)
        return row["version"], json.loads(row["config_json"])

    def set_config(self, org_id: str, config: dict[str, Any]) -> int:
        normalised = validate_config(config)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            version = self._config_version(db, org_id) + 1
            db.execute(
                """INSERT INTO device_org_config(org_id,version,config_json,updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(org_id) DO UPDATE SET version=excluded.version, config_json=excluded.config_json,
                   updated_at=excluded.updated_at""",
                (org_id, version, json.dumps(normalised), _iso(_now())),
            )
            db.commit()
        return version

    # --------------------------------------------------------------- events
    def add_events(self, device: Device, events: list[dict[str, Any]]) -> int:
        now = _iso(_now())
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            for event in events:
                db.execute(
                    """INSERT INTO device_events(id,device_id,org_id,kind,decision,folder_class,filename,data_types,
                       findings_count,quarantined,detail,occurred_at,received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (str(uuid4()), device.device_id, device.org_id, event["kind"], event["decision"],
                     event["folder_class"], event.get("filename"), json.dumps(event["data_types"]),
                     event["findings_count"], int(event["quarantined"]), event.get("detail"),
                     event.get("occurred_at") or now, now),
                )
            db.execute(
                """DELETE FROM device_events WHERE device_id=? AND id NOT IN
                   (SELECT id FROM device_events WHERE device_id=? ORDER BY received_at DESC LIMIT ?)""",
                (device.device_id, device.device_id, MAX_EVENTS_PER_DEVICE),
            )
            db.commit()
        return len(events)

    def list_events(self, org_id: str, device_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM device_events WHERE org_id=?" + (" AND device_id=?" if device_id else "")
        args: list[Any] = [org_id] + ([device_id] if device_id else [])
        with closing(self._connect()) as db:
            rows = db.execute(sql + " ORDER BY received_at DESC LIMIT ?", (*args, max(1, min(limit, 500)))).fetchall()
        return [{**dict(r), "data_types": json.loads(r["data_types"]), "quarantined": bool(r["quarantined"])} for r in rows]

    @staticmethod
    def _device(row: sqlite3.Row) -> Device:
        return Device(
            device_id=row["device_id"], org_id=row["org_id"], hostname=row["hostname"], os_name=row["os_name"],
            agent_version=row["agent_version"], state=row["state"], tamper_flags=json.loads(row["tamper_flags"]),
            tamper_at=row["tamper_at"], queue_depth=row["queue_depth"], config_version=row["config_version"],
            enrolled_at=row["enrolled_at"], last_seen_at=row["last_seen_at"], revoked_at=row["revoked_at"],
        )


@lru_cache
def get_device_store() -> DeviceStore:
    return DeviceStore(get_settings().devices_db_path)
