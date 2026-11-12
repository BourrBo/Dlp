"""One file from "stable" to "decided": extract, scan, quarantine, report."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from dlp_agent.client import AuthRejected, Offline, Rejected, ServerClient
from dlp_agent.fsutil import fs_path, safe_basename
from dlp_agent.log import AgentLog
from dlp_agent.queue import OfflineQueue
from dlp_agent.quarantine import Quarantine, QuarantineError
from dlp_agent.watcher import Change

MAX_CHUNKS_PER_CALL = 400
MAX_CHARS_PER_CALL = 4_000_000
STRICTNESS = {"allow": 0, "log": 1, "warn": 2, "block": 3}


@dataclass
class Outcome:
    status: str  # clean | decided | unscannable | deferred | skipped | revoked | error
    decision: str = "allow"
    quarantined: bool = False
    data_types: list[str] = field(default_factory=list)


class SeenStore:
    """Remembers files already judged clean so unchanged files are not rescanned."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        with closing(self._db()) as db:
            db.execute("CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, sig TEXT NOT NULL)")

    def _db(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path), timeout=30, isolation_level=None)

    @staticmethod
    def _key(path: Path) -> str:
        return hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()

    def is_clean(self, change: Change) -> bool:
        with closing(self._db()) as db:
            row = db.execute("SELECT sig FROM seen WHERE key=?", (self._key(change.path),)).fetchone()
        return bool(row) and row[0] == f"{change.size}:{change.mtime_ns}"

    def mark_clean(self, change: Change) -> None:
        with closing(self._db()) as db:
            db.execute("INSERT OR REPLACE INTO seen(key,sig) VALUES (?,?)", (self._key(change.path), f"{change.size}:{change.mtime_ns}"))


class FileProcessor:
    def __init__(
        self,
        *,
        client: ServerClient,
        queue: OfflineQueue,
        quarantine: Quarantine,
        log: AgentLog,
        seen: SeenStore,
        extract_file: Callable[..., Any],
        config: Callable[[], dict[str, Any]],
        emit: Callable[[dict[str, Any]], None],
    ) -> None:
        self.client, self.queue, self.quarantine, self.log = client, queue, quarantine, log
        self.seen, self.extract_file, self.config, self.emit = seen, extract_file, config, emit
        self.revoked = False

    # ------------------------------------------------------------------ main
    def process(self, change: Change, *, replay: bool = False) -> Outcome:
        cfg = self.config()
        name = safe_basename(change.path)
        if self.revoked:
            return Outcome("revoked")
        if self.seen.is_clean(change):
            return Outcome("skipped")
        if change.size > cfg["max_file_bytes"]:
            return self._unscannable(change, cfg, f"larger than {cfg['max_file_bytes']} bytes")
        try:
            result = self.extract_file(fs_path(change.path), display_path=name)
        except Exception as exc:  # extractor bugs must never crash the agent
            self.log.error("extract_failed", file=name, error=type(exc).__name__)
            return self._unscannable(change, cfg, "extraction failed")
        if getattr(result, "skipped_reason", None):
            return self._unscannable(change, cfg, str(result.skipped_reason))
        chunks = [{"text": c.text, "location": dict(c.location)} for c in result.chunks]
        if not chunks:
            self.seen.mark_clean(change)
            return Outcome("clean")
        try:
            decision, data_types, count = self._scan(name, chunks)
        except AuthRejected:
            self.revoked = True
            self.log.error("auth_rejected", status="revoked")
            return Outcome("revoked")
        except Offline:
            if not replay:
                self.queue.put("file", {"path": str(change.path), "folder_class": change.folder_class})
            self.log.warning("deferred_offline", file=name, folder_class=change.folder_class)
            return Outcome("deferred")
        except Rejected as exc:
            self.log.error("scan_rejected", file=name, error=str(exc))
            return Outcome("error")
        return self._act(change, cfg, name, decision, data_types, count)

    # ---------------------------------------------------------------- helpers
    def _scan(self, name: str, chunks: list[dict[str, Any]]) -> tuple[str, list[str], int]:
        decision, types, count = "allow", [], 0
        batch: list[dict[str, Any]] = []
        chars = 0

        def flush() -> None:
            nonlocal decision, count, batch, chars
            if not batch:
                return
            reply = self.client.scan(name, batch)
            count += len(reply.get("findings", []))
            for f in reply.get("findings", []):
                if f.get("data_type") not in types:
                    types.append(f["data_type"])
            if STRICTNESS.get(reply.get("decision", "allow"), 0) > STRICTNESS[decision]:
                decision = reply["decision"]
            batch, chars = [], 0

        for chunk in chunks:
            if batch and (len(batch) >= MAX_CHUNKS_PER_CALL or chars + len(chunk["text"]) > MAX_CHARS_PER_CALL):
                flush()
            batch.append(chunk)
            chars += len(chunk["text"])
        flush()
        return decision, types[:20], count

    def _act(self, change: Change, cfg: dict[str, Any], name: str, decision: str, types: list[str], count: int) -> Outcome:
        if decision == "allow" and not types:
            self.seen.mark_clean(change)
            self.log.info("scanned", file=name, folder_class=change.folder_class, decision="allow", findings=0)
            return Outcome("clean")
        quarantined = False
        if decision == "block" and cfg.get("quarantine_on_block", True):
            quarantined = self._quarantine(change.path, types)
        removable = change.folder_class == "removable"
        self.emit({"kind": "usb_copy" if removable else ("quarantine" if quarantined else "file_scan"),
                   "decision": decision, "folder_class": change.folder_class, "filename": name,
                   "data_types": types, "findings_count": count, "quarantined": quarantined,
                   "detail": "moved to quarantine" if quarantined else None})
        self.log.info("scanned", file=name, folder_class=change.folder_class, decision=decision,
                      findings=count, data_types=types, status="quarantined" if quarantined else "kept")
        if decision in ("warn", "log"):
            self.seen.mark_clean(change)  # warn once per version of the file
        return Outcome("decided", decision, quarantined, types)

    def _quarantine(self, path: Path, types: list[str]) -> bool:
        try:
            self.quarantine.add(path, types)
            return True
        except (QuarantineError, OSError) as exc:
            self.log.error("quarantine_failed", file=safe_basename(path), error=type(exc).__name__)
            return False

    def _unscannable(self, change: Change, cfg: dict[str, Any], reason: str) -> Outcome:
        action = cfg.get("unscannable_action", "warn")
        name = safe_basename(change.path)
        self.log.warning("unscannable", file=name, folder_class=change.folder_class, action=action, reason=reason)
        if action == "allow":
            return Outcome("unscannable", "allow")
        quarantined = action == "block" and cfg.get("quarantine_on_block", True) and self._quarantine(change.path, [])
        self.emit({"kind": "unscannable", "decision": action, "folder_class": change.folder_class, "filename": name,
                   "data_types": [], "findings_count": 0, "quarantined": bool(quarantined), "detail": reason[:300]})
        return Outcome("unscannable", action, bool(quarantined))
