"""Durable offline queue with retry and exponential backoff.

Holds two kinds of work and nothing sensitive: ``event`` payloads (masked
metadata) and ``file`` references (a path to scan again once online). Extracted
text is never written to disk.
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Optional

MAX_ITEMS = 100_000
BASE_DELAY = 5.0
MAX_DELAY = 900.0
MAX_ATTEMPTS = 50


def backoff_delay(attempts: int, rng: Callable[[], float] = random.random) -> float:
    delay = min(MAX_DELAY, BASE_DELAY * (2 ** max(0, attempts - 1)))
    return delay * (0.5 + rng() / 2)  # jitter: 50-100 percent of the delay


class OfflineQueue:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.executescript(
                """CREATE TABLE IF NOT EXISTS items (
                       id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload TEXT NOT NULL,
                       attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL, created_at REAL NOT NULL);
                   CREATE INDEX IF NOT EXISTS items_due ON items(next_at, id);"""
            )
        if os.name != "nt":
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def put(self, kind: str, payload: dict[str, Any]) -> None:
        if kind not in ("event", "file"):
            raise ValueError("kind must be 'event' or 'file'")
        now = self._clock()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
            if count >= MAX_ITEMS:  # drop the oldest file references first, then oldest events
                victim = db.execute("SELECT id FROM items ORDER BY (kind='event'), id LIMIT ?", (count - MAX_ITEMS + 1,)).fetchall()
                db.executemany("DELETE FROM items WHERE id=?", [(r["id"],) for r in victim])
            db.execute("INSERT INTO items(kind,payload,next_at,created_at) VALUES (?,?,?,?)",
                       (kind, json.dumps(payload), now, now))
            db.commit()

    def due(self, kind: str, limit: int = 100) -> list[tuple[int, dict[str, Any], int]]:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT id,payload,attempts FROM items WHERE kind=? AND next_at<=? ORDER BY id LIMIT ?",
                              (kind, self._clock(), limit)).fetchall()
        return [(r["id"], json.loads(r["payload"]), r["attempts"]) for r in rows]

    def done(self, ids: list[int]) -> None:
        with closing(self._connect()) as db:
            db.executemany("DELETE FROM items WHERE id=?", [(i,) for i in ids])

    def retry_later(self, ids: list[int], rng: Callable[[], float] = random.random) -> None:
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            for item_id in ids:
                row = db.execute("SELECT attempts FROM items WHERE id=?", (item_id,)).fetchone()
                if row is None:
                    continue
                attempts = row["attempts"] + 1
                if attempts >= MAX_ATTEMPTS:
                    db.execute("DELETE FROM items WHERE id=?", (item_id,))
                else:
                    db.execute("UPDATE items SET attempts=?, next_at=? WHERE id=?",
                               (attempts, self._clock() + backoff_delay(attempts, rng), item_id))
            db.commit()

    def depth(self) -> int:
        with closing(self._connect()) as db:
            return db.execute("SELECT COUNT(*) FROM items").fetchone()[0]

    def next_due_in(self) -> Optional[float]:
        with closing(self._connect()) as db:
            row = db.execute("SELECT MIN(next_at) FROM items").fetchone()
        return None if row[0] is None else max(0.0, row[0] - self._clock())
