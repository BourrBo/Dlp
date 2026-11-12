"""Quarantine folder with a restore flow.

A quarantined file is moved (never copied) into an agent-owned folder under a
random ID with a JSON sidecar. Restore puts it back without overwriting.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dlp_agent.fsutil import fs_path, safe_basename

_ID = re.compile(r"^[0-9a-f]{32}$")


class QuarantineError(Exception):
    pass


@dataclass(frozen=True)
class QuarantinedFile:
    id: str
    original_path: str
    original_name: str
    quarantined_at: float
    sha256: str
    size: int
    data_types: list[str]
    decision: str


class Quarantine:
    def __init__(self, folder: Path) -> None:
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.folder, 0o700)

    def _blob(self, qid: str) -> Path:
        return self.folder / f"{qid}.dlpq"

    def _meta(self, qid: str) -> Path:
        return self.folder / f"{qid}.json"

    def add(self, path: Path, data_types: list[str], decision: str = "block") -> QuarantinedFile:
        source = fs_path(path)
        digest = hashlib.sha256()
        with open(source, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
        qid = uuid.uuid4().hex
        size = os.stat(source).st_size
        meta = QuarantinedFile(qid, str(Path(path).absolute()), safe_basename(path), time.time(),
                               digest.hexdigest(), size, list(data_types)[:20], decision)
        try:
            shutil.move(source, str(self._blob(qid)))  # cross-volume safe: copy then delete
        except OSError as exc:
            raise QuarantineError(f"could not move file: {type(exc).__name__}") from None
        if os.name != "nt":
            os.chmod(self._blob(qid), 0o600)
        self._meta(qid).write_text(json.dumps(meta.__dict__), encoding="utf-8")
        return meta

    def list(self) -> list[QuarantinedFile]:
        items = []
        for meta_path in sorted(self.folder.glob("*.json")):
            try:
                items.append(QuarantinedFile(**json.loads(meta_path.read_text(encoding="utf-8"))))
            except (OSError, ValueError, TypeError):
                continue
        return sorted(items, key=lambda i: i.quarantined_at)

    def restore(self, qid: str, destination: Optional[Path] = None) -> Path:
        if not _ID.fullmatch(qid):
            raise QuarantineError("invalid quarantine ID")
        try:
            meta = QuarantinedFile(**json.loads(self._meta(qid).read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            raise QuarantineError("unknown quarantine ID") from None
        target = Path(destination) if destination else Path(meta.original_path)
        if not target.is_absolute():
            raise QuarantineError("restore path must be absolute")
        resolved_parent = target.parent.resolve()
        if resolved_parent == self.folder.resolve() or self.folder.resolve() in resolved_parent.parents:
            raise QuarantineError("cannot restore into the quarantine folder")
        target.parent.mkdir(parents=True, exist_ok=True)
        final = target
        counter = 1
        while final.exists():  # never overwrite
            final = target.with_name(f"{target.stem} (restored {counter}){target.suffix}")
            counter += 1
        try:
            shutil.move(str(self._blob(qid)), fs_path(final))
        except OSError as exc:
            raise QuarantineError(f"could not restore file: {type(exc).__name__}") from None
        self._meta(qid).unlink(missing_ok=True)
        return final

    def purge(self, qid: str) -> None:
        if not _ID.fullmatch(qid):
            raise QuarantineError("invalid quarantine ID")
        self._blob(qid).unlink(missing_ok=True)
        self._meta(qid).unlink(missing_ok=True)
