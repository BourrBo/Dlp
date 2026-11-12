"""Dependency-free polling watcher and stability gate.

Polling is deliberate: it behaves the same on Windows, Linux and macOS, copes
with network and removable drives, and cannot lose events when the process was
busy. The first poll of a root only reports files newer than its cutoff, so an
agent start does not rescan a whole Documents folder.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from dlp_agent.fsutil import fs_path

TEMP_SUFFIXES = (".crdownload", ".part", ".tmp", ".download", ".partial", ".swp", ".opdownload")
SKIP_DIR_NAMES = {"$recycle.bin", "system volume information", ".trash", ".trashes"}


@dataclass(frozen=True)
class WatchRoot:
    path: Path
    folder_class: str
    initial_cutoff: Optional[float] = None  # None: first poll is a silent baseline


@dataclass(frozen=True)
class Change:
    path: Path
    folder_class: str
    size: int
    mtime_ns: int


def is_temp_name(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(TEMP_SUFFIXES) or lowered.startswith("~$") or lowered.startswith(".~lock.")


class PollingWatcher:
    def __init__(self, roots: Iterable[WatchRoot], *, max_depth: int = 8, max_files_per_root: int = 500_000) -> None:
        self.roots = list(roots)
        self.max_depth = max_depth
        self.max_files_per_root = max_files_per_root
        self._seen: dict[str, tuple[int, int]] = {}
        self._primed: set[str] = set()
        self.truncated_roots: set[str] = set()

    def _walk(self, root: WatchRoot) -> Iterable[tuple[Path, os.stat_result]]:
        stack: list[tuple[str, int]] = [(fs_path(root.path), 0)]
        count = 0
        while stack:
            folder, depth = stack.pop()
            try:
                with os.scandir(folder) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if depth < self.max_depth and entry.name.lower() not in SKIP_DIR_NAMES:
                                    stack.append((entry.path, depth + 1))
                            elif entry.is_file(follow_symlinks=False) and not is_temp_name(entry.name):
                                count += 1
                                if count > self.max_files_per_root:
                                    self.truncated_roots.add(str(root.path))
                                    return
                                yield Path(entry.path), entry.stat(follow_symlinks=False)
                        except OSError:
                            continue  # vanished or unreadable entry
            except OSError:
                continue  # unreadable folder, unplugged drive

    def poll(self) -> list[Change]:
        changes: list[Change] = []
        current: dict[str, tuple[int, int]] = {}
        active = {str(r.path) for r in self.roots}
        for root in self.roots:
            key = str(root.path)
            first = key not in self._primed
            self._primed.add(key)
            for path, st in self._walk(root):
                sig = (st.st_size, st.st_mtime_ns)
                current[str(path)] = sig
                if first:
                    newest = max(st.st_mtime, st.st_ctime)
                    if root.initial_cutoff is not None and newest >= root.initial_cutoff:
                        changes.append(Change(path, root.folder_class, st.st_size, st.st_mtime_ns))
                elif self._seen.get(str(path)) != sig:
                    changes.append(Change(path, root.folder_class, st.st_size, st.st_mtime_ns))
        # keep entries of roots that are temporarily unreadable so they are not "new" on return
        for old_path, sig in self._seen.items():
            if old_path not in current and not any(old_path.startswith(r) for r in active):
                current[old_path] = sig
        self._seen = current
        self._primed &= active
        return changes

    def set_roots(self, roots: Iterable[WatchRoot]) -> None:
        self.roots = list(roots)


@dataclass
class _Pending:
    change: Change
    signature: tuple[int, int]
    stable_since: float
    first_seen: float


@dataclass
class StabilityGate:
    """Release a file only after its size and mtime stopped changing and it can be opened."""

    stable_seconds: float = 3.0
    give_up_seconds: float = 600.0
    clock: Callable[[], float] = time.time
    can_read: Callable[[Path], bool] = field(default=lambda p: _can_read(p))
    _pending: dict[str, _Pending] = field(default_factory=dict)

    def add(self, change: Change) -> None:
        now = self.clock()
        key = str(change.path)
        existing = self._pending.get(key)
        sig = (change.size, change.mtime_ns)
        if existing:
            if existing.signature != sig:
                existing.signature, existing.stable_since, existing.change = sig, now, change
        else:
            self._pending[key] = _Pending(change, sig, now, now)

    def ready(self) -> tuple[list[Change], list[Change]]:
        """Return (ready, abandoned). Abandoned files stayed locked or kept changing for too long."""
        now = self.clock()
        ready: list[Change] = []
        abandoned: list[Change] = []
        for key, item in list(self._pending.items()):
            try:
                st = os.stat(fs_path(item.change.path))
            except OSError:
                del self._pending[key]  # deleted or moved before we got to it
                continue
            sig = (st.st_size, st.st_mtime_ns)
            if sig != item.signature:
                item.signature, item.stable_since = sig, now
                item.change = Change(item.change.path, item.change.folder_class, st.st_size, st.st_mtime_ns)
            if now - item.stable_since >= self.stable_seconds and self.can_read(item.change.path):
                ready.append(item.change)
                del self._pending[key]
            elif now - item.first_seen >= self.give_up_seconds:
                abandoned.append(item.change)
                del self._pending[key]
        return ready, abandoned

    def __len__(self) -> int:
        return len(self._pending)


def _can_read(path: Path) -> bool:
    try:
        with open(fs_path(path), "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False
