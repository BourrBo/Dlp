"""OS-specific providers: removable drives and clipboard.

The Windows implementations use ctypes only (no pywin32). They are exercised by
the Windows test matrix in the plan (W32-33); on Linux CI only the fakes and the
POSIX mount parser are tested.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional, Protocol


class RemovableProvider(Protocol):
    def list_roots(self) -> list[Path]: ...


class ClipboardProvider(Protocol):
    def sequence(self) -> int: ...
    def read_text(self) -> Optional[str]: ...
    def clear(self) -> None: ...


# ------------------------------------------------------------ removable drives
class WindowsRemovableProvider:
    DRIVE_REMOVABLE = 2

    def __init__(self) -> None:
        import ctypes

        self._kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        self._kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        self._kernel32.GetDriveTypeW.restype = ctypes.c_uint

    def list_roots(self) -> list[Path]:
        mask = self._kernel32.GetLogicalDrives()
        roots = []
        for i in range(26):
            if mask & (1 << i):
                root = f"{chr(65 + i)}:\\"
                if self._kernel32.GetDriveTypeW(root) == self.DRIVE_REMOVABLE:
                    roots.append(Path(root))
        return roots


def parse_proc_mounts(text: str, prefixes: tuple[str, ...] = ("/media/", "/run/media/", "/Volumes/")) -> list[Path]:
    roots = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            mount = parts[1].replace("\\040", " ")
            if mount.startswith(prefixes):
                roots.append(Path(mount))
    return roots


class PosixRemovableProvider:
    def list_roots(self) -> list[Path]:
        try:
            return parse_proc_mounts(Path("/proc/mounts").read_text(encoding="utf-8", errors="replace"))
        except OSError:
            volumes = Path("/Volumes")  # macOS
            return [p for p in volumes.iterdir() if p.is_mount()] if volumes.exists() else []


def default_removable_provider() -> RemovableProvider:
    return WindowsRemovableProvider() if os.name == "nt" else PosixRemovableProvider()


def is_network_path(path: Path) -> bool:
    """True for UNC paths and mapped network drives on Windows; False elsewhere."""
    if os.name != "nt":
        return False
    text = str(path)
    if text.startswith("\\\\") and not text.startswith("\\\\?\\"):
        return True
    import ctypes

    drive = os.path.splitdrive(text)[0]
    return bool(drive) and ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == 4  # type: ignore[attr-defined]


# ------------------------------------------------------------------- clipboard
class WindowsClipboard:
    CF_UNICODETEXT = 13

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._u = ctypes.windll.user32  # type: ignore[attr-defined]
        self._k = ctypes.windll.kernel32  # type: ignore[attr-defined]
        self._u.GetClipboardSequenceNumber.restype = wintypes.DWORD
        self._u.OpenClipboard.argtypes = [wintypes.HWND]
        self._u.OpenClipboard.restype = wintypes.BOOL
        self._u.GetClipboardData.argtypes = [wintypes.UINT]
        self._u.GetClipboardData.restype = ctypes.c_void_p
        self._k.GlobalLock.argtypes = [ctypes.c_void_p]
        self._k.GlobalLock.restype = ctypes.c_void_p
        self._k.GlobalUnlock.argtypes = [ctypes.c_void_p]
        self._ctypes = ctypes

    def sequence(self) -> int:
        return int(self._u.GetClipboardSequenceNumber())

    def read_text(self) -> Optional[str]:
        if not self._u.OpenClipboard(None):
            return None  # another program holds the clipboard; try next tick
        try:
            handle = self._u.GetClipboardData(self.CF_UNICODETEXT)
            if not handle:
                return None
            pointer = self._k.GlobalLock(handle)
            if not pointer:
                return None
            try:
                return self._ctypes.wstring_at(pointer)
            finally:
                self._k.GlobalUnlock(handle)
        finally:
            self._u.CloseClipboard()

    def clear(self) -> None:
        if self._u.OpenClipboard(None):
            try:
                self._u.EmptyClipboard()
            finally:
                self._u.CloseClipboard()


def default_clipboard() -> Optional[ClipboardProvider]:
    return WindowsClipboard() if os.name == "nt" else None
