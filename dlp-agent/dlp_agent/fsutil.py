"""File-system helpers: Windows long paths, safe basenames."""

from __future__ import annotations

import os
import re
from pathlib import Path


def fs_path(path: Path | str) -> str:
    """Path usable with the OS APIs; adds the \\\\?\\ prefix on Windows for paths over 240 characters."""
    text = str(path)
    if os.name == "nt" and len(text) > 240 and not text.startswith("\\\\?\\"):
        absolute = os.path.abspath(text)
        if absolute.startswith("\\\\"):
            return "\\\\?\\UNC\\" + absolute[2:]
        return "\\\\?\\" + absolute
    return text


def safe_basename(path: Path | str, limit: int = 200) -> str:
    name = re.split(r"[\\/]", str(path))[-1]
    name = re.sub(r"[\x00-\x1f]", "_", name)
    return (name or "file")[:limit]


def expand_folder(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value)))
