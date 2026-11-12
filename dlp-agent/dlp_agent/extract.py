"""Load the shared extractor package.

The extractors live in ``dlp-backend/app/extractors`` and import neither the
database nor the network (enforced by scripts/check_extractor_boundaries.py).
The agent reuses them so a file is read exactly as the server would read it.
Packaging (P4, W31-33) bundles that folder; for development set
``DLP_EXTRACTORS_PATH`` to the ``dlp-backend`` directory.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional


class ExtractorsUnavailable(RuntimeError):
    pass


def load_extract_file(search_path: Optional[Path] = None) -> Callable[..., Any]:
    candidates = []
    if search_path:
        candidates.append(Path(search_path))
    if os.environ.get("DLP_EXTRACTORS_PATH"):
        candidates.append(Path(os.environ["DLP_EXTRACTORS_PATH"]))
    candidates.append(Path(__file__).resolve().parents[2] / "dlp-backend")
    candidates.append(Path(sys.executable).resolve().parent / "extractors")  # frozen build layout
    for base in candidates:
        if (base / "app" / "extractors" / "registry.py").is_file() and str(base) not in sys.path:
            sys.path.insert(0, str(base))
    try:
        return importlib.import_module("app.extractors.registry").extract_file
    except ImportError as exc:
        raise ExtractorsUnavailable("shared extractors not found; set DLP_EXTRACTORS_PATH to the dlp-backend folder") from exc
