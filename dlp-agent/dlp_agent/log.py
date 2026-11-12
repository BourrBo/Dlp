"""Structured local log. It records what happened, never file content or matched values."""

from __future__ import annotations

import json
import logging
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_ALLOWED = {"event", "file", "folder_class", "decision", "findings", "data_types", "reason", "status", "count",
            "error", "device_id", "version", "action", "attempt", "queue_depth"}


class AgentLog:
    def __init__(self, path: Path, level: int = logging.INFO) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger(f"dlp_agent.{path}")
        self._logger.setLevel(level)
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def write(self, level: str, event: str, **fields: Any) -> None:
        clean = {k: (v if isinstance(v, (int, float, bool, list)) or v is None else str(v)[:200])
                 for k, v in fields.items() if k in _ALLOWED}
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "level": level, "event": event, **clean}
        self._logger.log(getattr(logging, level.upper(), logging.INFO), json.dumps(record, ensure_ascii=False))

    def info(self, event: str, **fields: Any) -> None:
        self.write("info", event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self.write("warning", event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self.write("error", event, **fields)

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)
