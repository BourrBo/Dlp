"""Tamper detection: unclean stops, edited config, stale watchdog heartbeat.

Flags are persisted until the server acknowledges a heartbeat that carried
them, so a tamper seen while offline still reaches the dashboard.
"""

from __future__ import annotations

import json
import os
import time
from typing import Callable

from dlp_agent.state import AgentState

VALID = ("service_stop", "config_edit", "watchdog", "agent_modified")


class TamperMonitor:
    def __init__(self, state: AgentState, clock: Callable[[], float] = time.time) -> None:
        self.state, self.clock = state, clock

    def _read(self) -> dict:
        try:
            return json.loads(self.state.run_state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write(self, data: dict) -> None:
        self.state.ensure_dirs()
        tmp = self.state.run_state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, self.state.run_state_path)

    def on_start(self) -> None:
        data = self._read()
        pending = set(data.get("pending", []))
        if data.get("running") and not data.get("planned_stop"):
            pending.add("service_stop")  # previous run ended without a planned shutdown
        self._write({"running": True, "planned_stop": False, "pending": sorted(pending), "started": self.clock()})

    def on_stop(self, planned: bool) -> None:
        """Only a planned stop (update channel) clears the running marker; any other
        stop, including a service stop from the control panel, is reported next start."""
        data = self._read()
        data.update({"running": not planned, "planned_stop": bool(planned), "stopped": self.clock()})
        self._write(data)

    def flag(self, code: str) -> None:
        if code not in VALID:
            raise ValueError(code)
        data = self._read()
        data["pending"] = sorted(set(data.get("pending", [])) | {code})
        self._write(data)

    def pending(self) -> list[str]:
        return list(self._read().get("pending", []))

    def mark_reported(self, codes: list[str]) -> None:
        data = self._read()
        data["pending"] = sorted(set(data.get("pending", [])) - set(codes))
        self._write(data)

    # -------------------------------------------------------------- watchdog
    def touch_watchdog(self) -> None:
        self.state.ensure_dirs()
        self.state.watchdog_path.write_text(json.dumps({"ts": self.clock()}), encoding="utf-8")

    def watchdog_stale(self, max_age_seconds: float) -> bool:
        try:
            ts = json.loads(self.state.watchdog_path.read_text(encoding="utf-8"))["ts"]
        except (OSError, ValueError, KeyError):
            return True
        return self.clock() - float(ts) > max_age_seconds
