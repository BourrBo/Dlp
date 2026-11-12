"""Agent orchestrator: one ``tick`` does a bounded slice of every duty."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from dlp_agent import __version__
from dlp_agent.client import AuthRejected, Offline, Rejected, ServerClient
from dlp_agent.fsutil import expand_folder, safe_basename
from dlp_agent.log import AgentLog
from dlp_agent.pipeline import FileProcessor, SeenStore
from dlp_agent.platform_support import ClipboardProvider, RemovableProvider, is_network_path
from dlp_agent.quarantine import Quarantine
from dlp_agent.queue import OfflineQueue
from dlp_agent.state import DEFAULT_CONFIG, AgentState, Identity
from dlp_agent.tamper import TamperMonitor
from dlp_agent.watcher import Change, PollingWatcher, StabilityGate, WatchRoot

CLASS_BY_FOLDER = {"downloads": "downloads", "desktop": "desktop", "documents": "documents"}
REMOVABLE_LOOKBACK_SECONDS = 120.0
MAX_CLIPBOARD_CHARS = 1_000_000


def folder_class_for(path: Path) -> str:
    return CLASS_BY_FOLDER.get(path.name.lower(), "other")


def sanitise_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Accept only known keys with the right types; anything else keeps its default."""
    clean = dict(DEFAULT_CONFIG)
    for key, default in DEFAULT_CONFIG.items():
        value = raw.get(key, default)
        if isinstance(default, bool):
            clean[key] = value if isinstance(value, bool) else default
        elif isinstance(default, int):
            clean[key] = value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else default
        elif isinstance(default, list):
            folders = [v for v in value if isinstance(v, str) and v][:20] if isinstance(value, list) else []
            clean[key] = folders or default
        else:
            clean[key] = value if isinstance(value, str) and value in ("allow", "warn", "block") else default
    return clean


class Agent:
    def __init__(
        self,
        state: AgentState,
        identity: Identity,
        *,
        client: Optional[ServerClient] = None,
        extract_file: Callable[..., Any],
        removable: Optional[RemovableProvider] = None,
        clipboard: Optional[ClipboardProvider] = None,
        clock: Callable[[], float] = time.time,
        log: Optional[AgentLog] = None,
        skip_network_drives: bool = True,
    ) -> None:
        self.state, self.identity, self.clock = state, identity, clock
        state.ensure_dirs()
        self.log = log or AgentLog(state.log_path)
        self.client = client or ServerClient(identity.server_url, identity.device_key)
        self.queue = OfflineQueue(state.queue_path, clock=clock)
        self.quarantine = Quarantine(state.quarantine_dir)
        self.tamper = TamperMonitor(state, clock)
        self.removable, self.clipboard = removable, clipboard
        self.skip_network_drives = skip_network_drives
        self.config_version, self.config, tampered = state.load_config(identity.device_key)
        self.started_at = clock()
        self.gate = StabilityGate(stable_seconds=self.config["stable_seconds"], clock=clock)
        self.watcher = PollingWatcher([])
        self._removable_roots: dict[str, WatchRoot] = {}
        self._events: list[dict[str, Any]] = []
        self.processor = FileProcessor(
            client=self.client, queue=self.queue, quarantine=self.quarantine, log=self.log,
            seen=SeenStore(state.seen_path), extract_file=extract_file,
            config=lambda: self.config, emit=self._emit,
        )
        self._next_heartbeat = 0.0
        self._heartbeat_failures = 0
        self._last_clipboard_seq: Optional[int] = None
        self.stats = {"processed": 0, "quarantined": 0}

    # -------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self.tamper.on_start()
        if self._config_tampered():
            self.log.warning("config_tampered", status="reverted_to_defaults")
        self._rebuild_roots()
        self.log.info("agent_started", device_id=self.identity.device_id, version=__version__)

    def stop(self, planned: bool = False) -> None:
        self._flush_events()
        self.tamper.on_stop(planned)
        self.log.info("agent_stopped", status="planned" if planned else "unplanned")

    def _config_tampered(self) -> bool:
        version, config, tampered = self.state.load_config(self.identity.device_key)
        if tampered:
            self.tamper.flag("config_edit")
            # Fall back to safe defaults and re-sign them with version 0: the next
            # heartbeat sees the version gap and pulls the real config from the server.
            self.config_version, self.config = 0, dict(DEFAULT_CONFIG)
            self.state.save_config(0, self.config, self.identity.device_key)
            self._next_heartbeat = 0.0
        return tampered

    # ----------------------------------------------------------------- events
    def _emit(self, event: dict[str, Any]) -> None:
        self._events.append(event)

    def _flush_events(self) -> None:
        batch, self._events = self._events[:100], self._events[100:]
        while batch:
            try:
                self.client.events(batch)
            except Offline:
                for event in batch:
                    self.queue.put("event", event)
            except AuthRejected:
                self.processor.revoked = True
            except Rejected as exc:
                self.log.error("events_rejected", error=str(exc))
            batch, self._events = self._events[:100], self._events[100:]

    def _drain_queue(self) -> None:
        events = self.queue.due("event", 100)
        if events:
            try:
                self.client.events([payload for _, payload, _ in events])
                self.queue.done([i for i, _, _ in events])
            except Offline:
                self.queue.retry_later([i for i, _, _ in events])
            except Rejected:
                self.queue.done([i for i, _, _ in events])  # poison batch: drop rather than loop forever
            except AuthRejected:
                self.processor.revoked = True
        for item_id, payload, _ in self.queue.due("file", 20):
            path = Path(payload["path"])
            try:
                st = path.stat()
            except OSError:
                self.queue.done([item_id])
                continue
            outcome = self.processor.process(Change(path, payload.get("folder_class", "other"), st.st_size, st.st_mtime_ns), replay=True)
            if outcome.status == "deferred":
                self.queue.retry_later([item_id])
            else:
                self.queue.done([item_id])

    # ------------------------------------------------------------------ roots
    def _rebuild_roots(self) -> None:
        roots = []
        for folder in self.config["watch_folders"]:
            path = expand_folder(folder)
            if not path.is_dir():
                continue
            if self.skip_network_drives and is_network_path(path):
                self.log.info("skipped_network_path", file=path.name)
                continue
            roots.append(WatchRoot(path, folder_class_for(path), initial_cutoff=self.started_at))
        roots.extend(self._removable_roots.values())
        self.watcher.set_roots(roots)
        self.gate.stable_seconds = self.config["stable_seconds"]

    def _refresh_removable(self) -> None:
        if not self.removable or not self.config["scan_removable_drives"]:
            if self._removable_roots:
                self._removable_roots.clear()
                self._rebuild_roots()
            return
        try:
            present = {str(p): p for p in self.removable.list_roots()}
        except Exception as exc:  # a flaky provider must not stop the agent
            self.log.warning("removable_provider_failed", error=type(exc).__name__)
            return
        changed = False
        for key, path in present.items():
            if key not in self._removable_roots:
                self._removable_roots[key] = WatchRoot(path, "removable", initial_cutoff=self.clock() - REMOVABLE_LOOKBACK_SECONDS)
                changed = True
        for key in list(self._removable_roots):
            if key not in present:
                del self._removable_roots[key]
                changed = True
        if changed:
            self._rebuild_roots()

    # ----------------------------------------------------------------- tick
    def tick(self) -> dict[str, Any]:
        now = self.clock()
        summary: dict[str, Any] = {"processed": 0, "abandoned": 0}
        if self._config_tampered():
            self._rebuild_roots()
        self._refresh_removable()
        for change in self.watcher.poll():
            self.gate.add(change)
        ready, abandoned = self.gate.ready()
        for change in abandoned:
            self.log.warning("abandoned_locked_file", file=safe_basename(change.path), folder_class=change.folder_class)
            self._emit({"kind": "error", "decision": "log", "folder_class": change.folder_class,
                        "filename": safe_basename(change.path), "data_types": [], "findings_count": 0,
                        "quarantined": False, "detail": "file stayed locked or changing"})
        summary["abandoned"] = len(abandoned)
        for change in ready:
            outcome = self.processor.process(change)
            summary["processed"] += 1
            self.stats["processed"] += 1
            self.stats["quarantined"] += int(outcome.quarantined)
        self._check_clipboard()
        self._flush_events()
        self._drain_queue()
        if now >= self._next_heartbeat:
            self._heartbeat(now)
        self.tamper.touch_watchdog()
        summary["queue_depth"] = self.queue.depth()
        summary["revoked"] = self.processor.revoked
        return summary

    # ------------------------------------------------------------- clipboard
    def _check_clipboard(self) -> None:
        if not self.clipboard or not self.config["clipboard_monitoring"] or self.processor.revoked:
            return
        try:
            seq = self.clipboard.sequence()
            if seq == self._last_clipboard_seq:
                return
            self._last_clipboard_seq = seq
            text = self.clipboard.read_text()
        except Exception as exc:
            self.log.warning("clipboard_failed", error=type(exc).__name__)
            return
        if not text or not text.strip():
            return
        try:
            reply = self.client.scan("clipboard.txt", [{"text": text[:MAX_CLIPBOARD_CHARS], "location": {"source": "clipboard"}}])
        except (Offline, Rejected):
            return  # clipboard text is never queued: it would have to be stored on disk
        except AuthRejected:
            self.processor.revoked = True
            return
        decision = reply.get("decision", "allow")
        types = sorted({f.get("data_type") for f in reply.get("findings", []) if f.get("data_type")})[:20]
        if decision == "allow" and not types:
            return
        cleared = decision == "block"
        if cleared:
            self.clipboard.clear()
            self._last_clipboard_seq = self.clipboard.sequence()
        self._emit({"kind": "file_scan", "decision": decision, "folder_class": "clipboard", "filename": None,
                    "data_types": types, "findings_count": len(reply.get("findings", [])), "quarantined": False,
                    "detail": "clipboard cleared" if cleared else None})
        self.log.info("clipboard_scanned", decision=decision, data_types=types)

    # -------------------------------------------------------------- heartbeat
    def _heartbeat(self, now: float) -> None:
        flags = self.tamper.pending()
        try:
            reply = self.client.heartbeat(self.queue.depth(), self.config_version, flags)
        except Offline:
            self._heartbeat_failures += 1
            self._next_heartbeat = now + min(900.0, self.config["heartbeat_seconds"] * (2 ** min(self._heartbeat_failures, 5)))
            return
        except AuthRejected:
            self.processor.revoked = True
            self.log.error("auth_rejected", status="revoked")
            self._next_heartbeat = now + 3600.0
            return
        except Rejected as exc:
            self.log.error("heartbeat_rejected", error=str(exc))
            self._next_heartbeat = now + 300.0
            return
        self._heartbeat_failures = 0
        self.tamper.mark_reported(flags)
        self._next_heartbeat = now + self.config["heartbeat_seconds"]
        if "config" in reply and isinstance(reply["config"], dict):
            version = int(reply.get("config_version", self.config_version))
            self.config = sanitise_config(reply["config"])
            self.config_version = version
            self.state.save_config(version, self.config, self.identity.device_key)
            self._rebuild_roots()
            self.log.info("config_updated", version=version)

    # -------------------------------------------------------------------- run
    def run_forever(self, stop: threading.Event, poll_interval: float = 2.0) -> None:
        self.start()
        planned = False
        try:
            while not stop.is_set():
                try:
                    self.tick()
                except Exception as exc:  # the loop must survive anything
                    self.log.error("tick_failed", error=type(exc).__name__)
                stop.wait(poll_interval)
            planned = getattr(stop, "planned", False)
        finally:
            self.stop(planned=planned)


def local_hostname() -> str:
    return socket.gethostname()
