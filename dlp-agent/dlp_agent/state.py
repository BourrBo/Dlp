"""Local agent state: identity, signed config cache, directories.

The agent stores only its device key, server URL and the last server config.
The config file carries an HMAC (keyed with the device key) so a hand edit is
detected; this stops casual tampering, not an administrator who can also read
the key. See docs/endpoint-agent.md for the honest limits.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

DEFAULT_CONFIG: dict[str, Any] = {
    "watch_folders": ["~/Downloads", "~/Desktop", "~/Documents"],
    "stable_seconds": 3,
    "max_file_bytes": 25 * 1024 * 1024,
    "unscannable_action": "warn",
    "scan_removable_drives": True,
    "quarantine_on_block": True,
    "clipboard_monitoring": False,
    "heartbeat_seconds": 60,
}


def default_home() -> Path:
    override = os.environ.get("DLP_AGENT_HOME")
    if override:
        return Path(override)
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "DLPAgent"
    return Path.home() / ".dlp-agent"


@dataclass(frozen=True)
class Identity:
    server_url: str
    device_id: str
    device_key: str


def _canonical(version: int, config: dict[str, Any]) -> bytes:
    return json.dumps({"version": version, "config": config}, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if os.name != "nt":
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class AgentState:
    def __init__(self, home: Optional[Path] = None) -> None:
        self.home = Path(home) if home else default_home()
        self.identity_path = self.home / "identity.json"
        self.config_path = self.home / "config.json"
        self.queue_path = self.home / "queue.sqlite3"
        self.seen_path = self.home / "seen.sqlite3"
        self.quarantine_dir = self.home / "quarantine"
        self.log_path = self.home / "logs" / "agent.log"
        self.run_state_path = self.home / "run-state.json"
        self.watchdog_path = self.home / "watchdog.json"

    def ensure_dirs(self) -> None:
        for folder in (self.home, self.quarantine_dir, self.log_path.parent):
            folder.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(folder, 0o700)

    # --------------------------------------------------------------- identity
    def save_identity(self, identity: Identity) -> None:
        self.ensure_dirs()
        payload = {"server_url": identity.server_url, "device_id": identity.device_id, "device_key": identity.device_key}
        _atomic_write(self.identity_path, json.dumps(payload).encode("utf-8"))

    def load_identity(self) -> Optional[Identity]:
        try:
            data = json.loads(self.identity_path.read_text(encoding="utf-8"))
            return Identity(data["server_url"], data["device_id"], data["device_key"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    # ----------------------------------------------------------------- config
    def save_config(self, version: int, config: dict[str, Any], device_key: str) -> None:
        self.ensure_dirs()
        mac = hmac.new(device_key.encode("utf-8"), _canonical(version, config), hashlib.sha256).hexdigest()
        _atomic_write(self.config_path, json.dumps({"version": version, "config": config, "mac": mac}).encode("utf-8"))

    def load_config(self, device_key: str) -> tuple[int, dict[str, Any], bool]:
        """Return (version, config, tampered). A missing file is not tampering."""
        if not self.config_path.exists():
            return 0, copy.deepcopy(DEFAULT_CONFIG), False
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            version, config, mac = int(data["version"]), dict(data["config"]), str(data["mac"])
            expected = hmac.new(device_key.encode("utf-8"), _canonical(version, config), hashlib.sha256).hexdigest()
            if hmac.compare_digest(mac, expected):
                return version, {**DEFAULT_CONFIG, **config}, False
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return 0, copy.deepcopy(DEFAULT_CONFIG), True
