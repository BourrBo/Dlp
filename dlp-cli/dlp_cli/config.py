"""Configuration: ``.dlp.toml`` plus the synced allowlist cache."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.9/3.10
    import tomli as tomllib  # type: ignore[no-redef]

from dlp_cli.detectors import SEVERITY_ORDER

CONFIG_NAME = ".dlp.toml"
ALLOWLIST_CACHE_NAME = ".dlp-allowlist.json"
IGNORE_NAME = ".dlpignore"
_KNOWN_KEYS = {"fail_on", "max_file_bytes", "disable_rules", "detector_module", "allowlist"}


class ConfigError(ValueError):
    """Raised for unreadable or invalid configuration (CLI exit code 2)."""


@dataclass
class Config:
    fail_on: str = "medium"
    max_file_bytes: int = 2_000_000
    disable_rules: set[str] = field(default_factory=set)
    detector_module: str | None = None
    allow_paths: list[str] = field(default_factory=list)
    allow_fingerprints: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.fail_on not in SEVERITY_ORDER:
            raise ConfigError(f"fail_on must be one of {sorted(SEVERITY_ORDER)}, got {self.fail_on!r}")
        if self.max_file_bytes <= 0:
            raise ConfigError("max_file_bytes must be positive")


def find_config(start: Path) -> Path | None:
    current = start.resolve()
    for folder in (current, *current.parents):
        candidate = folder / CONFIG_NAME
        if candidate.is_file():
            return candidate
        if (folder / ".git").exists():
            break
    return None


def load_config(path: Path | None, start: Path) -> Config:
    config_path = path or find_config(start)
    data: dict = {}
    base = start
    if config_path is not None:
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Cannot read {config_path}: {exc}") from exc
        base = config_path.parent
    unknown = set(data) - _KNOWN_KEYS
    if unknown:
        raise ConfigError(f"Unknown config keys: {', '.join(sorted(unknown))}")
    allow = data.get("allowlist", {})
    if not isinstance(allow, dict):
        raise ConfigError("[allowlist] must be a table")
    fingerprints = {str(x) for x in allow.get("fingerprints", [])}
    fingerprints |= _load_cache(base / ALLOWLIST_CACHE_NAME)
    try:
        return Config(
            fail_on=str(data.get("fail_on", "medium")).lower(),
            max_file_bytes=int(data.get("max_file_bytes", 2_000_000)),
            disable_rules={str(x) for x in data.get("disable_rules", [])},
            detector_module=data.get("detector_module"),
            allow_paths=[str(x) for x in allow.get("paths", [])],
            allow_fingerprints=fingerprints,
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"Invalid configuration value: {exc}") from exc


def _load_cache(path: Path) -> set[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return {x for x in payload.get("fingerprints", []) if isinstance(x, str)}
    except (OSError, ValueError, AttributeError):
        return set()
