"""Scanning engine shared by --staged, --path and --git-range."""

from __future__ import annotations

import hashlib
import importlib
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

from dlp_cli.config import IGNORE_NAME, Config
from dlp_cli.detectors import RULES, SEVERITY_ORDER, Match, Rule, detect_line, mask
from dlp_cli.gitutil import AddedLine
from dlp_cli.ignore import IgnoreMatcher

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "__pycache__",
             ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", "target", ".next", ".idea"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock",
             "cargo.lock", "composer.lock", "go.sum", "bun.lock", "bun.lockb", "gemfile.lock"}
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tar", ".7z",
    ".rar", ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".pyc", ".woff", ".woff2", ".ttf",
    ".eot", ".mp3", ".mp4", ".mov", ".avi", ".bin", ".whl", ".docx", ".xlsx", ".pptx", ".sqlite",
}
WINDOW = 4096
OVERLAP = 128
MAX_LINE_CHARS = 200_000
INLINE_ALLOW = "dlp:allow"


@dataclass
class Finding:
    rule_id: str
    data_type: str
    severity: str
    confidence: float
    path: str
    line: int
    column: int
    end_column: int
    masked: str
    fingerprint: str
    description: str
    guidance: str
    commit: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def blocking(self, fail_on: str) -> list[Finding]:
        floor = SEVERITY_ORDER[fail_on]
        return [f for f in self.findings if SEVERITY_ORDER[f.severity] >= floor]


def fingerprint(rule_id: str, value: str) -> str:
    return hashlib.sha256(f"{rule_id}:{value}".encode("utf-8")).hexdigest()[:16]


def default_skip_reason(rel_path: str) -> Optional[str]:
    """Reason a path is skipped by default, or None."""
    parts = rel_path.replace("\\", "/").split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return "default skip: dependency or build directory"
    name = parts[-1].lower()
    if name in LOCKFILES:
        return "default skip: lockfile"
    if ".min." in name:
        return "default skip: minified file"
    if os.path.splitext(name)[1] in BINARY_EXTENSIONS:
        return "default skip: binary or document format (use the platform scan for documents)"
    return None


def _load_rules(config: Config) -> tuple[list[Rule], Optional[object]]:
    if config.detector_module:
        module = importlib.import_module(config.detector_module)
        if hasattr(module, "detect_line"):
            return [], module
        rules = list(getattr(module, "RULES"))
    else:
        rules = list(RULES)
    return [r for r in rules if r.id not in config.disable_rules], None


class Scanner:
    def __init__(self, config: Config, root: Path) -> None:
        self.config = config
        self.root = root
        self._rules, self._external = _load_rules(config)
        self._ignore = IgnoreMatcher.from_file(root / IGNORE_NAME)
        self._allow_paths = IgnoreMatcher(config.allow_paths)
        self.report = Report()

    # ------------------------------------------------------------ helpers
    def _skip_reason(self, rel: str) -> Optional[str]:
        if self._ignore.matches(rel):
            return f"excluded by {IGNORE_NAME}"
        if self._allow_paths.matches(rel):
            return "excluded by allowlist path"
        return default_skip_reason(rel)

    def _matches(self, line: str) -> Iterator[Match]:
        if self._external is not None:
            yield from self._external.detect_line(line)
            return
        if len(line) <= WINDOW:
            yield from detect_line(line, self._rules)
            return
        seen: set[tuple[str, int]] = set()
        step = WINDOW - OVERLAP
        for offset in range(0, min(len(line), MAX_LINE_CHARS), step):
            for m in detect_line(line[offset:offset + WINDOW], self._rules):
                key = (m.rule.id, m.start + offset)
                if key not in seen:
                    seen.add(key)
                    yield Match(m.rule, m.start + offset, m.end + offset, m.value)

    def scan_text_line(self, path: str, line_no: int, text: str, commit: Optional[str] = None) -> None:
        self.report.lines_scanned += 1
        if INLINE_ALLOW in text:
            return
        for m in self._matches(text):
            fp = fingerprint(m.rule.id, m.value)
            if fp in self.config.allow_fingerprints:
                continue
            self.report.findings.append(Finding(
                rule_id=m.rule.id, data_type=m.rule.data_type, severity=m.rule.severity,
                confidence=m.rule.confidence, path=path, line=line_no, column=m.start + 1,
                end_column=m.end + 1, masked=mask(m.value), fingerprint=fp,
                description=m.rule.description, guidance=m.rule.guidance, commit=commit,
            ))

    # ------------------------------------------------------------- inputs
    def scan_added_lines(self, lines: Iterable[AddedLine]) -> Report:
        decisions: dict[str, Optional[str]] = {}
        counted: set[str] = set()
        for item in lines:
            if item.path not in decisions:
                decisions[item.path] = self._skip_reason(item.path)
                if decisions[item.path]:
                    self.report.skipped.append((item.path, decisions[item.path]))
            if decisions[item.path]:
                continue
            if item.path not in counted:
                counted.add(item.path)
                self.report.files_scanned += 1
            self.scan_text_line(item.path, item.line, item.text, item.commit)
        return self.report

    def scan_paths(self, targets: Iterable[Path]) -> Report:
        for target in targets:
            target = Path(target)
            if target.is_dir():
                for file_path in self._walk(target):
                    self.scan_file(file_path)
            elif target.is_file():
                self.scan_file(target)
            else:
                self.report.skipped.append((str(target), "path does not exist"))
        return self.report

    def _walk(self, folder: Path) -> Iterator[Path]:
        for current, dirs, files in os.walk(folder, followlinks=False):
            rel_dir = self._rel(Path(current))
            prefix = "" if rel_dir in (".", "") else rel_dir + "/"
            kept = []
            for d in sorted(dirs):
                if d in SKIP_DIRS:
                    self.report.skipped.append((f"{prefix}{d}/", "default skip: dependency or build directory"))
                elif self._ignore.matches(f"{prefix}{d}/x"):
                    self.report.skipped.append((f"{prefix}{d}/", f"excluded by {IGNORE_NAME}"))
                else:
                    kept.append(d)
            dirs[:] = kept
            for name in sorted(files):
                yield Path(current) / name

    def _rel(self, path: Path) -> str:
        try:
            absolute = path.parent.resolve() / path.name if path.name else path.resolve()
            return absolute.relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def scan_file(self, path: Path) -> None:
        rel = self._rel(path)
        reason = self._skip_reason(rel)
        if reason is None and path.is_symlink():
            reason = "symbolic link"
        if reason:
            self.report.skipped.append((rel, reason))
            return
        try:
            size = path.stat().st_size
            if size > self.config.max_file_bytes:
                self.report.skipped.append((rel, f"larger than {self.config.max_file_bytes} bytes"))
                return
            data = path.read_bytes()
        except OSError as exc:
            self.report.skipped.append((rel, f"unreadable: {exc.strerror or exc}"))
            return
        text = decode_text(data)
        if text is None:
            self.report.skipped.append((rel, "binary file"))
            return
        self.report.files_scanned += 1
        for number, line in enumerate(text.splitlines(), start=1):
            self.scan_text_line(rel, number, line)


def decode_text(data: bytes) -> Optional[str]:
    """Decode text files (UTF-8/16); None for binary content."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")
