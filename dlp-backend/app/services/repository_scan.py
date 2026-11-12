"""Bounded GitHub working-tree scans with credential-safe shallow cloning.

This module owns repository transport and extraction only. The caller supplies
the authenticated P2 pipeline callback; this service never decides policy or
persists findings itself.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Callable, Generic, TypeVar

from app.extractors.limits import MAX_FILE_BYTES
from app.extractors.runner import extract_bytes_with_timeout


MAX_REPOSITORY_FILES = 1_000
MAX_REPOSITORY_BYTES = 200 * 1024 * 1024
MAX_REPOSITORY_SECONDS = 300
CLONE_TIMEOUT_SECONDS = 120
DEFAULT_IGNORES = (
    ".git/", "vendor/", "node_modules/", "dist/", "build/", "target/",
    "coverage/", "__pycache__/", ".venv/", "venv/", "*.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
    "*.min.js", "*.min.css",
)
_REPO_PART = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
T = TypeVar("T")


class RepositoryScanError(RuntimeError):
    """Safe-to-return repository scan error; never includes provider output."""


@dataclass(frozen=True)
class RepositoryFileResult(Generic[T]):
    path: str
    chunks_scanned: int = 0
    skipped_reason: str | None = None
    findings: list[T] = field(default_factory=list)


@dataclass(frozen=True)
class RepositoryScanResult(Generic[T]):
    repository: str
    ref: str
    commit_sha: str | None
    files_scanned: int
    bytes_considered: int
    files: list[RepositoryFileResult[T]]
    partial: bool = False
    partial_reason: str | None = None

    @property
    def findings(self) -> list[T]:
        return [finding for file in self.files for finding in file.findings]


def _validate_repo(owner: str, repository: str) -> tuple[str, str]:
    if not _REPO_PART.fullmatch(owner) or owner in {".", ".."}:
        raise ValueError("Invalid GitHub repository owner")
    if not _REPO_PART.fullmatch(repository) or repository in {".", ".."}:
        raise ValueError("Invalid GitHub repository name")
    return owner, repository


def _git_environment(token: str) -> dict[str, str]:
    if not token or "\r" in token or "\n" in token:
        raise ValueError("GitHub installation token is required")
    env = os.environ.copy()
    basic = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    # Git reads these environment-scoped config values; the secret is not part
    # of argv, a URL, a config file, stdout, or stderr.
    env.update({
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def _run_git(args: list[str], *, cwd: Path | None, env: dict[str, str], timeout: int) -> None:
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise RepositoryScanError("Git is not installed on the backend host") from exc
    except subprocess.TimeoutExpired as exc:
        raise RepositoryScanError("GitHub repository operation timed out") from exc
    if result.returncode:
        raise RepositoryScanError("GitHub repository operation failed; check repository access and ref")


def _read_head_sha(cwd: Path, env: dict[str, str]) -> str:
    local_env = env.copy()
    for name in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"):
        local_env.pop(name, None)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"], cwd=cwd, env=local_env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=False, text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryScanError("Could not read cloned repository revision") from exc
    value = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[a-fA-F0-9]{40,64}", value):
        raise RepositoryScanError("Cloned repository returned an invalid revision")
    return value.lower()


def _remove_readonly(func, path, _exc_info):
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    except OSError:
        pass


def _remove_checkout(path: Path) -> None:
    if not path.exists():
        return
    # Git marks objects and config read-only on Windows; make the checkout
    # removable without following symlinks or retaining its credential context.
    shutil.rmtree(path, onerror=_remove_readonly)
    if path.exists():
        raise RepositoryScanError("Temporary repository cleanup failed")


def _load_ignore_patterns(root: Path) -> list[str]:
    path = root / ".dlpignore"
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError):
        raise RepositoryScanError("Could not read repository .dlpignore")
    patterns = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith("!") or value.startswith("/") or ".." in PurePosixPath(value).parts:
            raise RepositoryScanError("Unsupported or unsafe pattern in repository .dlpignore")
        patterns.append(value.replace("\\", "/"))
    return patterns


def _ignored(relative: str, patterns: list[str]) -> bool:
    if relative == ".dlpignore":
        return True
    path = PurePosixPath(relative)
    parts = path.parts
    candidates = list(DEFAULT_IGNORES) + patterns
    for pattern in candidates:
        directory = pattern.endswith("/")
        clean = pattern.rstrip("/")
        if directory and any(part == clean for part in parts[:-1]):
            return True
        if fnmatch.fnmatchcase(relative, clean) or path.match(clean):
            return True
        # Git-like basename matching for patterns without a slash.
        if "/" not in clean and any(fnmatch.fnmatchcase(part, clean) for part in parts):
            return True
    return False


def scan_checkout(
    root: Path,
    *,
    repository: str,
    ref: str,
    scan_chunk: Callable[[str, str], T],
    max_files: int = MAX_REPOSITORY_FILES,
    max_bytes: int = MAX_REPOSITORY_BYTES,
    time_budget_seconds: int = MAX_REPOSITORY_SECONDS,
) -> RepositoryScanResult[T]:
    """Extract supported working-tree files and pass chunks to the shared scan pipeline."""
    if max_files <= 0 or max_bytes <= 0 or time_budget_seconds <= 0:
        raise ValueError("Repository scan limits must be positive")
    started = time.monotonic()
    patterns = _load_ignore_patterns(root)
    results: list[RepositoryFileResult[T]] = []
    file_count = 0
    byte_count = 0
    partial_reason = None

    for current, dirs, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(root).as_posix()
        dirs[:] = [name for name in dirs if not _ignored(
            f"{relative_dir}/{name}".lstrip("./"), patterns
        ) and not (current_path / name).is_symlink()]
        for name in sorted(filenames):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if _ignored(relative, patterns) or path.is_symlink():
                continue
            if time.monotonic() - started >= time_budget_seconds:
                partial_reason = "Repository scan time budget reached"
                break
            if file_count >= max_files:
                partial_reason = "Repository file limit reached"
                break
            try:
                size = path.stat().st_size
            except OSError:
                results.append(RepositoryFileResult(path=relative, skipped_reason="Could not access file"))
                continue
            if size > max_bytes - byte_count:
                partial_reason = "Repository byte limit reached"
                break
            byte_count += size
            file_count += 1
            if size > MAX_FILE_BYTES:
                results.append(RepositoryFileResult(
                    path=relative,
                    skipped_reason=f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit",
                ))
                continue
            try:
                with path.open("rb") as source:
                    data = source.read(MAX_FILE_BYTES + 1)
            except OSError:
                results.append(RepositoryFileResult(path=relative, skipped_reason="Could not read file"))
                continue
            extracted = extract_bytes_with_timeout(data, display_path=relative)
            if extracted.skipped_reason:
                results.append(RepositoryFileResult(path=relative, skipped_reason=extracted.skipped_reason))
                continue
            findings: list[T] = []
            for chunk in extracted.chunks:
                location = f"{relative}:{json.dumps(chunk.location, sort_keys=True, separators=(',', ':'))}"
                findings.append(scan_chunk(chunk.text, location))
            results.append(RepositoryFileResult(
                path=relative, chunks_scanned=len(extracted.chunks), findings=findings,
            ))
        if partial_reason:
            break

    return RepositoryScanResult(
        repository=repository, ref=ref, commit_sha=None, files_scanned=file_count,
        bytes_considered=byte_count, files=results,
        partial=partial_reason is not None, partial_reason=partial_reason,
    )


def clone_and_scan_github_repository(
    owner: str,
    repository: str,
    installation_token: str,
    *,
    scan_chunk: Callable[[str, str], T],
    ref: str = "HEAD",
    temp_root: str | Path | None = None,
    max_files: int = MAX_REPOSITORY_FILES,
    max_bytes: int = MAX_REPOSITORY_BYTES,
    time_budget_seconds: int = MAX_REPOSITORY_SECONDS,
) -> RepositoryScanResult[T]:
    """Shallow-clone one GitHub repository, scan supported files, then clean it up."""
    owner, repository = _validate_repo(owner, repository)
    if not ref or ref.startswith("-") or ".." in ref or "\x00" in ref:
        raise ValueError("Invalid Git ref")
    env = _git_environment(installation_token)
    base = Path(temp_root) if temp_root else None
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
    checkout = Path(tempfile.mkdtemp(prefix="dlp-github-", dir=base))
    # Clone into the existing empty directory so cleanup has one known root.
    clone_url = f"https://github.com/{owner}/{repository}.git"
    clone_args = ["clone", "--depth", "1", "--no-tags", "--single-branch"]
    if ref != "HEAD":
        clone_args.extend(["--branch", ref])
    clone_args.extend(["--", clone_url, str(checkout)])
    try:
        _run_git(
            clone_args,
            cwd=None, env=env, timeout=CLONE_TIMEOUT_SECONDS,
        )
        sha = _read_head_sha(checkout, env)
        result = scan_checkout(
            checkout, repository=f"{owner}/{repository}", ref=ref,
            scan_chunk=scan_chunk, max_files=max_files, max_bytes=max_bytes,
            time_budget_seconds=time_budget_seconds,
        )
        return replace(result, commit_sha=sha)
    finally:
        _remove_checkout(checkout)
