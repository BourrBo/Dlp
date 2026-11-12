"""Bounded, resumable added-line scanning for a local Git checkout."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import subprocess
from threading import Timer
import time
from typing import Callable, Generic, TypeVar

from app.extractors.limits import MAX_FILE_BYTES
from app.services.repository_scan import _ignored, _load_ignore_patterns


MAX_HISTORY_COMMITS = 10_000
MAX_HISTORY_FILES = 10_000
MAX_HISTORY_BYTES = 200 * 1024 * 1024
MAX_HISTORY_SECONDS = 300
MAX_COMMIT_FILES = 1_000
MAX_DIFF_BYTES = MAX_FILE_BYTES * 2 + 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 15
_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_REF = re.compile(r"^[A-Za-z0-9_./-]{1,255}$")
T = TypeVar("T")


class GitHistoryScanError(RuntimeError):
    """Sanitized error raised while inspecting repository history."""


@dataclass(frozen=True)
class HistoricalFinding(Generic[T]):
    findings: list[T]
    blob_sha: str
    commit_sha: str
    author: str
    authored_at: str
    file_path: str
    line_start: int
    line_end: int
    blob_version_in_head: bool


@dataclass(frozen=True)
class GitHistoryScanResult(Generic[T]):
    repository: str
    ref: str
    head_sha: str
    commits_scanned: int
    files_scanned: int
    bytes_scanned: int
    findings: list[HistoricalFinding[T]] = field(default_factory=list)
    partial: bool = False
    partial_reason: str | None = None
    resume_after: str | None = None
    force_push_detected: bool = False
    shallow_history: bool = False


def _run_git(args: list[str], root: Path, *, timeout: float, max_output: int = MAX_DIFF_BYTES) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args], cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=max(0.1, timeout), check=False,
        )
    except FileNotFoundError as exc:
        raise GitHistoryScanError("Git is not installed on the backend host") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitHistoryScanError("Git history operation timed out") from exc
    if result.returncode != 0:
        raise GitHistoryScanError("Git history operation failed")
    if len(result.stdout) > max_output:
        raise GitHistoryScanError("Git history operation exceeded its output limit")
    return result.stdout


def _kill_git_process(process: subprocess.Popen) -> None:
    """Stop a history enumerator safely, including timer/cleanup races."""
    try:
        if process.poll() is None:
            process.kill()
    except OSError:
        # The timeout timer and scan thread can observe process exit together.
        pass


def _metadata(root: Path, commit: str, deadline: float) -> tuple[str, str]:
    raw = _run_git(
        ["show", "-s", "--format=%an%x00%aI", commit], root,
        timeout=min(GIT_COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic()), max_output=4096,
    )
    fields = raw.rstrip(b"\r\n").split(b"\0", 1)
    if len(fields) != 2:
        raise GitHistoryScanError("Git returned invalid commit metadata")
    author = fields[0].decode("utf-8", errors="replace")
    author = "".join(ch for ch in author if ch >= " " and ch != "\x7f")[:200]
    authored_at = fields[1].decode("ascii", errors="replace")[:64]
    return author, authored_at


def _changed_paths(root: Path, commit: str, deadline: float) -> list[tuple[str, str]]:
    raw = _run_git(
        ["diff-tree", "--root", "--no-commit-id", "-r", "--find-renames", "--find-copies",
         "--diff-filter=AMRC", "--name-status", "-z", commit],
        root, timeout=min(GIT_COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic()),
        max_output=MAX_COMMIT_FILES * 2048,
    )
    tokens = raw.split(b"\0")
    changes: list[tuple[str, str]] = []
    index = 0
    while index < len(tokens) and tokens[index]:
        status = tokens[index].decode("ascii", errors="ignore")
        index += 1
        if status.startswith(("R", "C")):
            if index + 1 >= len(tokens):
                raise GitHistoryScanError("Git returned invalid rename metadata")
            index += 1  # Old path
            name = tokens[index]
            index += 1
        else:
            if index >= len(tokens):
                raise GitHistoryScanError("Git returned invalid change metadata")
            name = tokens[index]
            index += 1
        if status[:1] not in {"A", "M", "R", "C"}:
            continue
        try:
            path = name.decode("utf-8")
        except UnicodeDecodeError:
            continue
        changes.append((status, path.replace("\\", "/")))
        if len(changes) > MAX_COMMIT_FILES:
            raise GitHistoryScanError("Commit changes exceed the per-commit file limit")
    return changes


def _blob_info(root: Path, commit: str, path: str, deadline: float) -> tuple[str, str, int] | None:
    pathspec = f":(literal){path}"
    raw = _run_git(
        ["ls-tree", "-z", commit, "--", pathspec], root,
        timeout=min(GIT_COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic()), max_output=4096,
    )
    if not raw:
        return None
    record = raw.split(b"\0", 1)[0]
    metadata, _sep, _name = record.partition(b"\t")
    fields = metadata.split()
    if len(fields) != 3 or fields[1] != b"blob":
        return None  # Skip symlinks and submodules.
    mode = fields[0].decode("ascii", errors="ignore")
    if mode == "120000":
        return None
    oid = fields[2].decode("ascii", errors="ignore")
    if not _SHA.fullmatch(oid):
        raise GitHistoryScanError("Git returned invalid blob metadata")
    size_raw = _run_git(
        ["cat-file", "-s", oid], root,
        timeout=min(GIT_COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic()), max_output=128,
    )
    try:
        size = int(size_raw.strip())
    except ValueError as exc:
        raise GitHistoryScanError("Git returned invalid blob size") from exc
    return oid.lower(), mode, size


def _diff_added_lines(root: Path, commit: str, parent: str | None, path: str, deadline: float) -> list[tuple[int, str]]:
    pathspec = f":(literal){path}"
    if parent is None:
        args = ["diff-tree", "--root", "-p", "-r", "--no-commit-id", "--no-ext-diff",
                "--no-textconv", "--no-color", "--unified=0", commit, "--", pathspec]
    else:
        args = ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0",
                parent, commit, "--", pathspec]
    patch = _run_git(
        args, root, timeout=min(GIT_COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic()),
        max_output=MAX_DIFF_BYTES,
    )
    if b"GIT binary patch" in patch or b"Binary files " in patch:
        return []
    additions: list[tuple[int, str]] = []
    current_line: int | None = None
    new_symlink = False
    lfs_pointer = False
    for line in patch.splitlines():
        if line.startswith(b"new file mode 120000") or line.startswith(b"mode change 100644 => 120000") or line.startswith(b"mode change 100755 => 120000"):
            new_symlink = True
        if line.startswith(b"@@"):
            match = _HUNK.match(line)
            current_line = int(match.group(1)) if match else None
            continue
        if line.startswith(b"+++ "):
            continue
        if line.startswith(b"+") and current_line is not None:
            text = line[1:].decode("utf-8", errors="replace")
            if not additions and text.strip() == "version https://git-lfs.github.com/spec/v1":
                lfs_pointer = True
            additions.append((current_line, text))
            current_line += 1
        elif line.startswith(b" ") and current_line is not None:
            current_line += 1
    if new_symlink or lfs_pointer:
        return []
    return additions


def _in_head(root: Path, ref: str, path: str, blob_sha: str, deadline: float) -> bool:
    info = _blob_info(root, ref, path, deadline)
    return bool(info and info[0] == blob_sha)


def scan_git_history(
    repository_path: str | Path,
    *,
    repository: str,
    scan_added_text: Callable[[str, str], list[T]],
    ref: str = "HEAD",
    resume_after: str | None = None,
    max_commits: int = MAX_HISTORY_COMMITS,
    max_files: int = MAX_HISTORY_FILES,
    max_bytes: int = MAX_HISTORY_BYTES,
    time_budget_seconds: int = MAX_HISTORY_SECONDS,
) -> GitHistoryScanResult[T]:
    """Scan added text lines in chronological Git history with a commit resume cursor."""
    root = Path(repository_path).resolve()
    if not root.is_dir():
        raise GitHistoryScanError("Git repository path does not exist")
    if not _REF.fullmatch(ref) or ref.startswith("-") or ".." in ref or "@{" in ref or ref.endswith("."):
        raise ValueError("Invalid Git history ref")
    if min(max_commits, max_files, max_bytes, time_budget_seconds) <= 0:
        raise ValueError("Git history scan limits must be positive")
    started = time.monotonic()
    deadline = started + time_budget_seconds
    try:
        inside = _run_git(["rev-parse", "--is-inside-work-tree"], root,
                          timeout=GIT_COMMAND_TIMEOUT_SECONDS, max_output=64).strip()
        if inside != b"true":
            raise GitHistoryScanError("Path is not a Git working tree")
        head_sha = _run_git(["rev-parse", "--verify", ref], root,
                            timeout=GIT_COMMAND_TIMEOUT_SECONDS, max_output=128).decode().strip().lower()
        if not _SHA.fullmatch(head_sha):
            raise GitHistoryScanError("Git returned an invalid head revision")
        shallow = _run_git(["rev-parse", "--is-shallow-repository"], root,
                           timeout=GIT_COMMAND_TIMEOUT_SECONDS, max_output=64).strip() == b"true"
    except (OSError, GitHistoryScanError) as exc:
        if isinstance(exc, GitHistoryScanError):
            raise
        raise GitHistoryScanError("Could not open Git repository") from exc

    force_push_detected = False
    revision_args = ["rev-list", "--reverse", ref]
    if resume_after is not None:
        if not _SHA.fullmatch(resume_after):
            raise ValueError("Resume cursor must be a Git commit SHA")
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", resume_after, ref], cwd=root,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=min(GIT_COMMAND_TIMEOUT_SECONDS, max(0.1, deadline - time.monotonic())),
        )
        if ancestor.returncode == 0:
            revision_args.append(f"^{resume_after}")
        else:
            force_push_detected = True

    patterns = _load_ignore_patterns(root)
    seen_blobs: set[str] = set()
    results: list[HistoricalFinding[T]] = []
    commits_scanned = files_scanned = bytes_scanned = 0
    last_commit: str | None = None
    partial_reason = None
    process = None
    timer = None
    try:
        process = subprocess.Popen(
            ["git", *revision_args], cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        timer = Timer(max(0.1, deadline - time.monotonic()), lambda: _kill_git_process(process))
        timer.daemon = True
        timer.start()
        assert process.stdout is not None
        while True:
            raw_commit = process.stdout.readline()
            if not raw_commit:
                break
            if time.monotonic() >= deadline:
                partial_reason = "Git history time budget reached"
                break
            if commits_scanned >= max_commits:
                partial_reason = "Git history commit limit reached"
                break
            commit = raw_commit.decode("ascii", errors="ignore").strip().lower()
            if not _SHA.fullmatch(commit):
                raise GitHistoryScanError("Git returned an invalid commit ID")
            commits_scanned += 1
            author, authored_at = _metadata(root, commit, deadline)
            parents = _run_git(["rev-list", "--parents", "-n", "1", commit], root,
                               timeout=min(GIT_COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic()), max_output=1024).decode().split()
            parent = parents[1] if len(parents) > 1 else None
            try:
                paths = _changed_paths(root, commit, deadline)
            except GitHistoryScanError as exc:
                if "output limit" in str(exc) or "per-commit file limit" in str(exc):
                    partial_reason = "Commit changed-file limit reached"
                    break
                raise
            for _status, path in paths:
                if time.monotonic() >= deadline:
                    partial_reason = "Git history time budget reached"
                    break
                if files_scanned >= max_files:
                    partial_reason = "Git history file limit reached"
                    break
                if _ignored(path, patterns):
                    continue
                info = _blob_info(root, commit, path, deadline)
                if not info:
                    continue
                blob_sha, _mode, blob_size = info
                if blob_sha in seen_blobs:
                    continue
                if blob_size > MAX_FILE_BYTES or blob_size > max_bytes - bytes_scanned:
                    if blob_size > MAX_FILE_BYTES:
                        continue
                    partial_reason = "Git history byte limit reached"
                    break
                seen_blobs.add(blob_sha)
                files_scanned += 1
                bytes_scanned += blob_size
                additions = _diff_added_lines(root, commit, parent, path, deadline)
                if not additions:
                    continue
                # Scan each contiguous added-line run and retain only detector
                # output and masked provenance, never the raw added text.
                for group in ([line] for line in additions):
                    text = "\n".join(line for _number, line in group)
                    if "\n".join(line for _number, line in group).strip().startswith("version https://git-lfs.github.com/spec/v1"):
                        continue
                    start_line, end_line = group[0][0], group[-1][0]
                    location = f"{path}:{start_line}-{end_line}"
                    findings = scan_added_text(text, location)
                    if findings:
                        results.append(HistoricalFinding(
                            findings=findings, blob_sha=blob_sha, commit_sha=commit,
                            author=author, authored_at=authored_at, file_path=path,
                            line_start=start_line, line_end=end_line,
                            blob_version_in_head=_in_head(root, ref, path, blob_sha, deadline),
                        ))
                if partial_reason:
                    break
            last_commit = commit
            if partial_reason:
                break
        if partial_reason is not None:
            # We may have stopped consuming rev-list output at a scan limit.
            # Kill it before waiting so a full stdout pipe cannot deadlock us.
            _kill_git_process(process)
        returncode = process.wait(timeout=max(0.1, min(1, deadline - time.monotonic())))
        if returncode != 0 and partial_reason is None:
            if time.monotonic() >= deadline:
                partial_reason = "Git history time budget reached"
            else:
                raise GitHistoryScanError("Git history enumeration failed")
    except subprocess.TimeoutExpired as exc:
        partial_reason = "Git history time budget reached"
    except GitHistoryScanError as exc:
        if "timed out" in str(exc).lower() or time.monotonic() >= deadline:
            partial_reason = "Git history time budget reached"
        else:
            raise
    finally:
        if timer:
            timer.cancel()
        if process:
            _kill_git_process(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _kill_git_process(process)
                process.wait()
            if process.stdout:
                process.stdout.close()

    if shallow and partial_reason is None:
        partial_reason = "Shallow clone does not contain the complete repository history"
    if partial_reason == "Shallow clone does not contain the complete repository history":
        # A SHA cursor cannot fetch older history by itself; caller must deepen
        # the clone before offering a continuation.
        resume = None
    else:
        resume = last_commit if partial_reason else None
    return GitHistoryScanResult(
        repository=repository, ref=ref, head_sha=head_sha, commits_scanned=commits_scanned,
        files_scanned=files_scanned, bytes_scanned=bytes_scanned, findings=results,
        partial=partial_reason is not None, partial_reason=partial_reason,
        resume_after=resume, force_push_detected=force_push_detected, shallow_history=shallow,
    )
