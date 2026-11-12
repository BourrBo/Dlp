"""Minimal git plumbing: parse added lines out of unified diffs."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


class GitError(RuntimeError):
    """Git failed or is missing (CLI exit code 3)."""


@dataclass(frozen=True)
class AddedLine:
    path: str
    line: int
    text: str
    commit: Optional[str] = None


_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
COMMIT_MARK = "\x01DLPCOMMIT "


def run_git(args: list[str], cwd: Path, timeout: int = 120) -> bytes:
    cmd = ["git", "-c", "core.quotepath=off", "-c", "color.ui=false", *args]
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args[:2])} timed out after {timeout}s") from exc
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitError(f"git {args[0]} failed: {message[-1] if message else proc.returncode}")
    return proc.stdout


def repo_root(cwd: Path) -> Path:
    return Path(run_git(["rev-parse", "--show-toplevel"], cwd).decode("utf-8", "replace").strip())


def _unquote(path: str) -> str:
    if not (path.startswith('"') and path.endswith('"')):
        return path
    raw, out, i = path[1:-1], bytearray(), 0
    escapes = {"n": 10, "t": 9, "r": 13, '"': 34, "\\": 92}
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in escapes:
                out.append(escapes[nxt])
                i += 2
                continue
            octal = re.match(r"[0-7]{1,3}", raw[i + 1:])
            if octal:
                out.append(int(octal.group(0), 8))
                i += 1 + len(octal.group(0))
                continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return out.decode("utf-8", "replace")


def parse_diff(text: str) -> Iterator[AddedLine]:
    """Yield added lines with new-file line numbers. Works for ``-U0`` output
    from ``git diff`` and ``git log -p`` (commits marked by ``COMMIT_MARK``)."""
    path: Optional[str] = None
    commit: Optional[str] = None
    new_line = old_left = new_left = 0
    for line in text.split("\n"):
        if line.startswith(COMMIT_MARK):
            commit, path, old_left, new_left = line[len(COMMIT_MARK):].strip(), None, 0, 0
            continue
        if old_left <= 0 and new_left <= 0:
            if line.startswith("diff --git "):
                path = None
            elif line.startswith("+++ "):
                target = line[4:].rstrip("\t").rstrip("\r")
                if target == "/dev/null":
                    path = None
                else:
                    target = _unquote(target)
                    path = target[2:] if target.startswith("b/") else target
            else:
                m = _HUNK.match(line)
                if m:
                    old_left = int(m.group(1)) if m.group(1) is not None else 1
                    new_line = int(m.group(2))
                    new_left = int(m.group(3)) if m.group(3) is not None else 1
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("+"):
            if path is not None and not line.startswith("+Subproject commit"):
                yield AddedLine(path, new_line, line[1:].rstrip("\r"), commit)
            new_line += 1
            new_left -= 1
        elif line.startswith("-"):
            old_left -= 1
        else:  # context line (only with -U>0)
            new_line += 1
            new_left -= 1
            old_left -= 1


def staged_added_lines(cwd: Path) -> Iterator[AddedLine]:
    out = run_git(["diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR"], cwd)
    yield from parse_diff(out.decode("utf-8", "replace"))


def range_added_lines(cwd: Path, git_range: str) -> Iterator[AddedLine]:
    if git_range.startswith("-"):
        raise GitError("git range must not start with '-'")
    fmt = "--format=" + COMMIT_MARK.replace("\x01", "%x01") + "%H"
    out = run_git(["log", "-p", "-U0", "--no-merges", "--no-color", "--no-ext-diff", fmt, git_range, "--"], cwd)
    yield from parse_diff(out.decode("utf-8", "replace"))
