"""Gitignore-style path matching for ``.dlpignore`` and allowlist paths."""

from __future__ import annotations

import re
from pathlib import Path


def _translate(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


class IgnoreMatcher:
    """Last matching rule wins; ``!`` negates, trailing ``/`` means directory."""

    def __init__(self, patterns: list[str]) -> None:
        self._rules: list[tuple[re.Pattern, bool]] = []
        for raw in patterns:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            if negate:
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            anchored = line.startswith("/") or "/" in line
            line = line.lstrip("/")
            body = _translate(line)
            prefix = "^" if anchored else "^(?:.*/)?"
            suffix = "/.*$" if dir_only else "(?:/.*)?$"
            self._rules.append((re.compile(prefix + body + suffix), negate))

    @classmethod
    def from_file(cls, path: Path) -> "IgnoreMatcher":
        try:
            return cls(path.read_text(encoding="utf-8").splitlines())
        except OSError:
            return cls([])

    def matches(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        rel = rel.lstrip("/")
        ignored = False
        for regex, negate in self._rules:
            if regex.match(rel):
                ignored = not negate
        return ignored
