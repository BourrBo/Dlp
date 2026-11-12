"""Scanning engine: file walking, format handling, overlap resolution."""
from __future__ import annotations

import csv
import io
import os
import re
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .detectors.base import Detector
from .models import Finding, Hit, Severity

try:
    csv.field_size_limit(10 ** 7)
except OverflowError:  # pragma: no cover
    pass

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tgz",
    ".bz2", ".xz", ".7z", ".rar", ".tar", ".exe", ".dll", ".so", ".dylib", ".class", ".jar",
    ".pyc", ".woff", ".woff2", ".ttf", ".mp3", ".mp4", ".mov", ".avi", ".bin", ".iso",
}
DEFAULT_EXCLUDE_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".idea"}
_XLSX_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_MAX_XLSX_UNCOMPRESSED = 200 * 1024 * 1024


class SkipFile(Exception):
    pass


@dataclass
class ScanConfig:
    min_confidence: float = 0.30
    max_file_bytes: int = 25 * 1024 * 1024
    exclude_dirs: Set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    duration_s: float = 0.0

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def counts_by_rule(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.rule_id] = out.get(f.rule_id, 0) + 1
        return dict(sorted(out.items()))

    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)


class Scanner:
    def __init__(self, detectors: Iterable[Detector], config: Optional[ScanConfig] = None) -> None:
        self.detectors = list(detectors)
        self.config = config or ScanConfig()

    # ------------------------------------------------------------ core cell
    def _scan_cell(self, text: str, hint: str = "", file_hint: str = "") -> List[Tuple[Detector, Hit]]:
        pairs = []
        for d in self.detectors:
            # File-level exclusions (such as lockfiles for entropy checks) are
            # distinct from CSV/XLSX column context used by identifier rules.
            detector_hint = file_hint if d.category == "secret" and not hint else hint
            for h in d.detect(text, detector_hint):
                if h.confidence >= self.config.min_confidence:
                    pairs.append((d, h))
        # overlap resolution: the highest-confidence interpretation of a span wins
        pairs.sort(key=lambda p: (-p[1].confidence, p[1].start))
        kept: List[Tuple[Detector, Hit]] = []
        for d, h in pairs:
            if all(h.end <= k.start or h.start >= k.end for _, k in kept):
                kept.append((d, h))
        kept.sort(key=lambda p: p[1].start)
        return kept

    @staticmethod
    def _to_findings(pairs, file: str, line: int, field_name: Optional[str]) -> List[Finding]:
        return [
            Finding(
                rule_id=h.detector, category=d.category,
                severity=h.severity if h.severity is not None else d.severity_for(h.confidence),
                confidence=round(h.confidence, 2), file=file, line=line, column=h.start + 1,
                evidence=d.redact(h.value), reasons=tuple(h.reasons), field_name=field_name,
            )
            for d, h in pairs
        ]

    # --------------------------------------------------------- text sources
    def _scan_lines(self, lines: Iterable[str], file: str) -> List[Finding]:
        out: List[Finding] = []
        for n, raw in enumerate(lines, 1):
            line = raw.rstrip("\r\n")
            if line:
                out.extend(self._to_findings(self._scan_cell(line, file_hint=file), file, n, None))
        return out

    def _scan_csv(self, fh, file: str, delimiter: str) -> List[Finding]:
        out: List[Finding] = []
        header: Optional[List[str]] = None
        try:
            for line_no, row in _reader_with_lines(fh, delimiter):
                for i, cell in enumerate(row):
                    if not cell:
                        continue
                    hint = header[i] if header and i < len(header) else ""
                    name = hint or None
                    out.extend(self._to_findings(self._scan_cell(cell, hint, file), file, line_no, name))
                if header is None:
                    header = row
        except csv.Error:
            fh.seek(0)
            return self._scan_lines(fh, file)
        return out

    def scan_text(self, text: str, name: str = "<text>", kind: str = "text") -> List[Finding]:
        """Scan an in-memory string. ``kind`` is 'text', 'csv' or 'tsv'."""
        if kind in ("csv", "tsv"):
            return self._scan_csv(io.StringIO(text, newline=""), name, "\t" if kind == "tsv" else ",")
        return self._scan_lines(text.splitlines(), name)

    # ----------------------------------------------------------------- xlsx
    def _scan_xlsx(self, path: str, display: str) -> List[Finding]:
        out: List[Finding] = []
        try:
            for sheet, rnum, cells, header in _iter_xlsx(path):
                for col, val in cells:
                    if not val:
                        continue
                    hint = header.get(col, "")
                    fname = "%s!%s" % (sheet, hint) if hint else sheet
                    out.extend(self._to_findings(self._scan_cell(val, hint, display), display, rnum, fname))
        except (zipfile.BadZipFile, ET.ParseError, KeyError, ValueError) as exc:
            raise SkipFile("unreadable xlsx (%s)" % exc.__class__.__name__)
        return out

    # ---------------------------------------------------------------- files
    def scan_file(self, path: str, display: Optional[str] = None) -> List[Finding]:
        path = str(path)
        display = display or path
        if os.path.islink(path):
            raise SkipFile("symlink not followed")
        if os.path.getsize(path) > self.config.max_file_bytes:
            raise SkipFile("larger than %d bytes" % self.config.max_file_bytes)
        ext = os.path.splitext(path)[1].lower()
        if ext in (".xlsx", ".xlsm"):
            return self._scan_xlsx(path, display)
        if ext in BINARY_EXTENSIONS:
            raise SkipFile("binary extension")
        with open(path, "rb") as fh:
            if b"\x00" in fh.read(8192):
                raise SkipFile("binary content")
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            if ext in (".csv", ".tsv"):
                return self._scan_csv(fh, display, "\t" if ext == ".tsv" else ",")
            return self._scan_lines(fh, display)

    def _iter_files(self, target: str) -> Iterator[str]:
        if os.path.isfile(target):
            yield target
            return
        for root, dirs, files in os.walk(target, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in self.config.exclude_dirs)
            for name in sorted(files):
                yield os.path.join(root, name)

    def scan_path(self, target: str) -> ScanResult:
        result = ScanResult()
        t0 = time.monotonic()
        for fp in self._iter_files(target):
            try:
                result.findings.extend(self.scan_file(fp))
                result.files_scanned += 1
            except SkipFile as exc:
                result.skipped.append((fp, str(exc)))
            except OSError as exc:
                result.skipped.append((fp, "error: %s" % (exc.strerror or exc.__class__.__name__)))
        result.findings.sort(key=lambda f: (f.file, f.line, f.column))
        result.duration_s = time.monotonic() - t0
        return result


def _reader_with_lines(fh, delimiter):
    reader = csv.reader(fh, delimiter=delimiter)
    for row in reader:
        yield reader.line_num, row


def _col_index(ref: str) -> int:
    letters = re.match(r"[A-Za-z]+", ref)
    n = 0
    for ch in (letters.group(0).upper() if letters else "A"):
        n = n * 26 + ord(ch) - 64
    return n


def _iter_xlsx(path: str):
    """Yield (sheet, row_number, [(col, text)], header_map) using only the stdlib."""
    with zipfile.ZipFile(path) as z:
        if sum(i.file_size for i in z.infolist()) > _MAX_XLSX_UNCOMPRESSED:
            raise ValueError("uncompressed size limit exceeded")
        names = z.namelist()
        shared: List[str] = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall(_XLSX_NS + "si"):
                shared.append("".join(t.text or "" for t in si.iter(_XLSX_NS + "t")))
        sheets = sorted(n for n in names if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
        for sheet_path in sheets:
            sheet = os.path.splitext(os.path.basename(sheet_path))[0]
            header: Dict[int, str] = {}
            root = ET.fromstring(z.read(sheet_path))
            first = True
            for row in root.iter(_XLSX_NS + "row"):
                rnum = int(row.get("r", "0") or 0)
                cells = []
                for c in row.findall(_XLSX_NS + "c"):
                    col = _col_index(c.get("r", "A"))
                    t = c.get("t")
                    v = c.find(_XLSX_NS + "v")
                    if t == "s":
                        val = shared[int(v.text)] if v is not None and v.text else ""
                    elif t == "inlineStr":
                        val = "".join(x.text or "" for x in c.iter(_XLSX_NS + "t"))
                    else:
                        val = v.text if v is not None and v.text else ""
                        if re.fullmatch(r"-?\d+(\.\d+)?[eE]\+?\d+", val):
                            try:
                                val = format(Decimal(val), "f")
                            except InvalidOperation:
                                pass
                    cells.append((col, val))
                if first:
                    header = {col: val for col, val in cells if val}
                    first = False
                yield sheet, rnum, cells, header
