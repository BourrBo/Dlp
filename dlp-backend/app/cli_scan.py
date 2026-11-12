"""Offline repository scanner and SARIF 2.1.0 writer (P3 W22-25)."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Iterable

from app.extractors.limits import MAX_FILES_PER_SCAN, MAX_FILE_BYTES
from app.extractors.runner import extract_bytes_with_timeout
from app.models.finding import Finding
from app.services.person_b.detection_service import detect

_EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
_RULE_PREFIX = "DLP"


def iter_files(inputs: Iterable[Path]) -> tuple[list[Path], bool]:
    """Enumerate regular files deterministically without following symlinks."""
    found: set[Path] = set()
    truncated = False
    for item in inputs:
        try:
            if item.is_symlink():
                continue
            if item.is_file():
                found.add(item.resolve())
            elif item.is_dir():
                for root, dirs, files in os.walk(item, followlinks=False):
                    dirs[:] = sorted(
                        d for d in dirs
                        if d not in _EXCLUDED_DIRS and not (Path(root) / d).is_symlink()
                    )
                    for name in sorted(files):
                        path = Path(root) / name
                        if not path.is_symlink():
                            found.add(path.resolve())
                            if len(found) > MAX_FILES_PER_SCAN:
                                truncated = True
                                return sorted(found)[:MAX_FILES_PER_SCAN], truncated
        except OSError:
            continue
    return sorted(found)[:MAX_FILES_PER_SCAN], truncated or len(found) > MAX_FILES_PER_SCAN


def _finding_result(path: Path, finding: Finding, chunk_text: str, location: dict) -> dict:
    start = finding.start
    end = finding.end
    region: dict[str, int] = {}
    if start is not None and end is not None and start <= end <= len(chunk_text):
        prefix = chunk_text[:start]
        matched = chunk_text[start:end]
        base_line = int(location.get("line_start", 1))
        start_line = base_line + prefix.count("\n")
        start_col = len(prefix.rsplit("\n", 1)[-1]) + 1
        end_line = start_line + matched.count("\n")
        end_col = len(matched.rsplit("\n", 1)[-1]) + (1 if end_line != start_line else start_col)
        region = {"startLine": start_line, "startColumn": start_col, "endLine": end_line, "endColumn": end_col}

    rule_id = f"{_RULE_PREFIX}-{finding.data_type.value.upper()}"
    physical_location: dict = {"artifactLocation": {"uri": path.as_posix()}}
    if region:
        physical_location["region"] = region
    # Deliberately do not include matched_snippet: SARIF is often uploaded to CI.
    return {
        "ruleId": rule_id,
        "level": "error" if finding.confidence >= 0.85 else "warning",
        "message": {"text": f"Potential {finding.data_type.value.replace('_', ' ')} detected."},
        "locations": [{"physicalLocation": physical_location}],
        "properties": {"confidence": finding.confidence, "sensitivityLevel": finding.sensitivity_level},
    }


def scan_paths(inputs: Iterable[Path]) -> tuple[list[dict], list[str], bool]:
    files, truncated = iter_files(inputs)
    results: list[dict] = []
    skipped: list[str] = []
    seen: set[tuple[str, str, int | None, int | None]] = set()
    for path in files:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append(f"{path}: file exceeds {MAX_FILE_BYTES // (1024 * 1024)} MiB")
                continue
            with path.open("rb") as source:
                data = source.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                skipped.append(f"{path}: file exceeds {MAX_FILE_BYTES // (1024 * 1024)} MiB")
                continue
        except OSError:
            skipped.append(f"{path}: could not read file")
            continue
        extracted = extract_bytes_with_timeout(data, display_path=path.as_posix())
        if extracted.skipped_reason:
            skipped.append(f"{path}: {extracted.skipped_reason}")
            continue
        for chunk in extracted.chunks:
            for finding in detect(chunk.text):
                marker = (str(path), finding.data_type.value,
                          int(chunk.location.get("char_start", 0)) + finding.start if finding.start is not None else None,
                          int(chunk.location.get("char_start", 0)) + finding.end if finding.end is not None else None)
                if marker in seen:
                    continue
                seen.add(marker)
                results.append(_finding_result(path, finding, chunk.text, chunk.location))
    return results, skipped, truncated


def make_sarif(results: list[dict]) -> dict:
    rules = sorted({result["ruleId"] for result in results})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "DLP Guardian",
                "informationUri": "https://github.com/BourrBo/Dlp",
                "rules": [{"id": rule, "shortDescription": {"text": rule.replace("DLP-", "Potential ").replace("_", " ").lower()}} for rule in rules],
            }},
            "results": results,
        }],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan files or directories offline and optionally emit SARIF.")
    parser.add_argument("paths", nargs="+", type=Path, help="Files and/or directories to scan")
    parser.add_argument("--sarif", type=Path, help="Write SARIF 2.1.0 results to this file")
    parser.add_argument("--no-fail", action="store_true", help="Return success even when findings are present")
    args = parser.parse_args(argv)
    results, skipped, truncated = scan_paths(args.paths)
    for result in results:
        location = result["locations"][0]["physicalLocation"]
        region = location.get("region", {})
        where = location["artifactLocation"]["uri"]
        if "startLine" in region:
            where += f":{region['startLine']}:{region['startColumn']}"
        print(f"{result['level']}: {result['message']['text']} ({where})")
    for message in skipped:
        print(f"skipped: {message}", file=sys.stderr)
    if truncated:
        print(f"warning: scan stopped at the {MAX_FILES_PER_SCAN}-file limit", file=sys.stderr)
    if args.sarif:
        args.sarif.write_text(json.dumps(make_sarif(results), indent=2) + "\n", encoding="utf-8")
    print(f"Scanned results: {len(results)} finding(s), {len(skipped)} skipped file(s).")
    return 1 if results and not args.no_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
