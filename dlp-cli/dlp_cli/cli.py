"""``dlp`` command line.

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or config
error, 3 internal or git error. A scan never uses the network; only
``sync-allowlist`` does.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from dlp_cli import __version__
from dlp_cli.config import ALLOWLIST_CACHE_NAME, Config, ConfigError, load_config
from dlp_cli.detectors import RULES, SEVERITY_ORDER
from dlp_cli.gitutil import GitError, range_added_lines, repo_root, staged_added_lines
from dlp_cli.sarif import to_sarif
from dlp_cli.scanner import Report, Scanner

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3
_FINGERPRINT = re.compile(r"^[0-9a-f]{16}$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlp", description="Offline DLP scanner for developers.")
    parser.add_argument("--version", action="version", version=f"dlp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan staged changes, paths or a git range")
    mode = scan.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scan lines added in the git index")
    mode.add_argument("--path", action="append", metavar="PATH", help="file or folder (repeatable)")
    mode.add_argument("--git-range", metavar="RANGE", help="scan lines added in every commit of a range, e.g. origin/main..HEAD")
    scan.add_argument("--config", type=Path, help="path to .dlp.toml (default: search upwards)")
    scan.add_argument("--fail-on", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get), help="lowest severity that fails the run")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output", type=Path, help="write the report here instead of stdout")
    scan.add_argument("--quiet", action="store_true", help="print nothing when the scan is clean")

    sync = sub.add_parser("sync-allowlist", help="download approved fingerprints from the platform")
    sync.add_argument("--server", required=True, help="platform base URL")
    sync.add_argument("--api-key", help="API key (default: $DLP_API_KEY)")
    sync.add_argument("--config", type=Path)

    sub.add_parser("rules", help="list built-in rules")
    return parser


# ------------------------------------------------------------------ output


def render_text(report: Report, fail_on: str) -> str:
    lines = []
    for f in sorted(report.findings, key=lambda x: (x.path, x.line, x.column)):
        where = f"{f.path}:{f.line}:{f.column}"
        commit = f"  commit {f.commit[:10]}" if f.commit else ""
        lines.append(f"{where}  [{f.severity}] {f.rule_id} {f.description}  {f.masked}{commit}")
    seen: dict[str, str] = {}
    for f in report.findings:
        seen.setdefault(f.rule_id, f.guidance)
    if seen:
        lines.append("")
        lines.extend(f"{rule_id}: {text}" for rule_id, text in sorted(seen.items()))
    blocking = len(report.blocking(fail_on))
    lines.append(
        f"{len(report.findings)} finding(s), {blocking} at or above '{fail_on}'; "
        f"{report.files_scanned} file(s), {report.lines_scanned} line(s) scanned, {len(report.skipped)} skipped"
    )
    return "\n".join(lines)


def render_json(report: Report, fail_on: str) -> str:
    return json.dumps({
        "version": __version__,
        "summary": {"findings": len(report.findings), "blocking": len(report.blocking(fail_on)),
                    "files_scanned": report.files_scanned, "lines_scanned": report.lines_scanned,
                    "fail_on": fail_on},
        "findings": [f.to_dict() for f in report.findings],
        "skipped": [{"path": p, "reason": r} for p, r in report.skipped],
    }, indent=2)


def _emit(text: str, output: Optional[Path]) -> None:
    if output:
        output.write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")


# -------------------------------------------------------------------- scan


def _cmd_scan(args: argparse.Namespace) -> int:
    cwd = Path.cwd()
    config = load_config(args.config, cwd)
    if args.fail_on:
        config.fail_on = args.fail_on
    if args.staged or args.git_range:
        root = repo_root(cwd)
        scanner = Scanner(config, root)
        lines = staged_added_lines(root) if args.staged else range_added_lines(root, args.git_range)
        report = scanner.scan_added_lines(lines)
    else:
        try:
            root = repo_root(cwd)
        except GitError:
            root = cwd
        report = Scanner(config, root).scan_paths(Path(p) for p in args.path)

    if args.format == "sarif":
        text = json.dumps(to_sarif(report.findings), indent=2)
    elif args.format == "json":
        text = render_json(report, config.fail_on)
    else:
        text = render_text(report, config.fail_on)
    failing = bool(report.blocking(config.fail_on))
    if not (args.quiet and not report.findings and not args.output):
        _emit(text, args.output)
    return EXIT_FINDINGS if failing else EXIT_OK


# --------------------------------------------------------------- allowlist


def _cmd_sync(args: argparse.Namespace) -> int:
    key = args.api_key or os.environ.get("DLP_API_KEY")
    if not key:
        print("error: pass --api-key or set DLP_API_KEY", file=sys.stderr)
        return EXIT_USAGE
    parsed = urllib.parse.urlparse(args.server)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        print("error: --server must be https (http is allowed for localhost only)", file=sys.stderr)
        return EXIT_USAGE
    request = urllib.request.Request(
        args.server.rstrip("/") + "/api/v1/allowlist",
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - scheme checked above
            payload = json.loads(response.read(2_000_000))
    except (urllib.error.URLError, ValueError, OSError) as exc:
        print(f"error: allowlist sync failed: {type(exc).__name__}", file=sys.stderr)
        return EXIT_ERROR
    fingerprints = sorted({x for x in payload.get("fingerprints", []) if isinstance(x, str) and _FINGERPRINT.match(x)})
    config_path = args.config or None
    base = config_path.parent if config_path else Path.cwd()
    (base / ALLOWLIST_CACHE_NAME).write_text(
        json.dumps({"fingerprints": fingerprints, "synced_at": int(time.time())}, indent=2), encoding="utf-8")
    print(f"synced {len(fingerprints)} fingerprint(s) to {base / ALLOWLIST_CACHE_NAME}")
    return EXIT_OK


def main(argv: Optional[list[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "sync-allowlist":
            return _cmd_sync(args)
        for rule in RULES:
            print(f"{rule.id}  {rule.severity:<8} {rule.data_type:<18} {rule.description}")
        return EXIT_OK
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except GitError as exc:
        print(f"git error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # fail closed: a hook must not pass on an internal error
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
