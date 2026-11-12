"""Command-line interface: ``python -m secretguard scan PATH``."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .detectors import default_detectors
from .models import Severity
from .reporting import RENDERERS
from .scanner import ScanConfig, Scanner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secretguard", description="Enterprise Secret Guard")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path")
    s.add_argument("--format", choices=sorted(RENDERERS), default="text")
    s.add_argument("--output", "-o", help="write the report to a file instead of stdout")
    s.add_argument("--min-confidence", type=float, default=0.30,
                   help="drop findings below this confidence (default 0.30)")
    s.add_argument("--fail-on", default="medium", choices=[x.name.lower() for x in Severity],
                   help="exit with status 1 if any finding is at/above this severity (default medium)")
    s.add_argument("--no-secrets", action="store_true", help="disable the secret/entropy detector")
    s.add_argument("--no-india", action="store_true", help="disable Indian identifier detectors")

    sub.add_parser("rules", help="list active detectors")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        for d in default_detectors():
            print("%-22s %-18s %s" % (d.rule_id, d.category, d.description))
        return 0

    if not os.path.exists(args.path):
        print("error: path not found: %s" % args.path, file=sys.stderr)
        return 2

    detectors = default_detectors(include_secrets=not args.no_secrets, include_india=not args.no_india)
    scanner = Scanner(detectors, ScanConfig(min_confidence=args.min_confidence))
    try:
        result = scanner.scan_path(args.path)
    except FileNotFoundError:
        print("error: path not found: %s" % args.path, file=sys.stderr)
        return 2
    report = RENDERERS[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print("report written to %s (%d findings)" % (args.output, len(result.findings)))
    else:
        print(report)
    threshold = Severity.parse(args.fail_on)
    worst = result.max_severity()
    return 1 if worst is not None and worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
