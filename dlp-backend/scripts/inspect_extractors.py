"""Sandbox utility: inspect supported files and their extracted locations."""

import argparse
from pathlib import Path

from app.extractors import extract_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to inspect")
    args = parser.parse_args()

    files: list[Path] = []
    for path in args.paths:
        if path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file())
        else:
            files.append(path)

    for path in files:
        result = extract_file(path, display_path=path.as_posix())
        if result.skipped_reason:
            print(f"SKIPPED {path}: {result.skipped_reason}")
            continue
        print(f"EXTRACTED {path}: {len(result.chunks)} chunks, {result.extracted_chars} chars ({result.encoding})")
        for chunk in result.chunks[:3]:
            preview = " ".join(chunk.text.split())[:100]
            print(f"  {chunk.location}: {preview}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
