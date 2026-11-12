"""Prove the configured secret scanner flags a synthetic-only canary."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    scanner = os.environ.get("GITLEAKS_BIN", "gitleaks")
    with tempfile.TemporaryDirectory(prefix="dlp-secret-fixture-") as temp_dir:
        fixture = Path(temp_dir) / "synthetic.txt"
        fixture.write_text("DLP_TEST_SECRET_" + ("A" * 32), encoding="utf-8")
        result = subprocess.run(
            [
                scanner,
                "detect",
                "--no-git",
                "--source",
                temp_dir,
                "--config",
                ".gitleaks.toml",
                "--redact",
                "--exit-code",
                "1",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode == 1:
        print("Synthetic secret canary was detected as expected.")
        return 0
    if result.returncode == 0:
        print("ERROR: synthetic secret canary was not detected.")
        return 1
    print(f"ERROR: gitleaks failed with exit code {result.returncode}.")
    print(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
