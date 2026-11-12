"""Regenerate committed JSON Schema snapshots."""

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))


def main() -> None:
    from dlp_platform.contracts.export import export_schemas

    export_schemas(project_root / "contracts" / "schemas")


if __name__ == "__main__":
    main()
