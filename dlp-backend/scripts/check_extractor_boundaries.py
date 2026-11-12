"""Fail if extractor code starts depending on DB, network, API, or app-service layers."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "app" / "extractors"
FORBIDDEN_PREFIXES = (
    "app.database",
    "app.routers",
    "app.services",
    "fastapi",
    "httpx",
    "requests",
    "socket",
    "supabase",
    "urllib.request",
)


def check_boundaries(root: Path = ROOT) -> list[str]:
    violations = []
    for source_path in sorted(root.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if any(name == prefix or name.startswith(prefix + ".") for prefix in FORBIDDEN_PREFIXES):
                    violations.append(f"{source_path.relative_to(root)}:{node.lineno}: forbidden import {name}")
    return violations


if __name__ == "__main__":
    errors = check_boundaries()
    if errors:
        print("\n".join(errors))
        raise SystemExit(1)
    print("Extractor import boundaries are clean.")
