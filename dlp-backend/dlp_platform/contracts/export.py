"""Deterministically export JSON Schema snapshots for the proposed contracts."""

import json
from pathlib import Path

from pydantic import BaseModel

from . import (
    CONTRACT_STATUS,
    CONTRACT_VERSION,
    Event,
    Finding,
    Incident,
    Policy,
    Principal,
    ScanRequest,
    ScanResult,
)

MODELS: tuple[type[BaseModel], ...] = (
    Finding,
    ScanRequest,
    ScanResult,
    Event,
    Policy,
    Incident,
    Principal,
)


def export_schemas(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for model in MODELS:
        schema = model.model_json_schema()
        rendered = json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        (output_dir / f"{model.__name__}.schema.json").write_text(rendered, encoding="utf-8")
    manifest = {
        "contract_version": CONTRACT_VERSION,
        "status": CONTRACT_STATUS,
        "models": [model.__name__ for model in MODELS],
    }
    rendered_manifest = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    (output_dir / "manifest.json").write_text(rendered_manifest, encoding="utf-8")
