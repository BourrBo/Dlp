import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from dlp_platform.contracts import Event, Finding, Incident, Policy, Principal, ScanRequest, ScanResult

SCHEMA_DIR = Path("contracts/schemas")
CONTRACTS: tuple[type[BaseModel], ...] = (
    Finding,
    ScanRequest,
    ScanResult,
    Event,
    Policy,
    Incident,
    Principal,
)


@pytest.mark.parametrize("model", CONTRACTS, ids=lambda model: model.__name__)
def test_schema_snapshot_matches_model(model: type[BaseModel]) -> None:
    snapshot_path = SCHEMA_DIR / f"{model.__name__}.schema.json"
    expected = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert model.model_json_schema() == expected
    assert expected["additionalProperties"] is False


def test_contract_manifest_is_proposed_v1() -> None:
    manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["contract_version"] == "1.0.0"
    assert manifest["status"] == "PROPOSED"
    assert set(manifest["models"]) == {model.__name__ for model in CONTRACTS}
