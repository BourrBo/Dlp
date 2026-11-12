"""SARIF 2.1.0 export. Messages carry only masked values."""

from __future__ import annotations

from typing import Any

from dlp_cli import __version__
from dlp_cli.scanner import Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}


def to_sarif(findings: list[Finding], tool_version: str = __version__) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.data_type,
            "shortDescription": {"text": f.description},
            "help": {"text": f.guidance},
            "defaultConfiguration": {"level": _LEVEL[f.severity]},
            "properties": {
                "tags": ["security", "dlp", f.data_type],
                "security-severity": _SECURITY_SEVERITY[f.severity],
            },
        })
    ordered = sorted(rules)
    index = {rule_id: i for i, rule_id in enumerate(ordered)}
    results = []
    for f in findings:
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.description} detected ({f.masked}). {f.guidance}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.column, "endColumn": f.end_column},
                }
            }],
            "partialFingerprints": {"dlpFingerprint/v1": f.fingerprint},
            "properties": {"confidence": f.confidence, "severity": f.severity},
        }
        if f.commit:
            result["properties"]["commit"] = f.commit
        results.append(result)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dlp-cli",
                "version": tool_version,
                "informationUri": "https://github.com/BourrBo/Dlp",
                "rules": [rules[r] for r in ordered],
            }},
            "results": results,
        }],
    }
