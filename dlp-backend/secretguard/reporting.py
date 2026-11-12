"""Report renderers. Only redacted evidence is ever emitted."""
from __future__ import annotations

import json
from typing import Dict

from . import __version__
from .models import Severity
from .scanner import ScanResult


def render_text(result: ScanResult) -> str:
    lines = ["Enterprise Secret Guard %s - scan report" % __version__,
             "Scanned %d file(s), skipped %d, in %.2fs" % (
                 result.files_scanned, len(result.skipped), result.duration_s),
             "Findings: %d  (%s)" % (
                 len(result.findings),
                 ", ".join("%s %d" % (k, v) for k, v in result.counts_by_severity().items() if v) or "none"),
             "Raw identifier values are never printed; evidence below is redacted.", ""]
    for f in sorted(result.findings, key=lambda x: (-int(x.severity), x.file, x.line)):
        where = "%s:%d:%d" % (f.file, f.line, f.column)
        if f.field_name:
            where += "  field=%s" % f.field_name
        lines.append("[%s] %s  confidence=%.2f  %s" % (f.severity.name, f.rule_id, f.confidence, where))
        lines.append("       evidence: %s" % f.evidence)
        lines.append("       why: %s" % "; ".join(f.reasons))
    if result.skipped:
        lines.append("")
        lines.append("Skipped files:")
        lines.extend("  %s (%s)" % s for s in result.skipped)
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "enterprise-secret-guard", "version": __version__,
        "summary": {"files_scanned": result.files_scanned, "files_skipped": len(result.skipped),
                    "findings": len(result.findings), "by_severity": result.counts_by_severity(),
                    "by_rule": result.counts_by_rule()},
        "findings": [f.to_dict() for f in result.findings],
        "skipped": [{"file": p, "reason": r} for p, r in result.skipped],
    }, indent=2)


def render_sarif(result: ScanResult) -> str:
    level: Dict[Severity, str] = {Severity.CRITICAL: "error", Severity.HIGH: "error",
                                  Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
    rules = [{"id": r, "shortDescription": {"text": r}} for r in result.counts_by_rule()]
    results = [{
        "ruleId": f.rule_id, "level": level[f.severity],
        "message": {"text": "%s detected (confidence %.2f): %s" % (f.rule_id, f.confidence, f.evidence)},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file.replace("\\", "/")},
            "region": {"startLine": f.line, "startColumn": f.column}}}],
        "properties": {"severity": f.severity.name, "confidence": f.confidence, "field": f.field_name},
    } for f in result.findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Enterprise Secret Guard", "version": __version__,
                                      "rules": rules}}, "results": results}],
    }, indent=2)


RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif}
