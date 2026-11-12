# Offline developer scanner (P3 W22-25 starter)

Run from `dlp-backend` with the project environment installed:

```powershell
python -m app.cli_scan ..\path\to\repository --sarif .\dlp-results.sarif
```

The scanner uses the existing bounded extractors and the P1 detection entry
point without an organization ID. That means built-in detectors run offline;
organization-specific regex/EDM/fingerprint rules and policy evaluation are
not available. Findings make the command exit with code 1; use `--no-fail` to
report without gating. SARIF 2.1.0 output intentionally omits matched text so
CI artifacts do not contain detected secret values. Unsupported, oversized,
and unreadable files are reported as skipped. Directory walking skips common
generated/dependency directories and does not follow symlinks.

This is the initial local CLI slice, not yet a GitHub Action, pre-commit hook,
PR annotation integration, or VS Code extension. SARIF locations are emitted
when a detector supplies offsets; detector findings without offsets remain
file-level results.
