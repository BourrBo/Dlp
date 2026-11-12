# Teammate merge status

Updated 8 November 2026. All teammate work is merged into this repository.

| Source | What was merged | Where |
|---|---|---|
| P3 continuation (Shivam) | CLI, pre-commit hook, GitHub Action, VS Code extension, endpoint agent, device API, PR checks | `dlp-cli`, `action.yml`, `.pre-commit-hooks.yaml`, `dlp-vscode`, `dlp-agent`, `app/routers/devices.py`, `app/services/pr_check.py` |
| P4 (Ashish) | Dashboard redesign, landing page, findings page (now live data), backend incidents/findings | `dlp-Frontend`, `app/routers/incidents.py`, `app/routers/findings.py`; personal sign-in added to the extension |
| P2 platform | Full platform vendored as `dlp_platform` with migrations, contracts, docs and 376 tests; API-key auth bridged into scan routes; pipeline wired to the main detectors | `dlp-backend/dlp_platform`, `app/platform_bridge`, `docs/platform` |
| Secret Guard (milestones 2 and 3) | Engine used by detection; tests and demo data kept | `dlp-backend/secretguard`, `tests/secretguard_engine`, `tools/secret-guard` |

Fixed while merging: extension scans failed without `org_id`; the CLI allowlist route did not exist; the scan page referenced an undefined variable; the REST client had no delete; findings were never stored and incidents never opened.

See [INTEGRATION.md](INTEGRATION.md) for architecture and known limits.
