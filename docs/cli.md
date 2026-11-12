# dlp CLI, pre-commit hook, GitHub Action and VS Code extension

Offline scanner for developers (plan W22-25). A scan never opens a network
connection; only `dlp sync-allowlist` does. Source: `dlp-cli/`.

## Install

    pip install ./dlp-cli                      # from a checkout
    pip install git+https://github.com/BourrBo/Dlp   # root pyproject.toml is a shim for dlp-cli/

Python 3.9+. No runtime dependencies on 3.11+ (`tomli` on older versions). Works on Windows and Linux.

## Commands

    dlp scan --staged                        # lines you are about to commit
    dlp scan --path src/ --path README.md    # files or folders
    dlp scan --git-range origin/main..HEAD   # every added line in every commit of the range
    dlp scan --path . --format sarif --output dlp.sarif
    dlp scan --path . --format json
    dlp rules                                # list built-in rules
    dlp sync-allowlist --server https://dlp.example.com --api-key $KEY

`--staged` and `--git-range` read only the **added** lines of a diff, so a small
commit scans in well under a second (a test asserts under 2 seconds on a 3,000-line
file). `--git-range` uses `git log -p`, so a secret added and removed inside the
range is still found, with its commit SHA.

Options: `--fail-on low|medium|high|critical` (default `medium`), `--quiet`
(print nothing when clean), `--config PATH`, `--format text|json|sarif`, `--output FILE`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Clean, or findings below `--fail-on` |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage or configuration error (bad flag, unknown config key) |
| 3 | Internal or git error. Hooks fail closed: an error blocks the commit |

## Built-in rules

Line and column accurate. Findings show masked values only; raw values are never
printed, written to SARIF or stored.

| ID | Severity | Detects |
| --- | --- | --- |
| DLP001 | critical | Private key block |
| DLP002 | critical | AWS access key ID |
| DLP003 | critical | AWS secret access key |
| DLP004 | critical | GitHub token |
| DLP005 | high | Slack token |
| DLP006 | high | Google API key |
| DLP007 | high | Prefixed API key (`sk_live_...`) |
| DLP008 | medium | Hard-coded password or secret assignment (entropy and placeholder checks) |
| DLP009 | high | Payment card (Luhn plus network prefix and length) |
| DLP010 | high | Aadhaar (Verhoeff checksum) |
| DLP011 | medium | Indian PAN |
| DLP012 | low | Email address |

These are stand-ins for P1's frozen offline detector package (plan W16). To switch,
set `detector_module` in `.dlp.toml` to a module that exposes either `RULES` (a list of
`dlp_cli.detectors.Rule`) or `detect_line(line) -> list[Match]`.

## Configuration: `.dlp.toml`

Found by searching upward from the working directory to the repository root.

    fail_on = "medium"
    max_file_bytes = 2000000
    disable_rules = ["DLP012"]
    # detector_module = "p1_detectors.offline"

    [allowlist]
    paths = ["tests/fixtures/", "docs/examples/**"]
    fingerprints = ["0123456789abcdef"]

Unknown keys are an error (exit 2) so a typo cannot silently disable a check.

## Skips and the allowlist

- Default skips: `.git`, `node_modules`, `vendor`, `dist`, `build`, virtualenvs, lockfiles,
  `*.min.*`, binary and document formats (use the platform scan for PDF/Office), symlinks,
  files over `max_file_bytes`, binary content (NUL bytes). UTF-16 files are decoded.
- `.dlpignore` at the repository root uses gitignore syntax (`#`, `!`, trailing `/`, `**`).
- Inline: add `dlp:allow` anywhere on a line.
- Fingerprints: each finding has a 16-hex fingerprint (`dlp scan --format json`). A fingerprint
  is a truncated SHA-256 of the rule and value, never the value. `sync-allowlist` downloads
  approved fingerprints to `.dlp-allowlist.json`. Server contract: `GET {server}/api/v1/allowlist`
  with `Authorization: Bearer <key>` returning `{"fingerprints": ["..."]}`. The platform serves this route:
  create an API key in the dashboard, then admins approve fingerprints with `POST /api/v1/allowlist`
  (`{"fingerprint": "<16 hex>", "reason": "..."}`) and remove them with `DELETE /api/v1/allowlist/<fingerprint>`.
- The skipped list (with reasons) is in the `--format json` output.

## pre-commit

Add to `.pre-commit-config.yaml` of the repository you want to protect:

    repos:
      - repo: https://github.com/BourrBo/Dlp
        rev: v0.1.0
        hooks:
          - id: dlp-scan

The hook (`.pre-commit-hooks.yaml`) runs `dlp scan --staged --quiet`. Verified with a real
`pre-commit` run: a clean commit passes, a commit adding a fake card number is blocked.
Bypassing with `git commit --no-verify` is possible by design; run the Action in CI as the
second line of defence.

## GitHub Action

See `docs/examples/dlp-scan.yml`. Inputs: `mode` (`path` or `range`), `path`, `fail-on`,
`sarif-file`, `upload-sarif`, `python-version`. `range` mode needs `fetch-depth: 0` and scans
the pull request's commits. Inputs reach the script as environment variables, never
interpolated into shell. **Licence note:** uploading SARIF to GitHub code scanning is free on
public repositories; private repositories need GitHub Code Security. Leave `upload-sarif` at
`false` there; the job still fails on findings.

## SARIF

SARIF 2.1.0, validated against the official schema in tests. Rules carry `security-severity`
(critical 9.5, high 8.0, medium 5.0, low 2.0), results carry `partialFingerprints`
(`dlpFingerprint/v1`), and `properties.commit` for `--git-range` findings.

## Pull-request check (server side)

`dlp-backend/app/services/pr_check.py` creates a GitHub check run named "DLP scan" with
annotations on the exact added line (`failure` for blocking values, `warning` otherwise,
50 per request, 500 maximum with a partial-results notice). If the scan cannot run, it
publishes a failing check ("could not scan") rather than passing. `pull_request` webhooks
(`opened`, `synchronize`, `reopened`) are now accepted and queued as metadata only
(`refs/pull/N/head` and the head SHA). **Open:** no worker consumes the queue yet, the
detector and gate are injectable stand-ins for P1's detector and P2's gate API, and the
GitHub App needs the `pull_requests: read` permission added to its minimal set.

## VS Code extension

`dlp-vscode/` wraps the CLI: scans on save, shows problems on the exact range, commands
*Scan current file*, *Scan workspace*, *Clear diagnostics*. Settings: `dlp.cliPath`
(machine scope, ignored in untrusted workspaces), `dlp.scanOnSave`, `dlp.failOn`,
`dlp.timeoutSeconds`. Package with `npx @vscode/vsce package`. The pure parsing logic has
Node tests, including a run against the real CLI; the VS Code API layer itself
(`extension.js`) was syntax-checked but not run inside VS Code.

## Known limits

- Detection is pattern plus checksum. It cannot find a secret that has no recognisable shape.
- Unified diffs with renames report only the changed lines of the new path.
- `--git-range` skips merge commits (`--no-merges`); their content is in the parent commits.
- Documents (PDF, Office, archives) are skipped by the CLI; the platform scan handles them.
