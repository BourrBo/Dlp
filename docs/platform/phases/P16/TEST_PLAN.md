# P16 test plan and evidence

## Deterministic tests

`tests/connectors/test_p16_connectors.py` uses synthetic credentials and an injected fixture transport. It covers OAuth state binding and one-use semantics, PKCE S256, fixed-host rejection, OAuth URL settings, initial inventory pagination/shared-drive parameters, change pagination/checkpoint handling, repeated-page protection, bounded retry/non-retry errors, exposure categories, revoke verification/idempotence, shortcut identity, quarantine's explicit unsupported result, malformed/oversized permission metadata and lifecycle transition rules. `test_p16_scan_handoff.py` proves normalized Drive metadata reaches the existing `scan()` boundary and retains the tenant principal.

`test_p16_oauth_callback_http.py` exercises the mounted OAuth callback over HTTP using fixture provider/session dependencies. It covers valid callback, missing inputs, state rejection, expiry, replay, tampering, wrong tenant/principal/member/session/provider, PKCE mismatch, provider denial, invalid provider configuration, redirect-query tampering, and token/code redaction. PostgreSQL tests independently exercise durable state digest, tenant RLS, expiry, replay and concurrent consumption.

`test_p16_http_routes.py` enumerates the nine registered routes. `GET /connectors` and `GET /connectors/{connector_id}` are tenant-scoped reads requiring `connectors:read`; both accept scoped API keys. `POST /connectors`, OAuth start, sync, revoke-share, quarantine and disconnect are tenant-scoped mutations requiring `connectors:write` and an interactive user. The OAuth callback requires the authenticated initiating user and matching persistent tenant/principal/member/session/provider state. Missing and invalid credentials are exercised on every route; read/write scope denials cover all routes that use those permissions. `tests/auth/test_p16_connector_api_keys.py` checks valid/missing-scope/invalid/revoked read keys and confirms a write-scoped API key is rejected before action execution. API-key cases are not forced onto routes that require an interactive session. Tenant hiding covers both status directions and foreign IDs for revoke, sync, quarantine and disconnect; forged tenant/resource request fields are rejected. Foreign action requests do not read Vault plaintext, call Google or write action audit records. Quarantine safely returns 501.

`test_p16_scan_policy_p07_revoke.py` starts at the mounted connector sync endpoint with a realistic Drive change-feed fixture. Actual `GoogleDriveAPI.list_changes` consumes and normalizes the provider-shaped change, then existing sync calls `scan()`, P05 `PolicyEngine`, `ActionProcessor`, P07 approval HTTP routes and `GoogleDriveActionExecutor`. OAuth, Vault and Google revoke are fixture dependencies. Assertions cover normalized tenant/connector/file/permission identity, pending and rejected approvals with no provider call, forged client metadata, independent approver, successful revoke and audit events. Automated sync revocation selects a live public/link (`anyone`) permission; it fails closed rather than guessing a direct user/group/domain target.

`test_p16_checkpoint_actions.py` checks allow/log and revoke checkpoint outcomes. The change-feed integration simulates checkpoint persistence failure after a successful, durably recorded P07 revoke. Retry consumes the same change, advances the checkpoint from the durable P07 result and does not repeat the provider call. Feed processing is at-least-once; exactly-once external execution is not claimed for a crash before action status is persisted. Google revoke treats an already-absent permission as success.

`test_p16_secret_leakage.py`, callback tests, the PostgreSQL callback test and the sync/action test use synthetic access-token, refresh-token, OAuth-code, client-secret and Vault-plaintext markers. They inspect callback success/error responses, provider exception handling, OAuth persistence, Vault retrieval, action metadata/results, approval responses, audit metadata and connector model serialization. This is representative boundary coverage, not exhaustive instrumentation of every logger or database column.

`test_postgres_p16_connectors.py::test_persistent_postgres_oauth_callback_consumes_state_over_http` creates state in PostgreSQL and consumes it at the mounted HTTP callback. It verifies replay, persisted expiry, tenant-prefix tampering, principal mismatch, PKCE mismatch, fixed Google endpoint validation and no Vault credential write on rejected cases.

No fixture test contacts Google. No live-provider claim is made.

## PostgreSQL tests

`tests/isolation/test_postgres_p16_connectors.py` directly tests SELECT isolation, hidden cross-tenant UPDATE/DELETE, checkpoint isolation, missing tenant claims and forged cross-tenant INSERT rejection under `SET ROLE authenticated`. It also tests durable OAuth state persistence and two concurrent callback consumers (exactly one succeeds). `tests/isolation/test_postgres_migrations.py` applies the complete chain, downgrades P16 to P15, verifies P16 tables disappear, re-upgrades, and verifies forced RLS on the connector and OAuth tables.

Executed against the local PostgreSQL instance after loading the ignored `.env.p03-test` settings:

- Focused P16 fixture + PostgreSQL/RLS + migration suite — **64 passed, 0 failed, 0 skipped** (2026-10-23).
- Full P01–P16 repository suite, `.\\.venv\\Scripts\\python.exe -m pytest -q` with `P03_TEST_DATABASE_URL` loaded from ignored `.env.p03-test`: **363 passed, 0 failed, 0 skipped** (2026-10-23).
- Ruff lint — passed. Changed P16/P07 Python format check — 24 files already formatted. Repository-wide format check reports 12 files outside P16 that would be reformatted; they were left unchanged.
- mypy — passed (96 source files). pre-commit — passed, including hardcoded-secret detector. `pip-audit -r requirements.txt -r requirements-dev.txt` — no known vulnerabilities. `git diff --check` — passed.
- Standalone Gitleaks CLI is not installed. The configured pre-commit Gitleaks/hardcoded-secret hook passed. `detect-secrets scan --no-verify` over changed files reported 12 `Secret Keyword` heuristics: eight are role/audit vocabulary and four are explicit synthetic `TEST_*_DO_NOT_LEAK` markers in the PostgreSQL callback fixture. Review found no credential values.

## Remaining validation and acceptance gaps

Remaining limits: provider 403/quota and exhausted-pagination cases, content-download/file-cleanup behavior, and exhaustive capture across every logger/error/database column remain untested or unimplemented. Quarantine is intentionally unsupported and returns HTTP 501. Content retrieval is not implemented; only metadata reaches the existing `scan()` pipeline. No live Google validation was performed. The repository has no frontend connector UI; no frontend checks were applicable.
