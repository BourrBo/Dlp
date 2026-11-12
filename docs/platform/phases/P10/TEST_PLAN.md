# P10 Test Plan

## Commands

Run the dedicated PostgreSQL service from the repository root (the ignored local
`.env.p03-test` contains its password and test URL; do not commit or print it):

```powershell
docker compose --env-file .env.p03-test -f compose.p03-test.yaml up -d --wait p03-postgres
Get-Content .env.p03-test | ForEach-Object { if ($_ -match '^P03_TEST_DATABASE_URL=(.*)$') { $env:P03_TEST_DATABASE_URL=$Matches[1].Trim('"') } }
.\.venv\Scripts\python.exe -m pytest -q -ra
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check backend tests database/migrations/versions/0009_audit_log.py
.\.venv\Scripts\python.exe -m mypy backend/app
.\.venv\Scripts\python.exe -m pre_commit run --all-files
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt -r requirements-dev.txt
```

The Gitleaks hook runs as part of pre-commit. PostgreSQL-specific audit and migration
coverage can be run directly:

```powershell
python -m pytest tests/isolation/test_postgres_audit.py tests/isolation/test_postgres_migrations.py -q
```

## Coverage

- Unit tests validate the controlled action/outcome contract, sensitive-field
  redaction, credential-shaped values, metadata JSON types/depth/size, and safe
  user-agent handling.
- API tests cover authenticated role and API-key scope checks, tenant filtering,
  filters, ordering, pagination limits, response safety, correlation IDs, and
  authorization-denial events.
- Operation integration tests verify audit events for API keys, policies,
  exceptions, suppressions, approvals/actions, and vault writes. A forced audit
  persistence failure verifies the associated policy mutation rolls back.
- PostgreSQL tests run under `SET LOCAL ROLE authenticated` and verify tenant
  SELECT/INSERT isolation, forged tenant rejection, cross-tenant mutation denial,
  missing tenant context, API-key actor representation, transaction-local context
  reset, append-only privileges/triggers, and hash-chain tamper detection.
- Migration coverage upgrades to `0009_audit_log`, checks RLS/index/trigger schema,
  downgrades to `0008_secret_vault`, and upgrades again.

## Executed acceptance record

Validated on 2026-10-23 against PostgreSQL 16.15, migration head
`0009_audit_log`; `audit_events` reported both RLS and FORCE RLS enabled.

- Full P01–P10 pytest suite: **219 passed, 0 failed, 0 skipped** (two existing
  Python sqlite datetime-adapter deprecation warnings).
- PostgreSQL audit, migration, and vault subset: **3 passed**; the full suite also
  included the P03–P09 PostgreSQL isolation checks.
- Ruff check and format check: **passed**.
- mypy: **passed**, 71 application source files.
- pre-commit: **passed**, including Gitleaks and whitespace/merge-conflict hooks.
- pip-audit: **passed**, no known vulnerabilities found.
- Repository search for logging of credentials, authorization headers, request bodies,
  and vault content: **no matches** in backend logging/print patterns.

The test environment’s configured PostgreSQL endpoint remained reachable for these
checks. Docker CLI status is host-specific; if the database is stopped, start it with
the Compose command above and wait for its health check before running pytest.
