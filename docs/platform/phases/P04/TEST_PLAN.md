# P04 test and verification plan

## Automated tests

- `tests/scan/test_pipeline.py`: handoff invocation, finding normalization, shared file/API/
  repository path, repeated request replay, tenant-scoped keys, conflicting reuse,
  detector/policy failure, retry after failure, and content-size limit.
- `tests/auth/test_gate.py`: gate authentication/permission, SARIF-shaped response, and
  safe generic errors.
- Existing P01-P03 tests remain enabled. The PostgreSQL migration check follows the new
  head revision while still verifying the P03 RLS state and downgrade behavior.
- `tests/isolation/test_postgres_p04.py`: real PostgreSQL migration, persisted result,
  same-result replay, one event, tenant key separation, and RLS-visible rows.
- Existing P03 `test_postgres_rls.py` validates the previously established RLS behavior.

## Commands

```powershell
foreach ($entry in Get-Content .env.p03-test) {
  $parts = $entry.Split('=', 2)
  if ($parts.Length -eq 2) { Set-Item -Path "Env:$($parts[0])" -Value $parts[1] }
}
.\.venv\Scripts\pytest.exe -q
.\.venv\Scripts\ruff.exe check backend database tests
.\.venv\Scripts\mypy.exe backend
```

The test URL is `P03_TEST_DATABASE_URL` from the ignored `.env.p03-test`; do not commit
that file. Compose configuration remains `compose.p03-test.yaml` and uses the existing
PostgreSQL 16.15 container.

## Validation result [VER]

Validated October 21, 2026 against the existing healthy PostgreSQL 16.15 container:

- Full P01-P04 pytest suite: **73 passed**, zero skipped.
- PostgreSQL-specific P04, migration, and P03 RLS checks: **4 passed**.
- Ruff: **passed**.
- mypy: **passed** (34 application source files).
- pre-commit: **passed**, including Gitleaks secret scanning and repository hygiene hooks.
- pip-audit: **passed**, no known vulnerabilities found.

The PostgreSQL checks used the local Supabase-compatible `auth.jwt()` test bootstrap.
They validate PostgreSQL RLS and migration behavior, not a hosted Supabase deployment.
