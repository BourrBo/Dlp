# P03 test plan and results

## Local PostgreSQL setup

The repository provides `compose.p03-test.yaml`, pinned to `postgres:16.15-bookworm`, and `database/test_support/supabase_auth_bootstrap.sql`. The bootstrap creates a NOLOGIN `authenticated` role and an `auth.jwt()` compatibility function that reads `request.jwt.claims`, matching the Supabase claim source used by the migration. PostgreSQL itself executes and enforces every RLS policy. It also grants the role table privileges so tests prove row policies, rather than stopping at SQL privilege errors.

Create an ignored `.env.p03-test` with `P03_PG_PASSWORD=<random password>` and `P03_TEST_DATABASE_URL=postgresql+psycopg://postgres:<same password>@127.0.0.1:55432/dlp_p03_test`. Start and wait for the health check:

```powershell
docker --context default compose --env-file .env.p03-test -f compose.p03-test.yaml up -d --wait
```

Load the test URL into the current PowerShell process and apply the actual project migrations:

```powershell
Get-Content .env.p03-test | ForEach-Object { $parts = $_.Split('=', 2); Set-Item "Env:$($parts[0])" $parts[1] }
$env:DATABASE_URL = $env:P03_TEST_DATABASE_URL
alembic upgrade head
python -m pytest -vv tests/isolation/test_postgres_rls.py tests/isolation/test_postgres_migrations.py
```

The local password file is ignored by Git. The container binds only to localhost and uses its own named volume. The database is dedicated to P03 tests; do not point this suite at production or a shared database.

## PostgreSQL validation performed

Validated on October 21, 2026 using Docker Engine through Rancher Desktop and the healthy `postgres:16.15-bookworm` container. The direct-SQL RLS test set `SET LOCAL ROLE authenticated`, first verified missing claims returned no tenant rows, then set transaction-local claims and verified same-tenant rows only. It checked cross-tenant reads across organizations, members, channels, events, and API keys; zero-row cross-tenant update/delete attempts; persisted state after those attempts; denied event insertion despite table DML grants; and claim/role reset at transaction end. These are direct database queries, with no application authorization filters.

The migration integration test confirmed P03 upgrade to `0003_tenant_rls`, downgrade to `0002_api_keys` (RLS flags and policies removed), and upgrade back to P03 head. Result: 3 PostgreSQL integration tests passed. Application-level `/scan` tests also reject a valid request containing a forged `org_id` (422).

This uses real PostgreSQL RLS and a small test-only implementation of Supabase's `auth.jwt()` accessor; it is not a live Supabase hosted project. Live Supabase grants and provider-issued JWT integration remain outside this local container validation. Valkey server integration was not run; the available tests cover the local limiter and atomic Valkey implementation structure.

## Other checks

Run `pytest -q`, `ruff check .`, `mypy backend/app`, and `pre-commit run --all-files` for the full P01-P03 validation. Do not use SQLite as evidence for RLS. A skipped `tests/isolation` run means unvalidated.

## Final validation result

On October 21, 2026, the complete P01-P03 suite passed with the PostgreSQL test URL configured: **60 passed, 0 skipped**. The dedicated PostgreSQL integration subset passed **3/3**. Ruff, mypy, pre-commit (including the configured Gitleaks hook), and `pip-audit -r requirements.txt -r requirements-dev.txt` passed. `pip-audit` initially found a pytest 8.4.2 advisory; `requirements-dev.txt` now pins the reported fixed pytest 9.0.3, after which the audit reported no known vulnerabilities.
