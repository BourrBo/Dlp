# P05 implementation and operating instructions

## Components

- `backend/app/policy/engine.py` evaluates policies without executing policy-authored
  code. It applies tenant filtering again after the repository query.
- `backend/app/policy/matching.py` validates and matches allowlisted conditions and
  destination patterns.
- `backend/app/policy/repository.py` loads enabled policies and destinations with
  tenant predicates. On PostgreSQL it sets `authenticated` role and transaction-local
  tenant claims so RLS independently enforces the same boundary.
- `backend/app/routes/policies.py` and `destinations.py` provide tenant-filtered CRUD.
  Client-supplied `org_id`, policy id, version, creator and timestamps are rejected.
- `database/migrations/versions/0005_policy_engine_core.py` creates the JSONB policy
  table and destination table, constraints, indexes, grants and forced RLS policies.
- The existing P04 pipeline carries decision, reason and version using its existing
  ScanResult fields. The internal structured P05 handoff also carries matched
  conditions and the evaluation trace.

## PostgreSQL setup

The repository includes the P03 test Compose file `compose.p03-test.yaml` and the
ignored local credentials file `.env.p03-test`. Keep that file private and do not copy
credentials into documentation or source control. On this Windows host, Rancher
Desktop 1.23.1 runs Moby with its Docker API on the `default` context. Start it with:

```powershell
& "$env:LOCALAPPDATA\Programs\Rancher Desktop\resources\resources\win32\bin\rdctl.exe" start --container-engine.name=moby --kubernetes.enabled=false --application.start-in-background
docker --context default info
```

Then start the existing PostgreSQL service from `C:\DLP` and wait for its health check:

```powershell
docker --context default compose --env-file .env.p03-test -f compose.p03-test.yaml up -d --wait
```

Load the ignored environment file into the current PowerShell process without printing
any values, then run the PostgreSQL tests and the full suite:

```powershell
$envPath = (Resolve-Path .env.p03-test).Path
foreach ($line in [IO.File]::ReadAllLines($envPath)) {
    if ($line -match '^\s*([^#=\s]+)\s*=\s*(.*)\s*$') {
        $key = $matches[1]
        $value = $matches[2].Trim()
        if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($key, $value, 'Process')
    }
}
.\.venv\Scripts\pytest.exe -q tests\isolation\test_postgres_rls.py tests\isolation\test_postgres_migrations.py
.\.venv\Scripts\pytest.exe -q tests\isolation\test_postgres_p04.py tests\isolation\test_postgres_p05.py
.\.venv\Scripts\pytest.exe -q
```

At P05 completion, the migration test upgraded through 0005, verified forced RLS,
downgraded to 0004 and 0002, then upgraded to 0005 again. P06 extends the test to
downgrade from 0006 to 0005 and re-upgrade. The P03/P04/P05 PostgreSQL tests use direct SQL under
`SET LOCAL ROLE authenticated`; they do not rely on application route filters.

## Current validation record

Validated locally on 2026-10-22 against PostgreSQL **16.15** in container
`dlp-p03-postgres` (`postgres:16.15-bookworm`, healthy). Rancher Desktop 1.23.1 Moby
served Docker Engine 29.5.3 on the `default` context. The local `auth.jwt()` bootstrap
function was present. This validates the local PostgreSQL compatibility setup only;
hosted Supabase was not tested.

- P03 RLS and migration tests: **3 passed**. These exercised tenant-only reads,
  cross-tenant read/update/delete rejection, API-key isolation, missing tenant context,
  transaction-local claims/role behavior, and downgrade/upgrade.
- P04 PostgreSQL integration: **1 passed**.
- P05 PostgreSQL policy/destination RLS: **1 passed**, covering forced RLS, tenant
  reads, blocked cross-tenant writes, missing context, role-restricted writes and
  transaction-local claims.
- Full P01–P05 suite: **160 passed, 0 skipped**.
- Migration path: upgraded through `0005_policy_engine_core`, downgraded to
  `0004_scan_idempotency` and `0002_api_keys`, then upgraded back to 0005.
- Ruff: **passed**. mypy: **passed** (42 source files).
- `pre-commit run --all-files`: **passed**, including Gitleaks, merge conflict,
  end-of-file and trailing-whitespace hooks.
- `pip-audit -r requirements.txt -r requirements-dev.txt`: **passed**, no known
  vulnerabilities reported.
- `.env.p03-test` remains ignored. Manual review found no new secrets, policy-authored
  Python execution, or scan-content logging in P05. PostgreSQL tests confirmed both P05
  tables have RLS enabled and forced, with tenant grants and the `auth.jwt()` function
  available.

No hosted Supabase test or external production database validation is claimed.

## Authorization

Policy/destination GET operations require `identity:read`. POST/PUT/DELETE require
`api_keys:write` and Owner/Admin. This intentionally reuses the frozen P02 scope
vocabulary; no P02 scope is added in P05. Requests are always scoped to the verified
Principal organization.

## Privacy and failure behavior

Conditions contain metadata only. The evaluator computes volume from the ephemeral
SecretStr in memory and does not persist it. Reasons and traces contain policy IDs,
action names, priority and condition names, not condition values or scan content. A
repository or validation failure raises a policy evaluation error and flows into
P04's fail-closed failure path.

Evaluation is capped at 1000 enabled policies and 1000 destinations per tenant. Lists
inside one condition accept at most 100 values. The routes reject creates beyond the
tenant-wide policy/destination bounds; corrupted or externally inserted oversized
sets fail closed. These bounds are [REC] because the source asks for bounded evaluation
but does not specify numeric limits.
