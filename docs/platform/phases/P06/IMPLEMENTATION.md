# P06 implementation and local validation

## Data and behavior

Migration `0006_exceptions_versions` creates `dlp_policy_versions`, `dlp_exceptions`,
and `dlp_suppressions`, backfills current P05 policies, installs a mutation-rejecting
trigger for snapshots, and enables forced tenant RLS. Composite foreign keys prevent
cross-tenant policy/member references. Exception scopes use the P05 condition
allowlist and must be non-empty. An active exception changes only its target matching
policy to `allow`; other P05 policies still participate in strictest-action evaluation.

Suppressions match one exact value: `fingerprint` (64 hexadecimal HMAC characters),
`path`, or the P01 detector identifier under `pattern`. Pattern is an identifier, not
a regex or glob. The database stores no detected raw value. Both exception and
suppression expiry use the scan-start timestamp captured by the shared P04 pipeline.

Policy create/update/disable and rollback append immutable snapshots. Diff compares
policy configuration fields in stable order. Rollback copies an earlier snapshot into
the current policy and appends a new version. Draft and historical sandbox evaluation
uses the P05 engine without persisting policies, scan events, or findings. Admin
mutations emit safe identifiers through the replaceable `AdminChangeSink`; the default
implementation logs no policy values, scan data, credentials, or matching values.

P06 routes are:

- `GET/POST /exceptions`, `GET/PUT/DELETE /exceptions/{exception_id}`
- `GET/POST /suppressions`, `GET/PUT/DELETE /suppressions/{suppression_id}`
- `GET /policies/{policy_id}/versions` and `GET /policies/{policy_id}/versions/{version}`
- `GET /policies/{policy_id}/diff?from_version=N&to_version=N`
- `POST /policies/{policy_id}/rollback`
- `POST /policies/test` and `POST /policies/{policy_id}/versions/{version}/test`

Reads require `identity:read`; changes require `api_keys:write` and Owner/Admin. Delete
on a policy is a versioned soft disable; delete on an exception or suppression is a
versioned revocation by disabling it.

## PostgreSQL setup

This project reuses the ignored `.env.p03-test` credentials and pinned PostgreSQL
16.15 Compose service. The Docker daemon is Rancher Desktop Moby on the `default`
context; `desktop-linux` may refer to a stopped Docker Desktop engine.

```powershell
docker --context default info
docker --context default compose --env-file .env.p03-test -f compose.p03-test.yaml up -d --wait
```

Load the ignored connection string into the current PowerShell process without
printing it, then upgrade and run PostgreSQL checks:

```powershell
$line = Get-Content .env.p03-test | Where-Object { $_ -like 'P03_TEST_DATABASE_URL=*' } | Select-Object -First 1
$env:P03_TEST_DATABASE_URL = $line.Substring('P03_TEST_DATABASE_URL='.Length)
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\pytest.exe tests\isolation\test_postgres_rls.py tests\isolation\test_postgres_p04.py tests\isolation\test_postgres_p05.py tests\isolation\test_postgres_p06.py tests\isolation\test_postgres_migrations.py -q
.\.venv\Scripts\pytest.exe -q
```

The migration test verifies an upgrade to P06, forced RLS on each P06 table, downgrade
to P05, and re-upgrade. `P03_TEST_DATABASE_URL` is for PostgreSQL tests. Keep
`DATABASE_URL` unset during the whole test suite because the auth fixture runs Alembic
against isolated SQLite databases; the PostgreSQL migration test sets it locally.

## Validation record

Validated locally on 2026-10-22 against PostgreSQL 16.15 in the healthy
`dlp-p03-postgres` container (`postgres:16.15-bookworm`) through Rancher Desktop Moby
Engine 29.5.3 on the `default` Docker context. The local Supabase `auth.jwt()` bootstrap
function was available. The test validates local PostgreSQL compatibility and does not
claim a hosted Supabase deployment test.

- P01–P06 suite: **166 passed, 0 skipped**.
- P06 PostgreSQL RLS and immutable-version test: **1 passed**. It covers tenant-only
  reads, blocked cross-tenant updates/deletes/inserts, analyst write denial, missing
  tenant context, transaction-local claims, and immutable update/delete triggers.
- P06 PostgreSQL migration upgrade/downgrade/re-upgrade test: **1 passed**.
- Migration backfill test: a pre-existing P05 policy at version 3 was snapshotted at
  version 3 with its name and conditions intact.
- PostgreSQL exception and suppression boundary tests confirm each record is active
  one microsecond before expiry and inactive at the exact expiry instant.
- Ruff and mypy: **passed**.
- Ruff and mypy: **passed**. `pre-commit run --all-files`: **passed**, including
  Gitleaks, merge-conflict, end-of-file, and trailing-whitespace checks.
- `pip-audit -r requirements.txt -r requirements-dev.txt`: **passed**, no known
  vulnerabilities reported.
- Final Git diff review: **passed**. `.env.p03-test` remains ignored; no secrets or
  unrelated/P07 files are included in the phase change.

The ignored `.env.p03-test` file is not part of source control. No P07 or P04+ feature
implementation is included in P06.
