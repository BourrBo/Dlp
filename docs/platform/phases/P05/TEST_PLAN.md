# P05 test plan and results

## Coverage

- 50+ parameterized engine cases cover all supported channels, condition families,
  invalid data, list and conjunction semantics, action strictness, deterministic ties,
  tenant filtering, wildcard/apex behavior and destination matching.
- CRUD route tests cover policy and destination create/read/update/delete, version
  increments, tenant not-found behavior, client-supplied tenant rejection, role/scope
  enforcement, allowlisted action/condition validation and duplicate destinations.
- Scan integration test verifies a database-loaded policy's decision, reason and
  version flow through the P04 pipeline's unchanged ScanResult contract.
- PostgreSQL-only tests cover 0005 upgrade/downgrade, RLS enabled on both tables,
  cross-tenant reads/updates/deletes/inserts, missing tenant context, role-restricted
  writes, and transaction-local claims.

## Results recorded 2026-10-22

Validated against the healthy local `dlp-p03-postgres` container running PostgreSQL
16.15 through Rancher Desktop 1.23.1 Moby / Docker Engine 29.5.3. The PostgreSQL URL
was loaded from the ignored `.env.p03-test` into the test process without displaying
or committing credentials. The local Supabase-compatible `auth.jwt()` bootstrap was
present; hosted Supabase was not tested.

- `tests/isolation/test_postgres_rls.py` and
  `tests/isolation/test_postgres_migrations.py`: **3 passed**.
- `tests/isolation/test_postgres_p04.py`: **1 passed**.
- `tests/isolation/test_postgres_p05.py`: **1 passed**.
- Full P01–P05 suite with PostgreSQL enabled: **160 passed, 0 skipped**.
- Migration upgrade/downgrade: **passed** through 0005, down to 0004 and 0002, and
  back to 0005. Forced RLS remained enabled on P03 and P05 tenant tables at head.
- Ruff: **passed**. mypy: **passed**.
- `pre-commit run --all-files`: **passed**, including the configured Gitleaks scan.
- `pip-audit -r requirements.txt -r requirements-dev.txt`: **passed**, no known
  vulnerabilities reported.
- `git diff --check`: **passed**. `.env.p03-test` remains ignored; no credentials
  were added to source or documentation.

See [implementation and operating instructions](IMPLEMENTATION.md) for repeatable
local setup and validation commands. These results do not represent hosted Supabase
validation.
