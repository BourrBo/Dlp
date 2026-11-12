# P13 — Test plan and acceptance evidence

## Automated coverage

- `tests/auth/test_p13_identity_routes.py`: profile privacy, session establishment,
  list/revoke/current logout, API-key separation, membership-based organization
  switching, live role resolution, allowlist lifecycle, and SSO/SCIM identity
  interoperability.
- `tests/identity/test_network.py`: IPv4/IPv6/CIDR matching, trusted proxy chain
  handling, spoofed forwarded headers, malformed inputs, and fail-closed proxy
  configuration.
- `tests/isolation/test_postgres_p13.py`: real PostgreSQL RLS for tenant sessions,
  session updates, allowlist entries, self-membership discovery, and no tenant context.
- `tests/isolation/test_postgres_migrations.py`: migration head, RLS flags, downgrade
  from P13 to P12, and re-upgrade to P13.
- Existing P01–P12 suites remain part of full regression.
- Frontend tests cover profile privacy, session revocation, org role switching, and
  permission-aware IP allowlist UI.

## Required local commands

Run from the repository root after starting the PostgreSQL Compose service and loading
`P03_TEST_DATABASE_URL` from the ignored `.env.p03-test`:

```powershell
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
.\.venv\Scripts\pytest.exe -q tests/isolation/test_postgres_p13.py
.\.venv\Scripts\pytest.exe -q tests/isolation/test_postgres_migrations.py
.\.venv\Scripts\pytest.exe -q
.\.venv\Scripts\ruff.exe check backend tests database
.\.venv\Scripts\mypy.exe backend\app
```

Also run `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` in
`frontend`. Run pre-commit and available dependency and secret scans before release.

## Recorded validation

Validated on the local Windows development environment with the project-local
PostgreSQL 16.15 container (`healthy`) and Alembic at `0012_identity_management`
(head):

- PostgreSQL P13 RLS test: passed; migration test: passed, including P13 upgrade,
  downgrade to P12, and re-upgrade.
- Full backend/P01–P13 regression with `P03_TEST_DATABASE_URL` configured:
  **277 passed, zero skipped** (21 dependency/runtime deprecation warnings).
- Ruff: passed. mypy: passed (81 source files). pre-commit: all configured hooks passed,
  including Gitleaks.
- Frontend ESLint, TypeScript typecheck, Vitest (**15 tests**), and production build:
  passed.
- `pip-audit -r requirements.txt`: no known vulnerabilities. `npm audit --omit=dev`:
  zero vulnerabilities.
- `git diff --check`: passed. `.env.p03-test` is ignored and was not committed.

SQLite tests are included for application behavior but are not evidence for PostgreSQL
RLS behavior.
