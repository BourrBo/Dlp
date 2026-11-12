# P11 test plan

## Focused tests

- `tests/auth/test_sso_security.py`: URL scheme/host/port/IP rejection, DNS-to-private rejection, state-cookie signature and binding, OIDC signature/issuer/audience/expiry/nonce/email verification/JWKS rotation and unknown key, protocol configuration validation, strict SAML settings, unsigned response rejection, and SAML size limit.
- `tests/isolation/test_postgres_p11.py`: real PostgreSQL RLS tenant reads, cross-tenant updates/deletes, viewer denial, and missing tenant claim behavior.
- `tests/isolation/test_postgres_migrations.py`: migration head, P11 table RLS/constraints/indexes, downgrade to P10, re-upgrade, and the existing earlier phase downgrade/re-upgrade coverage.
- `frontend/src/App.test.tsx`: SSO token fragment removal and backend validation through `/auth/me`.

## Commands

```powershell
.\.venv\Scripts\pytest.exe tests/auth/test_sso_security.py -q
$env:P03_TEST_DATABASE_URL = (Get-Content .env.p03-test | Where-Object { $_ -match '^P03_TEST_DATABASE_URL=' }).Substring('P03_TEST_DATABASE_URL='.Length)
.\.venv\Scripts\pytest.exe tests/isolation/test_postgres_p11.py tests/isolation/test_postgres_migrations.py -q
.\.venv\Scripts\pytest.exe
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe
.\.venv\Scripts\pre-commit.exe run --all-files
.\.venv\Scripts\pip-audit.exe -r requirements.txt
```

PostgreSQL tests require `P03_TEST_DATABASE_URL` pointing at the isolated P03 test database; they skip when it is absent. Do not use SQLite to claim RLS validation. Frontend checks run from `frontend` with `npm test`, `npm run lint`, and `npm run build`.

## Recorded validation (2026-10-23)

- Focused P11 auth/security tests: **24 passed**.
- Full Python P01–P11 regression: **244 passed, 0 failed, 0 skipped** (rerun after final edits).
- PostgreSQL 16.15 P11 RLS and migration upgrade/downgrade/re-upgrade tests: **2 passed** (rerun after final edits).
- Ruff: **PASS**; mypy strict: **PASS**.
- Frontend ESLint: **PASS**; TypeScript/Vite production build: **PASS**; Vitest: **11 passed**.
- pre-commit hooks, including Gitleaks: **PASS**.
- `pip-audit -r requirements.txt`: **PASS**, no known vulnerabilities.

The full regression and PostgreSQL checks must be rerun after any further source or test edits before release.
