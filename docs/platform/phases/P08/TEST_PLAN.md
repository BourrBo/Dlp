# P08 test plan and results

## Frontend checks

Run from `frontend/`:

```powershell
npm ci
npm run typecheck
npm run lint
npm test -- --reporter=dot
npm run build
npm audit --audit-level=low
```

Validation on 2026-10-23:

- TypeScript: passed.
- ESLint: passed with no warnings.
- Vitest/Testing Library: 10 passed. Covers policy details/create request, required-field
  validation, version history and rollback confirmation, exception expiry/revoke,
  suppression details, synthetic sandbox,
  approval transition and pending executor representation, viewer restrictions/access
  identity, safe 403 handling, and loading/empty state.
- Production build: passed (Vite 6.4.5).
- `npm audit --audit-level=low`: 0 vulnerabilities.

The component tests use a mocked `fetch` boundary. In addition, a live smoke test ran
the Vite `/api` proxy against FastAPI and the existing PostgreSQL test container using
a synthetic owner JWT. `/auth/me`, policy list, create, detail, and version history
worked end to end. The smoke test used a dedicated synthetic organization and policy
in the isolated P03 test database; the policy-version table enforces immutable history,
so the synthetic policy was left disabled and its history retained. No production
database was involved.

The browser was reviewed at 1366×768 and 390×844 using the connected synthetic test
session. Both layouts had no document-level horizontal overflow. Mobile navigation is
intentionally horizontally scrollable. No separate automated accessibility scanner
was run.

## Backend regression and PostgreSQL

The PostgreSQL service is the existing `dlp-p03-postgres` container, from the pinned
project-local `compose.p03-test.yaml` configuration. Its health status was `healthy`.
Credentials come from ignored `.env.p03-test`; keep that file untracked and never copy
its contents into logs or documentation. `P03_TEST_DATABASE_URL` was loaded into the
test process from that file.

Commands and results:

```powershell
python -m pytest tests/isolation/test_postgres_rls.py -q
# 2 passed

python -m pytest -q
# 181 passed, 0 skipped; 2 existing Python sqlite datetime adapter deprecation warnings

python -m ruff check .
# passed

python -m mypy
# Success: no issues found in 61 source files

python -m pre_commit run --all-files
# passed: detect hardcoded secrets, merge conflicts, EOF, and whitespace hooks
```

The regression suite exercised the P01–P07 tests, including the real PostgreSQL RLS,
migration, and phase-isolation tests. No P01–P07 source files were changed.

## Security and diff checks

- `git diff --check`: passed.
- Pre-commit hardcoded-secret scanner: passed.
- The Gitleaks secret-scanning hook in `pre-commit run --all-files` passed; a standalone
  `gitleaks` executable was not installed.
- Source review checked for browser storage, tenant selection, token logging, and
  arbitrary API error-body rendering. The bearer token exists only in component state.
- `npm audit`: no known dependency vulnerabilities at validation time.

Rerun the component checks and the live smoke test after material UI/API integration
changes. The mocked component tests and live browser-to-API smoke test are separate
checks with distinct coverage.
