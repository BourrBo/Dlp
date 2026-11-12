# P12 test plan

Set P03_TEST_DATABASE_URL to the isolated P03 PostgreSQL database for RLS and migration tests. Do not use SQLite as evidence of RLS behavior.

## Commands

pytest tests/auth/test_scim_routes.py -q
Set P03_TEST_DATABASE_URL from the ignored .env.p03-test file before running the PostgreSQL checks:
pytest tests/isolation/test_postgres_scim.py tests/isolation/test_postgres_migrations.py -q
pytest
ruff check .
mypy
pre-commit run --all-files
pip-audit -r requirements.txt

Frontend P01–P08 UI regression uses npm run lint, npm run build, and npm test from frontend; P12 does not change the frontend.

## Coverage

- SCIM credentials: owner/admin management, one-time response, hash-only storage, no token/hash in listings or audit, revocation, malformed/absent token, and rate limiting.
- Users: create/link, duplicate constraints, GET/PUT/PATCH, allowed and protected fields, email/username/external ID validation, active=false, soft DELETE, and authentication rejection after deactivation.
- Groups: create/GET/PUT/PATCH/DELETE, filtering, membership add/remove, duplicate/unknown/cross-tenant/deactivated member checks, and no role effect.
- Protocol: SCIM content types, bounded malformed input, Error/ListResponse representations, supported filters, pagination, and unsupported filters.
- PostgreSQL RLS: organization A/B visibility and mutation, missing tenant claims, forged org insert, credential administration isolation, SCIM role and protected member field restrictions, and concurrent username uniqueness.
- Migration: upgrade, P12 downgrade to P11, re-upgrade, existing P01–P11 downgrade/re-upgrade coverage, RLS flags, indexes, constraints, and active state.
- Full regression, Ruff, mypy, pre-commit/Gitleaks, and pip-audit.

## Recorded validation

Validated 2026-10-23 on the project-local PostgreSQL test database with `P03_TEST_DATABASE_URL` set and `DATABASE_URL` unset for the suite:

- `pytest tests/isolation/test_postgres_scim.py tests/isolation/test_postgres_migrations.py -q`: 3 passed. This included real PostgreSQL RLS checks and P12 upgrade, downgrade to P11, and re-upgrade.
- `pytest -q`: 253 passed, no skips or failures. 21 existing dependency deprecation warnings were emitted by SQLite and python3-saml code paths.
- `ruff check .`: passed.
- `mypy backend`: passed (79 source files).
- `pre-commit run --all-files`: passed, including hardcoded-secret scanning.
- `pip-audit -r requirements.txt`: no known vulnerabilities in declared project dependencies.
- A separate audit of the entire local virtual environment reports advisories in its installed `pip` tool; the declared project requirements are clean.
- `git diff --check`: passed. No credentials were added to tracked files; `.env.p03-test` remains ignored.

SQLite auth-route fixtures validate protocol behavior only. PostgreSQL results above are the evidence for RLS and migration acceptance.
