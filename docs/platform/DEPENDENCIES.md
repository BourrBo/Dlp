# Project dependencies

All Python packages are pinned in requirements.txt and requirements-dev.txt.
License states below are not independently verified for this implementation and remain
[UNV]; verify at release or before commercial distribution.

| Package | Version | Purpose | License status |
|---|---:|---|---|
| Pydantic | 2.12.3 | Contract validation and JSON Schema | MIT, verified from installed package metadata |
| SQLAlchemy | 2.0.44 | Portable database types and migration operations | MIT, verified from installed package metadata |
| Alembic | 1.17.0 | Sole migration system | MIT, verified from installed package metadata |
| psycopg[binary] | 3.2.10 | PostgreSQL driver | [UNV] |
| FastAPI | 0.156.4 | P02 HTTP application and route dependencies | MIT, verified from PyPI project metadata |
| PyJWT[crypto] | 2.15.1 | P02 JWT signature and claims verification; asymmetric key support | MIT, verified from PyPI project metadata |
| cryptography | 50.0.2 | PyJWT asymmetric signature support and P09 AES-256-GCM encryption | Apache-2.0 OR BSD-3-Clause, verified from PyPI project metadata |
| Uvicorn | 0.54.0 | ASGI server for the P02 application | BSD-3-Clause, [VER] PyPI metadata |
| pytest | 9.0.3 | Contract and migration tests | MIT, verified from installed package metadata |
| httpx2 | 2.15.1 | FastAPI/Starlette test client transport | BSD-3-Clause, verified from PyPI project metadata |
| Ruff | 0.14.0 | Linting and import sorting | [UNV] |
| mypy | 1.18.2 | Static type checking | [UNV] |
| pre-commit | 4.3.0 | Local hook runner | [UNV] |
| Gitleaks | 8.28.0 | Local pre-commit and CI secret scan | MIT, [UNV] per supplied phase plan |
| Gitleaks OCI image | v8.28.0, pinned by digest | CI repository scan and synthetic canary | [VER] official GHCR package, checked 2026-10-21 |
| pip-audit | 2.10.1 | Development dependency vulnerability audit | [UNV] |

The CI uses the Gitleaks CLI image rather than the commercial GitHub action. The exact
image digest is recorded in the workflow. Its official usage supports running the
Gitleaks command in Docker; see the upstream project README and package listing.

The general CI workflow provides a pinned PostgreSQL 16.15 service for real RLS,
migration, and integration tests through `P03_TEST_DATABASE_URL`. Local PostgreSQL
tests use `compose.p03-test.yaml` and the ignored `.env.p03-test` file. Set credentials
in that ignored file before starting the database; do not add them to tracked config.

P2 unit-level route tests use isolated SQLite databases. Third-party identity providers
and Google Drive live-provider acceptance are not established by local fixtures.

P02 pins FastAPI and PyJWT directly. Starlette, cryptography, and related packages are
resolved transitively. The real Supabase deployment/provider remains external and is not
included as a software dependency.
