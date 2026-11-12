# P03 changelog

- Added PostgreSQL/Supabase RLS migration `0003_tenant_rls` for all existing tenant tables, with tenant claims tied to the verified P02 Principal.
- Added transaction-local `authenticated` role and JWT claim context to protected requests.
- Added per-key/per-subject and per-organization fixed-window rate limiter, with local development/test and atomic Valkey shared backends.
- Added authenticated `POST /scan` stub and `scan:request` permission/scope.
- Added route, deterministic limiter, migration, and direct-SQL PostgreSQL isolation tests.
- Added a dedicated local PostgreSQL 16.15 compose harness with ignored credentials and a test-only Supabase `auth.jwt()` compatibility function.
- PostgreSQL validation passed: direct tenant isolation, transaction-local context, and migration downgrade/re-upgrade tests all passed on October 21, 2026.
- Updated the dev test dependency to pytest 9.0.3 after pip-audit identified an advisory in 8.4.2.
