# P14 test plan

## Commands

The local backend checks use `.\.venv\Scripts\pytest.exe`; frontend uses `npm run lint`, `npm run typecheck`, `npm run build`, and `npm test` from `frontend/`. PostgreSQL migration/RLS checks use `P03_TEST_DATABASE_URL` and the repository's pinned `compose.p03-test.yaml` service. Full regression is `.\.venv\Scripts\pytest.exe -q`.

## Acceptance matrix

- Retention: expired and non-expired rows, active/released/multiple/category-scoped holds, bounded batches, effective time, retry and audit outcomes.
- Holds: owner/admin permission, invalid category/content, tenant isolation, release confirmation, audit redaction, creation/deletion serialization.
- Deletion: exact-name request/confirmation, authorization and IDOR, held-tenant block, staged cursor/retry, sessions/API keys/SCIM/SSO/vault/policy cleanup, immutable audit/tombstone, multi-organization membership preservation.
- Export: own and authorized admin, unauthorized/cross-tenant/nonexistent members, inactive/multi-org cases, bounded stable output, audit, secret/ciphertext exclusion.
- PostgreSQL: direct `SET ROLE authenticated` RLS reads/writes for each P14 table; migration upgrade, downgrade to P13, and re-upgrade.
- UI: retention, hold, deletion and export controls; permission states; exact-name confirmation; success/error/download behavior.

## Results

Validation performed on 2026-10-23 from implementation checkpoint `94d731824e06bb58692bdfce9d300cecd8bf1442` and prior validation checkpoint `e0760085469d98915cda0daac340b0ddf3111400`:

- `P03_TEST_DATABASE_URL` from ignored `.env.p03-test` connected to `dlp_p03_test`; SQL reported PostgreSQL 16.15. Docker CLI could not connect to its configured Docker Desktop Linux engine pipe, so no live container status is claimed.
- Focused P14 PostgreSQL acceptance, RLS and migration command: `pytest -q tests/isolation/test_postgres_p14_acceptance.py tests/isolation/test_postgres_p14_lifecycle.py tests/isolation/test_postgres_migrations.py` — 14 passed, zero failed, zero skipped.
- Migration test used a temporary database on the same server and verified upgrade to P14, downgrade to P13, re-upgrade, and earlier checkpoints without mutating shared audit history.
- Full backend `pytest -q`, with generic `DATABASE_URL` unset: 293 passed, zero failed, zero skipped; 21 dependency deprecation warnings.
- New real-PostgreSQL race coverage exercises retention versus hold creation, deletion versus hold creation, simultaneous retention workers, and retry after injected failures.
- New data checks cover bounded/idempotent tenant retention, multi-org deletion cleanup across actual P2 tables and vault ciphertext, export cap/truncation/size/secret filtering, export failure audit, HTTP IDOR/authorization, and single-org/multi-org membership outcomes.
- Ruff lint, mypy (85 source files), pre-commit (including hardcoded-secret scan), `pip-audit -r requirements.txt`, and `git diff --check` passed. `ruff format --check .` reports 12 historical files outside P14; they were not mass-formatted.
- Frontend lint, typecheck, build and tests passed (16 tests). Standalone Gitleaks is unavailable; pre-commit secret scan passed.

## Owner-accepted non-blocking validation gaps

The project owner explicitly accepts these remaining gaps as non-blocking for the P14 milestone:

1. Some HTTP lifecycle status/denial cases lack independent tests.
2. Some P14 audit success/failure cases and metadata combinations lack independent tests.
3. Standalone Gitleaks is unavailable; the pre-commit hardcoded-secret scan passed.
4. Repository-wide Ruff format check reports 12 pre-existing files outside P14.

These gaps remain untested/unverified; they are not represented as passing checks. The owner accepts them as milestone exceptions. P14 status is **COMPLETE — OWNER-ACCEPTED EXCEPTIONS**. P15 has not been started.
