# P07 test plan

## Unit and route tests

- Verify mapping of all four source-defined advanced actions and preservation of the
  four P05 actions.
- Verify the default external executor yields `pending_executor` and never success.
- Verify approval expiry boundary, escalation eligibility, and rejection of final-state
  transitions.
- Verify authenticated creation, explicit approver permission, Owner/Admin restriction,
  requester self-approval denial, tenant hiding, forged `org_id` rejection, and
  malformed/blank justification handling.
- Verify approval/rejection, duplicate action creation, and one-time user override
  application through the P04 scan pipeline.
- Verify safe API responses omit scan content and external action success is never
  fabricated.

## PostgreSQL

- Upgrade `0007_advanced_actions_approvals`, confirm both tables have enabled and
  forced RLS, and verify downgrade to `0006_exceptions_versions` and re-upgrade.
- Verify tenant-only reads, blocked cross-tenant updates/deletes/inserts, and no-claim
  isolation for both new tables.
- Exercise P04 scan -> P05 policy -> P06 lifecycle/exception/suppression adapters ->
  P07 action/approval persistence with a real PostgreSQL database.
- Verify action/approval idempotency and that scan content is not persisted.
- Exercise two concurrent approval decisions against the same locked row; exactly one
  decision may become final.

## Regression and security

Run every P01–P07 unit/API and PostgreSQL test with `P03_TEST_DATABASE_URL` configured
and `DATABASE_URL` unset for the SQLite auth fixture. Then run Ruff, mypy, pre-commit
(including Gitleaks), pip-audit, inspect migrations and every changed line, and verify
the final Git diff contains no credentials or out-of-phase work.

## Acceptance run (2026-10-23)

- Real PostgreSQL 16.15 container `dlp-p03-postgres` was healthy on the Rancher
  Desktop `default` Docker context.
- `tests/isolation/test_postgres_p07.py` and
  `tests/isolation/test_postgres_migrations.py`: **2 passed**. This includes the
  P04 scan → P05 policy → P06 lifecycle/exception/suppression → P07 action and
  approval path, a clearly test-only executor, tenant RLS checks, and migration
  downgrade/re-upgrade.
- Full P01–P07 suite: **181 passed, 0 skipped**. Two SQLite datetime-adapter
  deprecation warnings were emitted by SQLAlchemy/Python; there were no failures.
- Ruff checks, mypy (`backend/app`), pre-commit (including Gitleaks), and pip-audit
  passed. Ruff's repository-wide format check identifies three pre-existing,
  untouched P04/P06 files; formatting check passes for P07-touched Python files.
