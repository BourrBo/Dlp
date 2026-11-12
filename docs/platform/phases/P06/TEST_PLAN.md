# P06 test plan

## Unit and route tests

- Verify exact-only suppression keys, including path, detector identifier, fingerprint,
  and rejection of unsupported/raw evidence keys.
- Verify stable leaf-level policy diffs omit identity/version metadata.
- Verify sandbox results do not reveal sample content or create versions.
- Exercise policy create, update, version listing, diff, rollback, and versioned disable.
- Exercise exception/suppression create, list, revoke, role checks, and tenant isolation
  through an API key.
- Advance a fake clock during suppression and confirm the exception evaluator receives
  the original scan-start instant.

## PostgreSQL

- Upgrade migration 0006; confirm all three tables have forced RLS.
- Verify tenant A cannot read tenant B records, update/delete them, or forge an insert
  with tenant B's member/policy IDs.
- Verify analyst writes are blocked, absent tenant context sees no rows, and local
  role/claims do not leak across transactions.
- Verify policy version UPDATE and DELETE fail at the database trigger.
- Verify exception expiry just before and exactly at the boundary.
- Downgrade to 0005 and upgrade back to head.

## Repository validation

Run all P01–P06 tests with `P03_TEST_DATABASE_URL` set and `DATABASE_URL` unset, then
Ruff, mypy, pre-commit/Gitleaks, dependency audit, and inspect the final Git diff for
secrets or out-of-phase files.
