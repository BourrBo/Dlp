# P05 changelog

- Added deterministic P05 policy evaluation for the seven planned condition families
  and four P05 actions, including strictest-action wins and an evaluation trace.
- Added tenant-scoped policy and destination CRUD routes, schema validation and
  owner/admin write authorization.
- Added PostgreSQL revision 0005 with policy/destination storage, indexes, constraints,
  authenticated grants and forced tenant RLS.
- Connected database policy evaluation to the existing P04 policy handoff without
  changing the P01 Policy or ScanResult contracts, and exposed policy reason/version in
  the existing P04 scan/gate results.
- Added P05 engine, route, pipeline integration and PostgreSQL isolation test coverage.
- Fixed PostgreSQL migration assertions to execute `to_regclass()` as a SELECT and
  corrected nested transaction exception ordering in the P05 RLS test so savepoint
  rollback is checked against the real rejected write.
- Validated P03, P04 and P05 PostgreSQL integration tests against local PostgreSQL
  16.15: five passed. Full P01–P05 suite: 160 passed, zero skipped.
- Ruff, mypy, all configured pre-commit hooks (including Gitleaks), and `pip-audit`
  for both requirements files passed. See `TEST_PLAN.md` for the full validation record.
