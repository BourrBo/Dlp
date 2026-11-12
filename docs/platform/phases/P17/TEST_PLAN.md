# P17 test plan and evidence

## Required acceptance evidence

- Microsoft OAuth authority/PKCE use a tenant GUID and persisted P16 transaction
  handling. Tenant mismatch, callback replay, and tampered state are covered.
- Graph tests cover fixed-host URL validation, delta pagination, separate
  tenant/site/drive/item identifiers, deletion facets, repeated continuation
  rejection, exposure normalization, direct-only action targeting, and
  revocation success, provider failure, and idempotent retry.
- The integrated fixture exercises Graph delta through the HTTP sync route,
  `scan()`, P05 policy evaluation, P07 approval, the Microsoft action executor,
  audit, checkpoint persistence failure, and retry without repeating a
  successful provider delete.
- PostgreSQL tests verify tenant isolation for Microsoft connector/state and
  persistent OAuth rows. Migration validation performs upgrade, downgrade,
  and re-upgrade while checking P17 provider/audit constraints and RLS.
- HTTP tests cover foreign-tenant site-search hiding, tenant GUID validation,
  callback tenant mismatch, callback state replay, and tampered state. Shared
  P16 OAuth tests cover reusable transaction validation cases.

## Executed evidence

Final validation was run from `C:\DLP` on 2026-10-28:

| Command | Result |
| --- | --- |
| `python -m pytest tests/connectors/test_p17_microsoft_graph.py tests/connectors/test_p17_microsoft_routes.py tests/isolation/test_postgres_p17_microsoft.py tests/isolation/test_postgres_migrations.py -q` with `P03_TEST_DATABASE_URL` | 17 passed, 0 failed, 0 skipped |
| `python -m pytest -q` with `P03_TEST_DATABASE_URL` | 389 passed, 0 failed, 0 skipped; 21 dependency deprecation warnings |
| `ruff check .` | Passed |
| `ruff format --check` on all modified Python files | Passed (16 files) |
| `mypy backend/app` | Passed; 99 source files, no issues |
| `pre-commit run --all-files` | Passed, including configured Gitleaks v8.28.0 and hardcoded-secret detection |
| `python -m pip_audit -r requirements.txt -r requirements-dev.txt` | Passed; no known vulnerabilities |
| `git diff --check` | Passed |

All Microsoft OAuth and Graph behavior above is deterministic fixture/mock
validation. **Live Microsoft validation not performed.** No Microsoft tenant,
OAuth credentials, or live Graph API access were used. Gitleaks ran through the
configured pre-commit hook; a separate standalone Gitleaks CLI run was not
performed.

Delivery semantics are at-least-once. If a provider action succeeds but
checkpoint persistence fails, the delta item may be scanned again. P07's
idempotency key and the provider-side already-absent check prevent a repeated
destructive effect in the exercised revoke path. This is not exactly-once
processing.
