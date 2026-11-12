# P15 test plan

## PostgreSQL and API security

`tests/isolation/test_postgres_p15_public_api.py` uses `P03_TEST_DATABASE_URL` and real PostgreSQL. It checks API-key auth, missing/invalid/revoked key behavior, insufficient scopes, tenant A and tenant B policies, ignored forged `org_id`, cross-tenant resource concealment, authenticated-role RLS and missing-tenant RLS. The webhook case writes synthetic secrets through P09 `SecretVault`, inspects ciphertext/audit metadata, and verifies raw-body HMAC, constant-time comparison path, freshness, format/version, wrong/missing secret, changed body/timestamp, replay, empty/Unicode/newline body, and size limit.

## Local API tests

`tests/auth/test_public_v1.py` uses the established P02 auth fixture to cover JWT rejection, required API-key scopes, stable error envelope/request ID, bounded pagination/filter validation, tenant-scoped response schema, OpenAPI security/headers/errors, rate-limit 429 and fixed-window reset. `tests/public_api/test_errors.py` checks exception redaction and bounded replay-cache behavior. Existing P02 tests continue to cover API-key hashing and revocation.

## Commands

```powershell
$values = @{}
foreach ($line in Get-Content .env.p03-test) {
  if ($line -match '^\s*([^#=\s]+)\s*=\s*(.*)$') {
    $values[$matches[1]] = $matches[2].Trim('"').Trim("'")
  }
}
$env:P03_TEST_DATABASE_URL = $values['P03_TEST_DATABASE_URL']
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
python -m pytest -q tests/auth/test_public_v1.py tests/public_api tests/isolation/test_postgres_p15_public_api.py
```

No P15 migration was added, so migration-specific upgrade/downgrade checks are not applicable. Full regression and quality checks are recorded at acceptance time; no skipped tests are accepted.

## Known limits

The replay-store unit is verified as a process-local bounded in-memory store. A shared atomic multi-worker implementation is future work. The public API has no write operations, so idempotency behavior is not applicable. The initial tests do not establish multi-process shared replay or real network delivery behavior.

## Acceptance run (2026-10-23)

- Focused P15 run: 7 passed, zero failures/skips.
- Full backend suite: 300 passed, zero failures/skips, with 21 dependency deprecation warnings.
- Ruff check, mypy (89 source files), pre-commit secret scan, pip-audit and diff check passed. `ruff format --check .` reports 12 historical files outside P15. Standalone Gitleaks is unavailable.
- Frontend lint, typecheck, build and 16 tests passed; P15 changed no frontend files.
- P14 checkpoint/tag remained `5b52e153327e33a4098f7bab677999f3405dc7cd` / `p2-p14-complete` before final P15 commit.
