# P09 Test Plan

## Cryptographic checks

- AES-GCM encrypt/decrypt round trip and random nonce uniqueness.
- Ciphertext tampering and associated-data mismatch are rejected.
- Missing key versions and malformed, missing, or wrong-length key settings
  fail closed without returning key material.
- Key version and previous-key configuration are validated.

## PostgreSQL acceptance

Run with the dedicated `P03_TEST_DATABASE_URL` configured and PostgreSQL
healthy:

```powershell
python -m pytest tests/isolation/test_postgres_vault.py tests/isolation/test_postgres_migrations.py -q
```

The PostgreSQL tests exercise forced RLS under `SET LOCAL ROLE authenticated`,
tenant reads, cross-tenant update/delete denial, forged-tenant insert rejection,
missing tenant claims, encrypted persistence, internal authorized retrieval,
role permission denial, key rotation, existence, and soft-disable. The migration
test upgrades to head, downgrades P09, and upgrades again.

## Project regression and static checks

The phase acceptance run must include the full P01–P09 test suite, Ruff,
mypy, pre-commit, Gitleaks, and pip-audit where installed. PostgreSQL-marked
tests must not be reported as skipped in the acceptance run.
