# P14 security notes

## Threat model and tenant boundary

The API derives organization scope from the verified `Principal`, never from a caller-supplied organization ID. Lifecycle routes require an interactive user. Retention/hold operations use centralized P02 permissions; only an owner can delete an organization. New tenant tables have PostgreSQL RLS, `FORCE ROW LEVEL SECURITY`, and organization/role predicates. The service performs fixed, server-authored SQL after principal verification and resets the transaction role to the backend database role for privileged bounded cleanup; database credentials must remain private to the service.

## Holds, deletion and races

The organization advisory transaction lock serializes hold create/release, retention deletion, deletion confirmation and each deletion batch. Each retention batch checks active category/global holds after obtaining the lock. Deletion checks holds at confirmation and before every batch/finalization. No hold bypass exists. Deletion is restartable and bounded; the current tenant membership/session are retained until finalization. The organization is anonymized, not dropped, because immutable hash-chained audit rows reference it.

## Export and IDOR

Own export is available only to an interactive principal; another subject requires owner/admin permission and a membership lookup constrained to the current organization. The public API accepts no organization ID. Output is bounded, uses explicit safe projections and omits bearer/session tokens, hashes, API key/SCIM secrets, vault ciphertext/plaintext, private keys, hold reasons and unrelated tenants. Only export metadata is audited.

## Vault and limitations

Vault rows are removed as ciphertext without decryption. Key destruction/cryptographic erasure is not implemented or claimed. P1/P4 storage is absent in this repository; future adapters must be trusted, idempotent and tenant scoped. There is no global subject export across organizations, subject-level hold, background scheduler, or external-store integration in P14. Database admin credentials can bypass RLS by design; never expose them to clients.

## Validation status (2026-10-23)

The configured PostgreSQL URL connected to database `dlp_p03_test`, reporting PostgreSQL 16.15. Docker CLI could not reach the configured Docker Desktop Linux engine, so container status is unverified. P14 acceptance/RLS/migration tests passed (14 passed, zero skips); the complete backend suite passed (293 passed, zero failures or skips). Real PostgreSQL coverage includes concurrency races, multi-tenant deletion cleanup, bounded export redaction and failure auditing. Ruff lint, mypy, pre-commit secret scan, pip-audit, diff check and frontend checks passed; the repository-wide format check reports 12 historical out-of-scope files and standalone Gitleaks is unavailable.

The owner explicitly accepts as non-blocking exceptions that some HTTP lifecycle status/denial and P14 audit success/failure cases are not independently tested, standalone Gitleaks is unavailable, and the 12 Ruff format findings are pre-existing and outside P14. These untested cases are not claimed as passing. P14 status is **COMPLETE — OWNER-ACCEPTED EXCEPTIONS**. No P15 functionality was started.
