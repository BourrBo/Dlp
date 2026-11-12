# Security remediation review

**Scope:** P2 repository controls and runtime boundaries.
**State:** implemented and locally validated; not a production-readiness certification.

## Findings and disposition

| Area | Change and evidence | Remaining boundary |
| --- | --- | --- |
| Secret scanning | CI scans repository history with pinned Gitleaks 8.28.0 and checks that a synthetic canary is rejected. Reviewed historical matches are suppressed only by exact captured-string allowlists; no test paths are excluded. The tracked working tree scan found no unreviewed findings. A canary was detected in an ordinary file and inside a path containing an allowlisted fixture. | CI has not been observed on a remote GitHub runner in this review. Secret scanning cannot certify runtime logs or external systems. |
| Database selection | Startup now requires an explicit supported `APP_ENV` and `DATABASE_URL`. Production and integration-test modes require PostgreSQL; SQLite is allowed only when explicitly selected for development or unit-test. The isolated Alembic URL now takes precedence over an unrelated process URL. | The application still needs deployment-level PostgreSQL and secret-manager configuration. SQLite is not evidence of tenant RLS. |
| Vault key architecture | P09 specifies direct AES-256-GCM with a versioned replaceable key provider. The implementation matches that contract. Its KMS/HSM adapter is an extension point, not an implemented provider. | No per-record envelope DEKs, KMS wrapping, or HSM integration is claimed. Operators must keep key material outside PostgreSQL and use a deployment secret manager. |
| Audit-chain operation | Added tenant-scoped `GET /audit/events/verify-chain`, gated by `audit:read`, bounded at 10,000 events, and read-only. It reports invalid chains and never reports a partial over-limit scan as complete. SQLite verification now treats stored naive timestamps as UTC. | Hash chaining is tamper-evident, not non-repudiation. A tail deletion is undetectable without an external anchor; no scheduled monitor or alert is provided. |
| Contracts v1 | Added `docs/contracts-v1.md` with current fields, enums, owner/consumer boundaries, compatibility rules, and explicit proposed status. | The tag identifies this repository baseline only. It does not claim cross-stream or external approval. |
| OAuth callback | Removed the unusable Bearer-header requirement from the provider redirect. A one-time persisted state binds the authenticated initiator and is consumed atomically; membership and session are rechecked before code exchange. | Provider validation remains fixture/mock based unless real Google credentials and APIs are used. |
| Validation errors | Non-public Pydantic errors retain location, type, and message but omit submitted `input` and context payloads. An HTTP regression test submits a marker and verifies that it is not reflected. | Custom validators must continue to use non-sensitive static messages. |
| Rate limits and webhook replay | P15 docs now state the process-local behavior and the requirement for shared Valkey and atomic shared replay storage across workers. | Multi-process production verification requires those shared services; in-memory stores are not distributed guarantees. |
| Repository hygiene | Added LF policy and archive exclusions, extended cache/build ignores, and added pinned PostgreSQL CI validation. | No bulk line-ending rewrite or artifact removal was performed. |

## Local validation evidence

The validated local run used the dedicated PostgreSQL 16.15 test container and an
explicit `P03_TEST_DATABASE_URL` from the ignored local environment file. CI uses an
ephemeral isolated PostgreSQL service with trust authentication and no committed
database password.

- PostgreSQL isolation and migration suite: 31 passed, 0 skipped.
- Complete repository suite: 373 passed, 0 skipped.
- Ruff: passed.
- mypy: passed (96 source files).
- `ruff format --check`: all remediation-touched Python files are formatted; 12 existing
  files outside this remediation still need formatting and were left untouched.
- pre-commit: passed, including the configured secret hook.
- pip-audit: no known vulnerabilities found for `requirements-dev.txt` and its included runtime requirements.
- Gitleaks 8.28.0 history and tracked-worktree scans: no unreviewed findings.
- Gitleaks synthetic canary: detected as expected.
- `git diff --check`: passed before commit.

The suite emitted dependency deprecation warnings from SQLite datetime adaptation and
the SAML library. They did not fail tests. The local Docker engine was supplied by the
installed Rancher Desktop runtime; no unrelated project files were changed.
