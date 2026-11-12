# P2 architecture baseline

## Scope

One repository and one application, built phase by phase. P2 owns the platform,
policy, identity, runtime-protection, and cloud-storage connector capabilities. This
repository now contains P01 contract/persistence foundations, P02 authentication,
authorization, and API-key management, P03 RLS and rate limits, and P04 scan orchestration.
It does not implement P1 detector internals, P3 extraction/OCR, dashboards, or other
P4 features.

## Contract boundaries

The Pydantic v2 contracts live under backend/app/contracts/. Contract schemas are
checked in under contracts/schemas/. ScanRequest.content is an ephemeral SecretStr; it
must not be logged, persisted, or returned. Event and Finding contain metadata, masked
evidence, and references only.

Every contract has extra=forbid and is immutable. Contract version is 1.0.0, status
PROPOSED. No cross-stream sign-off has been requested or claimed.

## P04 scan orchestration

`POST /scan` and `POST /gate/check` call the same `app.scan.pipeline.scan` function.
That pipeline runs extraction, detection, classification, scoring, fingerprinting,
suppression, policy decision, enforcement, and record/handoff stages. Each stage is an
injectable protocol. Current defaults are explicitly named deterministic fakes: the
extractor passes through text, the detector returns no findings, and the policy fake
allows. They are development/test doubles, not security controls. Production mode
rejects scan requests until host-supplied P1/P3/P05-compatible stages are installed with
`configure_pipeline`; errors never become an ALLOW result.

P05 adds the deterministic policy evaluator and tenant-scoped policy and destination
management described in [P05 implementation](phases/P05/IMPLEMENTATION.md). In local
PostgreSQL development, the configured evaluator is injected into the default fake
pipeline for policy contract work. This does not mark the fake P1/P3 stages production
ready; production still rejects scans until the host configures every required stage.

The gate uses the authenticated `Principal`, existing `scan:request` permission, tenant
identity, and P03 rate limiter. It returns pass only for an explicit ALLOW decision; all
other decisions fail. Its response contains a SARIF 2.1.0-shaped result envelope; it does
not generate or download a SARIF file.

Successful results are recorded in the existing `events` table. Migration 0004 adds
`dlp_scan_idempotency`, keyed by `(organization_id, request_id)`, with an input SHA-256
fingerprint and contract-valid result JSON containing masked evidence only. Raw request
content is never stored. The reservation, event insert, and completed result share one
PostgreSQL transaction: concurrent retries wait for the first transaction, and a
failed/crashed transaction rolls back its reservation. Same-input retries return the
stored result; different-input reuse returns a stable 409. The migration forces RLS and
authenticated reads are tenant scoped. Runtime writes use the backend service database
connection and always include the Principal organization in every lookup/update.

The request-size default is 1 MiB of UTF-8 content [REC], configurable with
`SCAN_MAX_CONTENT_BYTES`. No idempotency expiration or retention period is introduced;
retention is NOT SPECIFIED IN SOURCE.

## Persistence

Alembic is the sole migration system. The greenfield baseline creates organizations,
members, channels, and events. The migration is portable across PostgreSQL and SQLite
for local verification. P02 API-key queries are filtered by the authenticated Principal's
organization. There is no RLS in P01/P02; P03 owns it. Events has no request-body or
raw-content column.

Organization-scoped configuration uses organizations.settings_json as the proposed
storage location. Credentials and provider tokens do not belong there.

P05 policy rules and destination classes use dedicated `dlp_policies` and
`dlp_destinations` tables with forced PostgreSQL RLS. Policy condition data is
declarative JSON validated against a closed allowlist; policy content cannot execute
code. Raw scan content is not stored in these tables.

P07 adds tenant-scoped action and approval records with forced PostgreSQL RLS. The
P04 pipeline routes advanced decisions through an idempotent action processor after
P05/P06 evaluation. External actions remain pending until a configured executor
confirms completion. P07 approval APIs are documented in
[the P07 implementation](phases/P07/IMPLEMENTATION.md).

P09 adds a tenant-scoped encrypted secret vault. AES-256-GCM protects values before
they reach PostgreSQL; the external key provider is versioned, and the database
stores ciphertext, nonce, and safe metadata only. Forced RLS and application
permissions both apply. HTTP APIs return metadata only; trusted backend callers use
the internal vault interface for authorized retrieval. See
[the P09 implementation](phases/P09/IMPLEMENTATION.md).

P10 adds a separate append-only audit stream for security accountability. P01's
`Event` remains the scan-decision record because its required scan fields do not fit
administrative and identity actions. `AuditService` writes bounded metadata in the
same transaction as database-backed security changes, and the query route is
tenant-scoped and permission-checked. PostgreSQL applies forced RLS and immutable
guards; per-tenant hashes make later row changes detectable. See
[the P10 implementation](phases/P10/IMPLEMENTATION.md).

## Security foundation

.env files, private keys, local databases, build outputs, and Python caches are ignored.
.env.example contains placeholders only. Gitleaks is configured for pre-commit and a
single-purpose GitHub Actions workflow. The workflow does not establish a general CI
pipeline.

## Identity and auth (P02)

FastAPI routes use a shared Principal dependency. JWTs are validated against one
configured HS256 secret or RS256/ES256 JWKS source. Roles come from the P01 members
table; API-key requests use a closed scope set and a centralized role matrix. API-key
secrets are hashed before persistence and the organization is always taken from the
Principal. See [auth-and-roles.md](auth-and-roles.md).
