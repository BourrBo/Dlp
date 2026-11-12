# P04 implementation

## Pipeline

`POST /scan` and `POST /gate/check` invoke `app.scan.pipeline.scan`, preserving the P03
`scan(request, principal)` call shape and P01 `ScanRequest`/`ScanResult`/`Finding`
contracts. The pipeline performs the nine source stages in order and normalizes findings
through the existing Pydantic contract. Collector type does not select a separate route
implementation.

The adapter protocols live in `backend/app/scan/interfaces.py`. `FakeExtractor`,
`FakeDetector`, `FakeClassifier`, `FakeScorer`, `FakeFingerprinter`, `FakeSuppressor`,
`FakePolicyEvaluator`, and `FakeEnforcer` are clearly marked development/test doubles.
The default detector returns no findings. The policy fake has no policy rules and returns
ALLOW. `configure_pipeline` is the host handoff for real adapters. In `APP_ENV=production`,
an unconfigured pipeline returns 503 rather than presenting a fake ALLOW as a completed
security decision.

## Gate API

`POST /gate/check` accepts the same validated `ScanRequest` and uses the same authenticated
Principal, `scan:request` permission, tenant context, and P03 rate limiter. The response
contains `status` (`pass`/`fail`), scan and request IDs, decision, and a SARIF 2.1.0-shaped
envelope. Only explicit ALLOW passes [REC]. The endpoint does not export a SARIF file.

## Idempotency and recording

P04 adds migration `0004_scan_idempotency`. The table is keyed by tenant organization and
request ID and stores an SHA-256 input fingerprint plus the completed `ScanResult` JSON.
The fingerprint includes channel, destination, content, and context; it excludes the
request timestamp. Raw content is never stored. The existing `events` row is written with
the result in the same transaction. Replays return the stored logical result and do not
write a second event. A same-key/different-input request returns 409. Database
reservations are held in one transaction through all stages, so concurrent requests
serialize on the unique key and a failed/crashed transaction does not leave a permanent
processing row.

The idempotency table uses forced PostgreSQL RLS and tenant-scoped authenticated SELECT.
Writes are performed by the backend service database connection; the API derives the
organization only from the verified Principal. The migration has upgrade and downgrade
paths. No raw document/content columns were added.

## Failures and privacy

Stable error codes cover oversized input, conflicting/in-progress keys, detector failure,
policy-decision failure, storage failure, unconfigured production pipeline, and
unexpected errors. Client responses omit exception text. Logs contain only stable error
and exception type labels; they never include request bodies, content, credentials, or
stack traces. Detection/policy errors do not silently become ALLOW. Failed runs release
the reservation so the same request can be retried.

## Security boundaries

Both routes retain P02 authentication and role/scope checks and P03 per-key/per-organization
rate limits. Tenant identity is derived from Principal, never request data. PostgreSQL
idempotency reads/writes include organization and request keys; RLS independently limits
authenticated reads. Existing P03 RLS policies and migrations are unchanged.

## Handoff to P05

P05 can replace `PolicyEvaluator` and `Enforcer` through the injected `PipelineStages`.
No policy CRUD, rules, conditions, priority handling, OPA/Rego, masking, or enforcement
engine is implemented here. FindingStore, AlertSink, and AuditSink are handoff interfaces;
P04 does not implement P4-owned findings or alert products.

## Known limitations [UNV]

- Real P1 detection/classification/scoring/fingerprinting and P3 extraction are not
  available in this repository; test doubles demonstrate the handoff only.
- No production adapter registration is supplied by this phase; production requests fail
  with `scan_pipeline_unconfigured` until the host installs adapters.
- PostgreSQL behavior was verified with the local P03 test role/bootstrap, not a hosted
  Supabase deployment.
