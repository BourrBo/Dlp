# P04 — Real scan orchestration and gate API

## [SRC] Source scope

P04 replaces the P03 scan stub with one shared `scan()` path and adds `POST /gate/check`.
The pipeline has nine injectable stages: extract, detect, classify, score, fingerprint,
suppress, policy, enforce, and record. Extractor, Detector, Classifier, Scorer,
Fingerprinter, PolicyEvaluator, Enforcer, Recorder, AlertSink, AuditSink, and FindingStore
are interfaces with deterministic fakes where the owning phase is not available.
Idempotency, input size limits, safe structured logging, stable error taxonomy, and a
privacy test are in scope. Existing P01 contracts, P02 auth, and P03 RLS/rate limits stay
unchanged.

The phase acceptance statement is that file, paste, and repository scans use the same
`scan()` implementation. P3 extraction is represented by an interface/fake. Gate output
is pass/fail and SARIF-ready; file export remains outside P04.

## Explicit exclusions [SRC]

No P1 detector/classification/scoring/fingerprinting implementation; no P3 extractor,
OCR, or file-scanning implementation; no P05 policy engine/rules; no P4 findings storage,
incident, alert delivery, UI, SIEM, ticketing, or reports. The included fakes are not
security detectors or policy rules.

## Choices not specified by source

- Idempotency storage is NOT SPECIFIED IN SOURCE. The phase plan recommends a
  Redis-compatible store with TTL, or otherwise a small RLS-protected table [REC]. This
  implementation chooses the table because it can atomically commit the result and the
  existing event without adding Redis/Valkey configuration [REC]. No retention period is
  invented.
- Idempotency key is the existing tenant-scoped `request_id` [REC].
- Gate pass semantics are NOT SPECIFIED IN SOURCE. Only explicit ALLOW passes; WARN,
  LOG, BLOCK, and other actions fail [REC].
- Maximum request content size is NOT SPECIFIED IN SOURCE. Default 1 MiB UTF-8, with
  `SCAN_MAX_CONTENT_BYTES` override [REC].
- Policy failure behavior is NOT SPECIFIED IN SOURCE. P04 fails closed with a stable
  error, never an implicit ALLOW [REC].
