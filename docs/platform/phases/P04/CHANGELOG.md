# P04 changelog

- Replaced the deterministic P03 stub implementation with a modular shared scan pipeline.
- Added detector/classification/policy/enforcement, finding, audit, and alert handoff
  interfaces with deterministic fakes.
- Added authenticated `/gate/check` with a SARIF-shaped pass/fail response.
- Added tenant-scoped idempotency, existing event recording, stable safe errors, input-size
  limits, and production fail-closed adapter configuration.
- Added PostgreSQL migration `0004_scan_idempotency`, migration/RLS tests, pipeline/gate
  tests, and phase documentation.
