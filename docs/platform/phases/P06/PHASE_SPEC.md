# P06 — Exceptions, Suppressions, Policy Versions and Sandbox

## Scope

P06 adds tenant-scoped, time-limited allow exceptions; exact-match finding
suppressions; immutable policy snapshots with deterministic diffs and rollback; and a
side-effect-free policy sandbox. It reuses the P02 Owner/Admin and API-key scope model
and the existing P04 scan contracts.

## Acceptance

- Exceptions have a non-empty allowlisted scope, reason, Owner/Admin approver, and
  timezone-aware expiry. Evaluation uses scan-start time, including when the expiry
  falls during a scan.
- Suppressions expire, match exact path, detector identifier, or HMAC fingerprint, and
  never store raw detected values.
- Policy snapshots cannot be updated or deleted. Existing policies are backfilled on
  migration; every create, update, disable, and rollback creates the next version.
- Version diffs are deterministic and rollback restores a prior configuration as a new
  version.
- Sandbox evaluation has no production state, scan event, or policy mutation side
  effects, and does not expose sample content.
- P06 records are isolated with forced PostgreSQL RLS and tenant-consistent foreign
  keys. Missing tenant context yields no visible rows.
- P01–P06 regression tests, Ruff, mypy, pre-commit, and available dependency/secret
  checks pass before the completion tag is created.

## Exclusions

Approval workflows, notifications, a real detector pipeline, policy-authoring code
execution, and P07+ features are outside this phase.
