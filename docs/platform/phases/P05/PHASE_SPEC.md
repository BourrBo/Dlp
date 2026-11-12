# P05 — Policy Engine Core

## Objective

Provide deterministic policy and destination classification CRUD, evaluate the
specified policy conditions inside the shared P04 scan flow, and persist tenant-scoped
configuration with PostgreSQL RLS.

## Included

- Policy fields: organization, name, enabled, non-negative priority, declarative
  conditions, P05 action, monotonically incremented current version, creator and
  timestamps.
- Destination fields: organization, class (`internal`, `public`, `personal`,
  `partner`), kind (`domain`, `repo`, `email_domain`) and pattern.
- Conditions: channel, destination class, authenticated user group, data type,
  classification, volume and file type.
- Actions: allow, warn, block, log. When multiple enabled policies match, the strictest
  action wins.
- Authenticated tenant filtering in routes and PostgreSQL row-level isolation.
- P04 scan/gate returns the selected policy reason and version through fields already
  present in the P01 ScanResult contract.

## Excluded

P06 exceptions, approval workflows, drafts, snapshots, rollback and policy lifecycle
history; P07 approvals; OPA or another embedded policy language; UI; real scanning or
P1/P3 detector and extraction work; vault, alerts or durable policy audit history.

## Acceptance

See [test plan](TEST_PLAN.md) for the completed local PostgreSQL validation and
[implementation instructions](IMPLEMENTATION.md) for setup. The local PostgreSQL
results do not represent hosted Supabase validation.
