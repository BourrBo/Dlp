# P06 changelog

- Added migration `0006_exceptions_versions` with immutable policy snapshots,
  tenant-scoped exceptions and suppressions, same-tenant foreign keys, and forced RLS.
- Added versioned policy history, deterministic diff, rollback, and versioned soft
  disable to policy CRUD.
- Added exact-match expiring suppressions and narrow time-limited allow exceptions.
- Added scan-start clock propagation to the existing P04 pipeline.
- Added draft and historical sandbox routes with no production state writes.
- Added safe injectable administrative audit events.
- Added unit, API, migration and real PostgreSQL tests.
