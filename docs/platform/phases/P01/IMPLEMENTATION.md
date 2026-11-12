# P01 implementation

The repository was empty apart from Git metadata. The DLP source PDFs and P2 final
phase plan are copied into docs/source/ as read-only references. No prior database or
application behavior existed.

P01 creates seven immutable Pydantic v2 models, exports JSON Schema snapshots, creates
a portable Alembic baseline from zero, and adds secret-scan configuration. The baseline
contains no raw-content column and no P03 row-level security. No product route is added.

The selected migration tool is Alembic. Local migration tests use SQLite because the
Docker CLI exists but no Docker server is running. PostgreSQL is the intended runtime
database; PostgreSQL execution remains an environment-level verification item.
