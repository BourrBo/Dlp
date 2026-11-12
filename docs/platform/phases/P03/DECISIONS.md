# P03 decisions

| Decision | Status | Detail |
|---|---|---|
| RLS scope | [SRC]/[REC] | Enable and force RLS on the five P01/P02 tenant tables; match records to verified `org_id`. |
| Claims | [REC] | The backend synthesizes transaction-local Supabase JWT claims only after P02 verification and assumes `authenticated`. |
| API-key DML | [REC] | Only Owner/Admin may list, create, update, or revoke keys for their own tenant. This preserves P02 runtime writes. |
| Scan permission | NOT SPECIFIED IN SOURCE; [REC] | Add `scan:request` to Owner/Admin/Analyst; Viewer/Auditor remain denied. |
| Limits | NOT SPECIFIED IN SOURCE; [REC] | 30 per key and 300 per organization per 60 seconds, all configurable. |
| Limiter backend | [REC] | Valkey 6.2.0 in production; in-memory only in non-production local/test use. |
| Stub result | [REC] | Deterministic ALLOW, empty findings, no raw content use or storage. |

## Unresolved

- [UNV] Live Supabase hosted-project grants and provider-issued JWT integration remain unverified; PostgreSQL 16.15 RLS, grants, and `SET ROLE` behavior passed locally using the test-only `auth.jwt()` compatibility function.
- [UNV] Valkey server concurrency behavior remains unverified in this environment.
- [UNV] The numeric development defaults are recommendations, not source limits.
