# P03 implementation

## RLS and tenant context

Migration `0003_tenant_rls` enables and forces RLS on organizations, members, channels, events, and API keys. Policies use `auth.jwt() ->> 'org_id'`; absent claims match no rows. The organizations root is visible only to its tenant. Members, channels, and events have tenant-scoped SELECT policies and no `authenticated` write policies. API-key reads are tenant-scoped and restricted to Owner/Admin. API-key insert/update is tenant-scoped and Owner/Admin-only so existing P02 key create/revoke and last-use flows continue. No policy permits event inserts from the authenticated role.

After P02 verifies the provider JWT or API key and resolves the database membership, the backend assumes the Supabase `authenticated` role transaction-locally and sets `request.jwt.claims` to claims synthesized from that verified Principal. No client `org_id` is used. This requires `DATABASE_URL` to authenticate as a Supabase service database role with permission to `SET ROLE authenticated`; application traffic must not connect with an end-user supplied database credential. Claims are transaction-local.

## Rate limits

`RateLimiter` separates the endpoint from its backend. The local in-memory backend is thread-safe but counters are process-local and reset with the process. It is permitted for development/test only. Production configuration rejects it. The shared Valkey backend uses a single Lua script to increment the identity and organization counters atomically. Keys contain SHA-256 identifiers rather than raw user or key IDs.

Numeric limits are NOT SPECIFIED IN SOURCE. [REC] defaults are 30 requests per API key per 60-second fixed window and 300 per organization per window. JWT users use their verified subject as the identity dimension. Configure `RATE_LIMIT_PER_KEY`, `RATE_LIMIT_PER_ORG`, `RATE_LIMIT_WINDOW_SECONDS`, `RATE_LIMIT_BACKEND`, and `VALKEY_URL`. 429 responses include `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining`.

## Scan interface

`POST /scan` requires P02 `Principal` and `scan:request`. Owner/Admin receive all permissions; Analyst receives scan permission; Viewer/Auditor are denied. A new API key must explicitly request `scan:request`. The stub derives a deterministic `scan_id` from the tenant and request ID, returns ALLOW with no findings, and echoes no content. It does not persist, inspect, classify, mask, or score the content. P04 can replace `app.scan.stub.scan(request, principal)` while preserving the P01 contracts.

## Operations and validation

For the repeatable local PostgreSQL harness, use `compose.p03-test.yaml`, the ignored `.env.p03-test`, and `database/test_support/supabase_auth_bootstrap.sql`. The bootstrap creates a test-only authenticated role and `auth.jwt()` claim accessor; policies and RLS behavior run in PostgreSQL itself. Run the P03 isolation and migration integration tests as documented in `docs/phases/P03/TEST_PLAN.md`.

Validated against PostgreSQL 16.15 on October 21, 2026: RLS direct-SQL tests passed for tenant reads, cross-tenant mutations, missing context, event-write denial, and transaction-local context. Migration upgrade, downgrade, and re-upgrade passed. This confirms PostgreSQL policy behavior with the Supabase claim accessor, not a live Supabase project; hosted-project grants and provider JWT integration still need deployment validation.
