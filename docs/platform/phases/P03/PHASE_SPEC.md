# P03 — Tenant Isolation, RLS, Rate Limits, and `scan()` Stub

## Scope

[SRC] P03 owns database tenant isolation, PostgreSQL/Supabase row-level security, organization-isolation checks, per-API-key and per-organization rate limits, and the `scan()` interface required by the next phase. P03 does not perform scanning.

## Tenant data inventory

The P01/P02 schema contains five tenant-owned tables: `organizations` (tenant root), `members.organization_id`, `channels.organization_id`, `events.organization_id`, and `dlp_api_keys.org_id`. No new tenant table is introduced. RLS policies match each record to the `org_id` claim produced from the verified P02 Principal.

## Acceptance boundary

The database must isolate tenant reads and deny unauthorized writes even when queries omit application filters. The API must authenticate and authorize `/scan`, enforce limits, and return a valid P01 `ScanResult` without detector behavior.

## Out of scope

Real detection/classification, policy evaluation, gate logic, idempotency, findings production, and all P04 UI/response/integration/operations features remain out of scope.
