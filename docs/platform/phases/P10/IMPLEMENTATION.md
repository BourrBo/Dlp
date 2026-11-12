# P10 Audit Log

## Contract boundary

P01's `Event` contract and `events` table are scan-decision records: they require a
scan ID, channel, decision, reason, and finding count. Those fields do not represent
policy administration, access changes, approvals, or vault lifecycle activity.
P10 therefore adds the separate `AuditEvent` contract and `audit_events` table
without changing the P01 scan contract or overloading scan-decision semantics.
Both are durable event records, with distinct purposes and schemas.

## Persistence and integrity

Migration `0009_audit_log` creates tenant-owned append-only audit events with actor,
authentication method, role, action, resource, outcome, occurrence time, correlation
ID, source IP, user-agent, bounded metadata, tenant sequence number, predecessor hash,
and row hash. Foreign keys restrict organization deletion while evidence exists.
Indexes support tenant/time, action, actor, resource, and correlation queries.

`AuditService.record_event` derives the tenant and actor from `Principal`; callers
cannot submit a tenant ID. It inserts into the caller's database transaction. A
per-tenant PostgreSQL advisory transaction lock serializes sequence allocation. Each
SHA-256 hash covers the canonical event payload, sequence, and prior hash. The service
provides `verify_chain` for integrity checks. A database trigger rejects row updates
and deletes, while the `authenticated` role receives only SELECT and INSERT grants.

## Event taxonomy and integrations

P10 records actual security-sensitive operations implemented in P01–P09:

- API-key creation and revocation.
- Policy create, update, disable, and rollback; destination create, update, and delete.
- Exception and suppression create, update, and revoke.
- Approval request, decision, cancellation, and attempted action execution.
- Secret create, replace, disable, and rotation. No secret value or ciphertext is
  included.
- Authenticated authorization denials. Authentication failures without a verified
  tenant principal are not written to a tenant log.

Audit rows are written in the same transaction as database-backed changes. Failed
audit writes abort those operations and return a generic unavailable response. A
denied authorization event is written separately after the denied request, because
the rejected business transaction cannot commit it. External action execution cannot
participate in the database transaction; P07 reports a sanitized failure if the final
audit write fails, but an external provider may already have acted.

## Metadata, actors, and correlation

Only a small allowlist of metadata fields is persisted (`scopes`, stable resource or
action IDs, action result/type, and key/version information). Unknown fields are
redacted. Sensitive key names and common credential formats are redacted before
serialization. Metadata is JSON-only, depth-bounded, and limited to 4 KiB. Arbitrary
request bodies and decision justifications are not copied into the log.

Actor IDs use the internal member ID when the authenticated subject resolves to a
member, or the safe API-key record ID for API-key requests. Service-only identities
fall back to their existing stable principal subject ID. Plaintext API keys and tokens
are never recorded. Request middleware creates
a server-generated UUID correlation ID and returns it in `X-Request-ID`. The trusted
ASGI peer address is captured only when it parses as an IP address; forwarding headers
are ignored. User-agent values are length-limited and credential-pattern filtered.

## Query API and authorization

`GET /audit/events` is read-only and tenant-filtered. It supports action, actor,
resource type/ID, outcome, correlation ID, time range, and bounded offset pagination.
Results sort by occurrence time and event ID in descending order. Owner, Admin, and
Auditor roles can read audit events; API-key callers also need `audit:read`. No update
or delete HTTP endpoints exist.

## RLS and P11 handoff

`audit_events` uses enabled and forced PostgreSQL RLS with tenant claim-based SELECT
and INSERT policies. No authenticated UPDATE or DELETE privileges or policies exist.
P11 can record future SSO events by calling `AuditService` with the established
principal, correlation, resource, outcome, and safe-metadata fields. P10 adds no SSO
event instances or identity-provider flows.
