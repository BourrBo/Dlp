# P15 security notes

## Public API

- Uses the P02 key parser, SHA-256-at-rest comparison, active member check, revocation state and verified organization context.
- Only service/API-key Principals with existing `identity:read` scope can call v1. JWT sessions and keys without the scope are rejected.
- The organization is taken from the key row; clients cannot override it. Policy reads also execute under the established PostgreSQL `authenticated` role and tenant JWT claim. Unknown or foreign policy IDs return the same not-found envelope.
- Responses use explicit projections and bounded pagination/filtering. No conditions, secrets, session material, audit rows or admin-only resources are returned.
- Public errors suppress validation details and internal exception strings. The existing middleware request ID is returned in a header and in error envelopes.
- The existing P03 limiter is used per key and tenant. In-memory mode is single-process; Valkey mode is the shared alternative. Retry time is returned only from the limiter's fixed-window result.

## Webhooks and Vault

- HMAC-SHA256 signs `timestamp + b'.' + raw_body`; HMAC comparison uses `compare_digest`.
- `v1` is explicit in the header format. Verification enforces a bounded freshness window, 1 MiB body limit, MAC validity, and one-time replay claim.
- Only a tenant-owned P09 Vault `generic_secret` reference can be used. The signer receives a short-lived `SecretStr` from Vault and never returns it. P09 encryption and P10 audit remain authoritative.
- Missing/foreign Vault references return the same `invalid_signature` result as an incorrect MAC, avoiding disclosure of secret ownership.
- Replay store capacity is bounded and fails closed when full. The included in-memory implementation only prevents replay within one process; multi-process consumers must inject an atomic shared store.
- P15 has no delivery receiver endpoint, subscription lifecycle, dual-secret rotation, or delivery retry queue. Verification failure codes are safe and omit expected MACs and secret details.

## Audit and limitations

Public GET requests are not individually audited. Vault writes/rotation continue through existing P09/P10 audit paths; P15 does not record keys, signatures, bodies or secret values. There is no migration or new persistent tenant table. Public API writes and idempotency are intentionally absent. P16 must preserve the key-derived tenant boundary and use the signer/Vault interface without implementing P4 subscriptions in P15.

## Deployment requirements

The in-memory P03 rate limiter is process-local and is suitable only for local or
single-process use. Production requires the Valkey-backed limiter configured by the
application; multiple workers must share that store to enforce one tenant/key window.
Likewise, `InMemoryReplayStore` only prevents duplicate webhook verification in one
process. Any multi-worker verifier must inject a shared `ReplayStore` whose
`claim(token, expires_at, now=...)` operation is atomic across workers and retains
claims through the signature freshness window. Until then, deploy those components
with one process. These caches are bounded and fail closed when full; they are not
durable delivery queues or exactly-once processing guarantees.
