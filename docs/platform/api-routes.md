# P2 route table

P01 created no API endpoints. P02 implements its four authentication routes. Other names
remain planning targets; route behavior belongs to the phase listed.

| Phase | Method | Proposed route | Notes |
|---|---|---|---|
| P02 | GET | /auth/me | Authenticated principal |
| P02 | POST | /api-keys | Create key; plaintext shown once |
| P02 | GET | /api-keys | List metadata only |
| P02 | DELETE | /api-keys/{key_id} | Revoke |
| P04 | POST | /scan | Shared synchronous scan entry |
| P04 | POST | /gate/check | Authenticated CI pass/fail result with SARIF-shaped envelope |
| P05 | GET/POST/PUT/DELETE | /policies | Tenant-scoped policy CRUD |
| P05 | GET/POST/PUT/DELETE | /destinations | Tenant-scoped destination classification CRUD |
| P06 | GET/POST/PUT/DELETE | /exceptions | Tenant-scoped expiring allow exceptions |
| P06 | GET/POST/PUT/DELETE | /suppressions | Exact-match expiring finding suppressions |
| P06 | GET | /policies/{id}/versions[/{version}] | Immutable policy history |
| P06 | GET | /policies/{id}/diff | Deterministic version diff |
| P06 | POST | /policies/{id}/rollback | Restore an earlier policy as a new version |
| P06 | POST | /policies/test | Side-effect-free draft sandbox |
| P06 | POST | /policies/{id}/versions/{version}/test | Historical-version sandbox |
| P07 | GET/POST | /approvals | Tenant-scoped action approvals |
| P07 | GET | /actions | Tenant-scoped action state |
| P07 | POST | /approvals/{id}/approve, /reject, /cancel | Authorized approval lifecycle |
| P15 | GET | /api/v1/policies | Versioned API-key-only policy metadata page |
| P15 | GET | /api/v1/policies/{policy_id} | Tenant-scoped policy metadata |
| P16 | GET/POST | /connectors | Tenant-scoped connector metadata; create is interactive owner/admin only |
| P16 | GET | /connectors/{connector_id} | Safe connector status |
| P16 | POST | /connectors/{connector_id}/oauth/start | Start Google OAuth Authorization Code + PKCE |
| P16 | GET | /connectors/oauth/google/callback | State-bound Google callback |
| P16 | POST | /connectors/{connector_id}/sync | Bounded Google Drive change-feed sync (metadata only) |
| P16 | POST | /connectors/{connector_id}/disconnect | Revoke Google refresh token and disconnect |

P3 async job routes and all P4-owned UI, alert, incident, and operations routes are
outside this P2 route table.

P04 gate and scan requests use the authenticated Principal and P03 rate limiter. The
client cannot select a tenant. See [P04 implementation](phases/P04/IMPLEMENTATION.md)
for the failure taxonomy and gate decision recommendation.

P05 policy and destination reads require `identity:read`; writes require the existing
`api_keys:write` scope and Owner/Admin role. The closed P02 API-key scope vocabulary is
unchanged. See [P05 implementation](phases/P05/IMPLEMENTATION.md) for condition and
evaluation semantics.

P06 exception and suppression reads require `identity:read`; writes require the
existing `api_keys:write` scope and Owner/Admin role. Policy versions are immutable;
rollback appends a new version. See [P06 implementation](phases/P06/IMPLEMENTATION.md)
for expiry, isolation, and sandbox behavior.

P07 approval creation requires `scan:request`; decision endpoints require the explicit
`approvals:decide` permission and Owner/Admin role. See
[P07 implementation](phases/P07/IMPLEMENTATION.md) for lifecycle and executor states.

P15 exposes only a stable, read-only policy metadata surface under `/api/v1`. Calls use
existing P02 API keys with `identity:read`; query filters and pagination are bounded.
See [P15 implementation](phases/P15/IMPLEMENTATION.md) for the versioned error,
request-ID, rate-limit, OpenAPI and webhook-signing contracts.
