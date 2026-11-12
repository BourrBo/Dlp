# Authentication and roles (P02)

## Authentication

Protected routes require `Authorization: Bearer <token>`. JWTs are validated by
`backend/app/auth/jwt.py` using either exactly one configured verifier source:

- `SUPABASE_JWT_SECRET` for HS256, or
- `SUPABASE_JWKS_URL` for RS256/ES256 public keys.

The algorithm is selected from a fixed allowlist and is never accepted from an
unverified token header. `exp`, `sub`, and `aud` are required; audience defaults to
`authenticated`. `JWT_ISSUER` is checked when set and defaults to
`<SUPABASE_URL>/auth/v1`. `JWT_LEEWAY_SECONDS` defaults to 30 seconds and is capped at
120 seconds. There is no unsigned-token or development bypass.

After signature validation, the subject is resolved against `members`. The role comes
from that row, not a token role claim. If the signed JWT includes `org_id` or
`organization_id`, the member must match that organization. If it does not, the subject
must have exactly one membership; ambiguous multi-organization identities are rejected.
No request body or query parameter selects the authenticated organization. JWTs without
provider credentials configured are rejected.

API keys use `dlp_<12-hex-prefix>.<random-secret>`. The full token is generated with
`secrets`, hashed using SHA-256 before storage, and returned only in the create response.
The visible prefix selects the row; `hmac.compare_digest` checks the stored hash. A
successful authentication updates `last_used_at`. Revoked or malformed keys return a
generic 401. The database stores only the hash, never the secret.

## Roles and permissions

The source names the roles but does not specify the permission matrix. This matrix is a
recommended P02 implementation choice [REC], centralized in
`backend/app/auth/roles.py`:

| Role | Identity read | API key read | API key write | Scan request |
|---|---:|---:|---:|
| Owner | Yes | Yes | Yes | Yes |
| Admin | Yes | Yes | Yes | Yes |
| Analyst | Yes | No | No | Yes |
| Viewer | Yes | No | No | No |
| Auditor | Yes | No | No | No |

Role permissions and API-key scopes are both required. Denials return a generic 403.
API-key requests can only select from the closed `identity:read`, `api_keys:read`,
`api_keys:write`, and `scan:request` vocabulary, and requested scopes must be allowed for the creator's
role and be a subset of the caller's own scopes. `org_id`, creator identity, prefix, and
hash are server-controlled. The one-time secret response is marked `Cache-Control:
no-store`.

`POST /scan` uses the shared Principal and requires the `scan:request` permission and
scope. It currently returns a deterministic P03 stub result without scanning content.

## Routes

- `GET /auth/me` returns the resolved `Principal` when `identity:read` is granted.
- `POST /api-keys` creates a key. It accepts `name` and an explicit list of scopes. The
  response contains the plaintext key exactly once.
- `GET /api-keys` returns metadata for the authenticated organization's keys.
- `DELETE /api-keys/{key_id}` revokes a key. Revoke is idempotently rejected after
  revocation; a key outside the caller's organization returns a generic 403 as required
  by the source plan. An unknown ID returns 404.
- P10 adds `audit:read` to the scope vocabulary. Owner, Admin, and Auditor roles may
  query their tenant's audit events. Client API keys must be explicitly issued this
  scope to read `/audit/events`; the event actor records the safe API-key row ID.
- P09 extends the permission vocabulary with `vault:metadata:read`, `vault:write`,
  `vault:delete`, and `vault:use`. Owner has all four; Admin has metadata, write, and
  delete but not plaintext use. Analyst, Viewer, and Auditor have none. API-key
  creators must explicitly grant a vault scope; a key without `vault:use` cannot
  retrieve plaintext through the internal vault interface.
- `POST /vault/secrets`, `GET /vault/secrets`, `GET /vault/secrets/{secret_id}`,
  `PUT /vault/secrets/{secret_id}`, and `DELETE /vault/secrets/{secret_id}` manage
  encrypted tenant-owned secrets. HTTP responses contain metadata only; plaintext is
  available only to authorized backend workflows through `SecretVault.get`.
- `GET /audit/events` returns immutable, tenant-filtered audit records for permitted
  principals. It supports event, actor, resource, outcome, time, and correlation
  filters with bounded pagination. There are no audit write or delete routes.

All four routes require an authenticated Principal. There are no user or organization
selectors in request models. Extra fields such as a client-provided `org_id` fail schema
validation and cannot override the Principal.

## Database and operational boundaries

Migration `0002_api_keys` adds `dlp_api_keys`, a unique prefix index, an organization
index, and foreign keys to `organizations` and `members`. Application queries always
filter by the Principal's organization. RLS, database tenant isolation, rate limiting,
key expiry, key rotation UI, SSO, and API-key administration UI are out of P02 scope.

Configure one JWT verifier source in the runtime environment. `.env.example` contains
placeholders only. Do not log bearer tokens, plaintext API keys, or hashes. For local
synthetic tests, the signing key is created in test code only and is never production
configuration.

## P03 handoff

P03 uses `Principal`, JWT authentication, API-key authentication, role permissions, and
scopes; adds PostgreSQL/Supabase RLS, database tenant isolation, rate limits, and the
`scan()` stub. The scan scope is a P03 extension to the closed P02 permission vocabulary.

## Unresolved decisions

- The source does not define a role-to-permission matrix or a scope catalog. The matrix
  above and the three scope strings are [REC] pending product-owner confirmation.
- Key expiry is NOT SPECIFIED IN SOURCE; P02 keys do not expire automatically.
- Real Supabase project configuration and provider-issued JWT integration were not
  available in this local environment; validation uses synthetic signed tokens and a
  mocked JWKS client.
