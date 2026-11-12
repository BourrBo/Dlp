# P02 — Authentication, API keys, roles

Source: P2 Final Phase Plan WP1 [SRC]. P02 depends on P01 and hands Principal,
authentication, API keys, roles, permissions, and scopes to P03.

## Included [SRC]

- Verify Supabase JWT signatures, expiration, audience, issuer when configured, and
  small clock skew; reject malformed, forged, expired, unsigned, and unsupported tokens.
- Resolve authenticated callers to the existing `Principal` contract and the P01
  organization membership/role.
- Implement Owner, Admin, Analyst, Viewer, and Auditor role checks and API scopes.
- Create, list, and revoke API keys; store only SHA-256 hashes, show plaintext once,
  record a visible prefix and last-used time.
- Add `GET /auth/me`, `POST /api-keys`, `GET /api-keys`, and
  `DELETE /api-keys/{key_id}`.
- Add `0002_api_keys`; leave P01 contracts and migration unchanged.

## Excluded [SRC]

RLS, rate limits, scan(), SSO, SCIM, sessions, and API Keys UI. P1, P3, and P4 product
features remain out of scope.

## Recommended implementation choices [REC]

- Use FastAPI for the HTTP routes; use PyJWT with HS256 or the configured RS256/ES256
  JWKS verifier.
- Derive roles from `members`, not JWT role claims. Derive organization from a verified
  JWT org claim plus membership check, or the unique database membership when no org
  claim exists.
- Owner and Admin can read/write key metadata. All roles can read their identity.
- Scope vocabulary: `identity:read`, `api_keys:read`, `api_keys:write`.
- A cross-organization key-resource lookup returns a generic 403 as specified by the
  source; invalid or revoked credentials return 401.
- API keys have no expiry field because key expiry is NOT SPECIFIED IN SOURCE.
