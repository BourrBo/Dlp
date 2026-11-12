# P02 implementation

Added a FastAPI application with protected auth and API-key routes. JWT validation
requires a signature, `exp`, `sub`, and `aud`; permits only HS256 with a configured
shared secret or RS256/ES256 through one configured JWKS URL. Issuer and leeway are
configurable. Membership lookups supply the role and enforce organization context.

Added centralized role permissions and a closed API-key scope list. API-key secrets are
generated with Python's cryptographic random source; the full token is SHA-256 hashed
before insertion. Create returns the secret once; list omits secrets and hashes; revoke
prevents future authentication. Successful API-key authentication updates `last_used_at`.

Migration `0002_api_keys` creates the table and indexes with organization and creator
foreign keys. It does not alter `0001_baseline` and adds no RLS. The HTTP routes do not
accept caller-controlled organization IDs.

The P01 `Principal` contract and seven schemas remain unchanged. Supabase issuer/JWKS
configuration is environment-driven. Integration was tested with deterministic fake
JWTs and a mocked asymmetric JWKS key; no live Supabase account was available.
