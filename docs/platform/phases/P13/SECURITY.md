# P13 — Security notes

- User sessions are indexed by SHA-256 token digest; raw JWTs are not stored. Session
  revocation is checked on protected requests.
- Effective role and permissions come from the active membership row, not a stale
  client-supplied organization or role. Organization switching requires an active
  membership for the authenticated subject.
- API keys remain distinct service credentials. P13 does not create a browser session
  for them and does not apply the interactive user IP allowlist to them.
- PostgreSQL FORCE RLS policies scope sessions and allowlist rows to the active tenant
  and identity/role. Transaction-local claims are set only after authentication and
  membership resolution.
- The allowlist is disabled by default. Once enabled it must retain at least one CIDR
  entry. CIDRs are validated and canonicalized by IP parsing and the database type.
- Forwarded client addresses are honored only behind explicitly configured trusted
  proxy CIDRs. Arbitrary forwarded headers are ignored. Configure proxy networks
  narrowly and sanitize headers at the edge.
- Audit metadata records lifecycle actions but excludes token material and hashes.
- The P13 test database URL and credentials belong only in ignored local environment
  configuration. Do not commit secrets or test database credentials.
- Known limitation: P13 does not add refresh tokens or an independent idle-session
  timeout. Session lifetime follows the signed JWT expiry and configured clock-skew
  leeway.
