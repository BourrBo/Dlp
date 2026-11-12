# P02 test plan

- JWT: valid HS256, asymmetric JWKS validation, missing/malformed/unsigned token,
  expired token, forged signature, invalid audience, invalid issuer, required claims,
  membership resolution, and unsupported algorithms.
- API keys: creation, once-only plaintext response, hash and prefix persistence,
  metadata-only listing, last-used update, invalid/revoked rejection, and revoke.
- Authorization: Owner, Admin, Analyst, Viewer, Auditor; insufficient role and scope;
  unknown scope.
- Tenant context: distinct organizations, list filtering, cross-organization revoke (403),
  wrong-org API-key record, client-supplied org ID, and no organization override.
- Routes: authenticated and unauthenticated `/auth/me`.
- Database: apply `0002_api_keys` after P01, inspect columns/indexes/FKs, then downgrade
  to P01 without removing its tables.

Use only synthetic identities and signing keys. Run pytest, Ruff, mypy, pre-commit,
Gitleaks, and the synthetic secret canary before checkpointing.
