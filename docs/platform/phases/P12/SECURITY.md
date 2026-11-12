# P12 SCIM security

- Dedicated credentials are generated with 256 random bits; only SHA-256 hash and lookup prefix persist. Comparisons use constant-time comparison. Plaintext is returned once on creation and omitted from list, audit, logs, and errors. Revocation sets revoked_at and immediately blocks subsequent requests.
- Privilege boundary: SCIM tokens are not P02 API keys, user JWTs, or SSO tokens. They authorize only /scim/v2. Credential administration remains owner/admin-only through the existing Principal, permissions, and RLS policy.
- Tenant binding: the resolved credential row supplies the organization. The API has no organization path selector; body/query tenant fields are rejected or unused. Every SCIM transaction sets a local tenant claim and app_role=scim before resource access. RLS, composite foreign keys, and org-scoped uniqueness prevent cross-tenant reads and writes.
- Member roles and protected identity: new members are viewers. User payloads reject role, organization, principal, credential, and permission fields. The database insert policy allows only viewer and a trigger blocks SCIM changes to role, member ID, tenant ID, and auth subject. Existing linked-member roles are preserved.
- Deprovisioning: active=false and SCIM DELETE disable authentication without deleting the member, mappings, or audit history. Inactive members are rejected by P02 JWT/API-key resolution.
- Groups: group membership is a same-tenant directory relation over active SCIM users. It has no policy or RBAC effect.
- Input safety: request bodies stream with a 256 KiB cap; field lengths, list sizes, operation counts, content types, pagination, and supported filter grammar are bounded. Filter fields/operators are parsed from a closed allowlist into SQLAlchemy expressions; user text is never interpolated as SQL.
- Rate limits: the existing P03 limiter applies both credential and tenant limits. Production must use its configured shared Valkey backend.
- Vault: one-way hashes are the correct storage for verifiable bearer tokens; reversible P09 Vault storage would unnecessarily retain a reusable secret.
- Audit: P10 AuditService records only operation markers and stable resource IDs. Token material, hashes, authorization headers, and raw SCIM bodies are excluded.

Known scope limits: no SCIM discovery, bulk, arbitrary filter, or arbitrary PATCH support; groups do not affect authorization; no credential UI is included. Configure a live identity provider and use HTTPS at deployment. PostgreSQL is required for RLS acceptance; SQLite tests cover route contracts only.
