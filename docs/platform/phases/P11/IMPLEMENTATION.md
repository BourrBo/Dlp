# P11 — Enterprise SSO implementation

## Architecture

P11 adds organization-scoped OIDC and SAML sign-in while retaining the P02 `Principal`, database member, and role model. Successful authentication creates a 15-minute, HS256 DLP access token signed with `DLP_SSO_TOKEN_SECRET`. P02 principal resolution verifies this token with a separate key and then reloads the member's current role from the database. SSO does not grant roles from provider attributes or groups.

The browser flow puts the short-lived token in the URL fragment, which is not sent in the HTTP request. The frontend removes the fragment immediately, validates the token through `/auth/me`, and keeps it in memory. This temporary token handoff is a P11 bridge; broader sessions belong to P13.

## OIDC

1. An owner/admin creates an OIDC configuration with an issuer, client ID, claimed email domains, scopes, and an existing same-organization P09 vault reference of type `oauth_client_secret`.
2. The backend performs discovery at the issuer's `.well-known/openid-configuration`, verifies the issuer, and validates the authorization, token, and JWKS URLs before storing the endpoints.
3. `GET /auth/sso/{organization_id}/login?protocol=oidc` starts the authorization-code flow with fresh state, nonce, and an S256 PKCE challenge. A five-minute signed, HttpOnly, Secure, `__Host-` cookie binds the browser transaction. Only hashes and transaction metadata are stored in PostgreSQL.
4. `GET /auth/sso/{organization_id}/oidc/callback` consumes the transaction once, exchanges the code using the stored verifier, validates the token signature/algorithm, issuer, audience, expiry, issued-at, nonce, and verified email, then maps the subject.

The supported token endpoint authentication methods are `client_secret_basic` and `client_secret_post`. Provider requests use HTTPS, block non-public DNS addresses and IP literals, reject redirects, disable proxy environment variables, enforce timeouts and response size limits, and use a short JWKS cache with key-rotation refresh.

## SAML

1. An owner/admin creates a SAML configuration with the IdP entity ID, HTTPS SSO URL, claimed email domains, attribute names, and an existing same-organization P09 vault reference containing the trusted IdP X.509 certificate as a generic secret.
2. The SP metadata endpoint is `GET /auth/sso/saml/{organization_id}/metadata`; the ACS is `POST /auth/sso/{organization_id}/saml/acs`.
3. `GET /auth/sso/{organization_id}/login?protocol=saml` creates an SP-initiated AuthnRequest. The request ID is stored with a five-minute transaction and browser-bound RelayState.
4. The OneLogin `python3-saml` toolkit validates the response with strict mode, XML security via `xmlsec`, trusted certificate, issuer, audience, destination, recipient, time conditions, and `InResponseTo`. Assertions must be signed. Assertion IDs are persisted for replay rejection.

Only email, email verification, display name, and external ID attribute mappings are accepted. Email verification is required for first-login mapping; first login is limited to configured domains and creates a viewer. Existing linked members keep their database role. Owners/admins can explicitly link an external subject to an existing same-tenant member.

## Integrations

- **RBAC:** P02 permissions `sso:config:read` and `sso:config:write` gate configuration; the write permission is owner/admin only.
- **RLS:** P03 policies isolate provider and identity tables by `org_id` and require owner/admin for authenticated CRUD. Transaction and replay tables are forced through RLS and reserved for the trusted application database role.
- **Vault:** configuration rows store opaque same-tenant secret/certificate IDs only. The callback worker decrypts secrets through the existing P09 service.
- **Audit:** P10 records provider lifecycle, login started/success/failed, and identity mapping events. Audit metadata contains safe result/operation markers only.

## Database

Alembic revision `0010_sso` adds `members.email`, case-insensitive tenant email uniqueness, the vault composite tenant key, and four tables: `dlp_sso_configs`, `dlp_sso_identities`, `dlp_sso_transactions`, and `dlp_sso_replays`. Tenant composite foreign keys prevent cross-organization config/member/vault references. SSO configuration and identity tables have organization indexes; identity/member and transaction/replay expiry lookups are indexed. Configuration protocol/reference checks and audit action checks are migrated with the schema.

Apply with `alembic upgrade head`. P11 migrations require PostgreSQL with the project's `auth.jwt()` function and RLS support.

## Runtime environment

Set these values in the deployment environment or an ignored local env file:

```text
DLP_SSO_BASE_URL=https://api.example.com
DLP_SSO_FRONTEND_URL=https://console.example.com
DLP_SSO_STATE_SECRET=<random value of at least 32 bytes>
DLP_SSO_TOKEN_SECRET=<separate random value of at least 32 bytes>
DLP_SSO_TOKEN_ISSUER=dlp-sso
DLP_SSO_TOKEN_AUDIENCE=dlp-api
```

Do not reuse the P02 Supabase JWT key for either SSO secret. For local development, loopback HTTP base/frontend URLs are accepted; transaction cookies remain Secure.

## P12 handoff

P12 SCIM can resolve an organization via `organizations.id`, a provider via `dlp_sso_configs.id`, an external identity via `(org_id, config_id, issuer, subject)` in `dlp_sso_identities`, and the local user via `member_id` in the existing `members` table. Reuse these records and roles; do not create another user table. P11 does not implement SCIM or lifecycle deprovisioning.
