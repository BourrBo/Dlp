# P12 — SCIM provisioning

## Architecture

SCIM 2.0 provisions existing members; it does not authenticate users or create sessions. Each organization can issue dedicated bearer credentials. A credential resolves the tenant, and the server establishes transaction-local PostgreSQL claims before touching SCIM resources. SCIM credentials have no P02 permissions and cannot authenticate to non-SCIM APIs.

P11 dlp_sso_identities represents an OIDC/SAML (issuer, subject) relationship. SCIM externalId, userName, and stable SCIM id have different meanings, so dlp_scim_users stores this source mapping and references the existing member with a composite tenant foreign key. New members receive the viewer role. A matching same-organization email links to the existing member and preserves its current role. SCIM never accepts a role or permission mapping.

members.active controls whether P02 JWT, P11 SSO, or API-key authentication may resolve the member. SCIM active=false and DELETE /Users/{id} deactivate the member; they retain the member, SCIM mapping, external SSO identities, and audit history. Groups are directory records with member links only. They do not grant roles or permissions.

## Credentials

Owners and admins manage credentials with their existing P02 Principal and RBAC:

- POST /api/scim/credentials with {"name": "Workforce IdP"} creates a token and returns it once.
- GET /api/scim/credentials lists name, prefix, lifecycle timestamps, and ID. It omits the token and token hash.
- DELETE /api/scim/credentials/{id} revokes a credential.

The bearer token is generated from 256 random bits. The database stores only SHA-256 of the full token and its 12-hex lookup prefix; comparison uses hmac.compare_digest. The random token is high entropy, so a slow password hash is unnecessary. The credential table's RLS policy allows tenant owner/admin management. A trusted application database connection reads a candidate credential by prefix before tenant claims exist; after verification, all SCIM resource operations run as authenticated with the credential's tenant claims.

## SCIM API

The base path has no organization parameter: the credential establishes the tenant.

| Resource | Operations |
| --- | --- |
| /scim/v2/Users | GET list, POST create |
| /scim/v2/Users/{id} | GET, PUT, PATCH, DELETE (soft deactivation) |
| /scim/v2/Groups | GET list, POST create |
| /scim/v2/Groups/{id} | GET, PUT, PATCH, DELETE |

Success and protocol errors use application/scim+json. Write requests accept application/scim+json and application/json. Error bodies use the SCIM Error schema. Payload size is capped at 256 KiB; email arrays at 8 entries; group membership at 1,000 entries; PATCH operations at 20.

User fields are schemas, id, externalId, userName, displayName, name, active, emails, and meta. Supported name components are validated and normalized to the stored display name. New users default to active unless the IdP sends active=false. externalId and userName are unique per organization; usernames are case-insensitive.

Groups support externalId, displayName, members, and metadata. Membership values must reference active SCIM-managed users in the same organization. Common SCIM PATCH add, replace, and remove operations support user active, displayName, userName, externalId, emails, and group displayName, externalId, and members, including members[value eq "<id>"]. Groups are not used for authorization.

Filtering implements only eq for userName or externalId on Users, and displayName or externalId on Groups. Pagination uses startIndex and count, caps count at 200, and returns ListResponse. The service does not claim full RFC 7644 coverage: discovery resources (ServiceProviderConfig, Schemas, ResourceTypes), arbitrary filter expressions, bulk operations, complex multi-valued attribute filters, and arbitrary PATCH paths are not implemented.

## Authorization, tenant isolation, and audit

Every SCIM resource read/write uses the authenticated database role and the tenant claim resolved from the credential. There is no tenant ID in the route. Unknown or cross-tenant resource IDs return not found; request resource attributes cannot select a tenant. PostgreSQL RLS and composite tenant foreign keys enforce organization boundaries for credentials, users, groups, and group membership. Database constraints prevent duplicate identities under concurrent provisioning. A member trigger prevents SCIM-context updates to member ID, tenant, authentication subject, or role; inserts are limited to viewer.

P10 AuditService records credential create/revoke, user provision/update/deactivation, group lifecycle, and membership changes. Metadata records the operation only; it never includes authorization headers, SCIM payloads, token values, or hashes. Request correlation, source address, and user agent follow the existing P10 sanitization rules. Audit actions remain accepted after downgrade so append-only historical events stay valid.

SCIM uses the P03 shared per-credential and per-organization rate limiter. Production deployments must configure the existing Valkey backend as required by P03; the in-memory limiter remains local/development only.

## Migration

Alembic revision 0011_scim follows 0010_sso. It adds members.active, dlp_scim_credentials, dlp_scim_users, dlp_scim_groups, and dlp_scim_group_members. Tenant-owned tables have tenant foreign keys, indexes, uniqueness constraints, and RLS. User/group directories and membership force RLS; credential lookup is the trusted service-role bootstrap before tenant claims, while authenticated credential administration is tenant owner/admin-only.

Apply with alembic upgrade head; P12 requires the PostgreSQL RLS/auth schema already used by P03–P11.

## P13 handoff

P13 can reuse members and members.active for users, organizations.id for tenants, dlp_scim_users.member_id for SCIM-managed identities, dlp_sso_identities.member_id and config_id for SSO mappings/providers, and dlp_scim_groups plus dlp_scim_group_members for directory memberships. P12 does not implement sessions, IP allowlists, organization switching, lifecycle pages, or group-to-role mapping.
