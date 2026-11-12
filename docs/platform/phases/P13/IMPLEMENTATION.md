# P13 — Identity, sessions, organizations, and network access

## Delivered

P13 adds identity APIs and UI on top of the P01–P12 authentication, authorization,
SSO, SCIM, and audit foundation. The implementation provides a profile view,
cross-organization membership discovery for the signed-in identity, validated
organization switching, active session listing and revocation, and tenant-owner/admin
management of a CIDR IP allowlist. The frontend exposes Identity, Sessions, and IP
Allowlist pages and only offers organization choices returned for the current
authenticated subject.

P13 does not add a scan pipeline, policy features, or later-phase functionality.

## Session model

Existing signed JWTs represent interactive sessions. On first successful use, the
server stores a UUID, organization and member IDs, authentication method, timestamps,
source IP, and sanitized user agent. The stored token identifier is SHA-256 of the
bearer token; the raw token is not persisted. Expiration follows the JWT expiration
plus the configured JWT clock-skew leeway. Every later request checks revocation and
expiry, resolves the currently active membership and role, and updates last-seen.
Revoking the current or another session takes effect on its next request. “Log out
other sessions” revokes the other active sessions in the current organization.

This model does not issue refresh tokens and does not introduce a separate idle
timeout. API keys remain service credentials: they are not interactive sessions and
are not subject to the user IP allowlist.

## Organization and tenant enforcement

The profile and membership endpoints use the validated bearer subject. Organization
switching accepts an organization ID only when that subject has an active membership
there; it updates the tracked session organization and returns the active role and
permissions. A supplied organization ID never creates membership or changes the
authenticated subject. Existing application checks and PostgreSQL RLS both enforce
tenant boundaries. The migration adds narrowly scoped self-membership SELECT policies
so a person can discover their own memberships across organizations.

Session, allowlist settings, and allowlist entries have forced PostgreSQL RLS. Session
rows are visible and revocable only for the authenticated member in the active
organization. Allowlist rows require the active organization and owner/admin role.
The migration grants only the table operations used by these APIs. The real database
acceptance test exercises these policies using the `authenticated` database role,
including `SET LOCAL ROLE`, transaction-local JWT claims, tenant switching, and no
tenant context.

## IP allowlist and proxy trust

Entries are normalized CIDR networks and stored in PostgreSQL's `cidr` type. The
setting is disabled by default; enabling it requires at least one entry, and an enabled
list cannot be emptied. Requests are matched against the socket peer address. The
`X-Forwarded-For` chain is considered only when the direct socket peer belongs to a
network in `DLP_TRUSTED_PROXY_CIDRS`; the chain is walked from the nearest hop through
trusted proxies to resolve the client. Untrusted forwarded headers are ignored.
Malformed trusted-proxy configuration or a malformed forwarded chain fails closed.
The application currently treats an unavailable client address as unmatched when an
allowlist is active.

Deployments behind a proxy must configure `DLP_TRUSTED_PROXY_CIDRS` with the exact
proxy networks and ensure the edge proxy overwrites or sanitizes forwarded headers.
Do not trust arbitrary client-supplied forwarding headers.

## Audit and migration

Session establishment/revocation, organization switches, and allowlist changes or
blocks are recorded through the existing P10 audit service. Audit metadata excludes
bearer tokens and token hashes. Migration `0012_identity_management` follows
`0011_scim`, creates the P13 tables and RLS policies, adds self-membership policies,
and extends the audit action constraint. Downgrade removes P13 tables and policies
while retaining the P13 action vocabulary so append-only historical audit rows remain
valid.

## Local PostgreSQL test setup

The repository's `.env.p03-test` is local and ignored by Git. It contains
`P03_TEST_DATABASE_URL` for the dedicated project-local Compose service; do not commit
or print this file. Start the pinned PostgreSQL service with Docker Compose and wait
for its health check before running tests. The tested environment used PostgreSQL
16.15 and a project-local port mapping. Set `P03_TEST_DATABASE_URL` from the ignored
environment file and ensure `DATABASE_URL` is unset when running the PostgreSQL
isolation tests. The fixture/migration tests exercise upgrade to P13, downgrade to
P12, and re-upgrade to P13. `tests/isolation/test_postgres_p13.py` checks live RLS for
sessions, allowlist entries, memberships, and missing tenant context.

## Scope boundary

P13 is the identity and network-access phase only. Later-phase features are not
implemented here.
