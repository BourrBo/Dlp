# P17 implementation record

## Scope

P17 adds tenant-bound Microsoft OneDrive and SharePoint connectors on the P16
connector tables, lifecycle service, OAuth transaction store, P09 Vault, audit
events, and P04 scan boundary. It does not add content download, parsing, or new
policy/action semantics. File metadata from Graph is passed to the existing
`scan()` pipeline, so configured P1 detectors, P05 policy evaluation, and P07
action/approval execution remain the enforcement path.

## Microsoft identity and authorization

Each Microsoft connector stores its Microsoft Entra tenant GUID in that
connector's `config_json`. OAuth authority URLs are constructed only from that
validated GUID and `login.microsoftonline.com`; tokens are never looked up by a
global tenant map. OAuth uses persisted one-time P16 transactions, session and
principal binding, PKCE S256, and an exact configured HTTPS redirect URI. Before
the refresh token is saved, the callback reads `/organization?$select=id` and
requires the returned tenant ID to match the connector configuration. Refresh
tokens are stored only in the existing encrypted P09 Vault.

Set these server-side environment variables before enabling OAuth:

- `MICROSOFT_OAUTH_CLIENT_ID`
- `MICROSOFT_OAUTH_CLIENT_SECRET`
- `MICROSOFT_OAUTH_REDIRECT_URI` (must exactly match the Entra app registration)
- the existing P09 Vault encryption configuration

The Entra app must be single tenant for the configured tenant. The delegated
scopes are `openid`, `profile`, `offline_access`, `User.Read`, and
`Files.ReadWrite.All` for OneDrive, with `Sites.ReadWrite.All` added for
SharePoint. Tenant administrators must grant the consent required by the app's
tenant and access model. Permissions include write access because P07 can
revoke sharing links after the existing policy and approval flow authorizes the
action.

Create a connector with provider `microsoft_onedrive` or
`microsoft_sharepoint` and its tenant GUID, then start OAuth through
`POST /connectors/{id}/microsoft/oauth/start`. OneDrive uses the authenticated
user's drive. SharePoint requires the interactive operator to search sites,
list a site's drives, and select a drive. The selected site and drive are
validated against Graph and saved separately. Site, drive, item, and tenant IDs
remain separate values throughout the connector and action metadata.

## Change feed and enforcement

OneDrive and SharePoint use Graph drive-item delta. Opaque `@odata.nextLink` and
`@odata.deltaLink` values are stored in tenant-scoped connector state, not in
the short checkpoint column. Every continuation link is fixed-host, HTTPS,
`/v1.0/`, and length checked. A page is scanned before state is committed; a
provider, scan, persistence, or incomplete P07 action failure leaves the prior
continuation link in place. Deleted Graph facets are treated as removals and
are not scanned.

Graph sharing metadata distinguishes anonymous and organization links, direct
users/groups, unknown grants, and inherited grants. The connector only attaches
a P07 revoke target for a live, direct anonymous or organization sharing link
returned by Graph. Inherited permissions are never selected as revoke targets.
P07 re-reads the connector and Vault refresh token, refreshes against the
configured tenant authority, verifies the tenant again, performs the Graph
permission delete, and verifies the permission is absent. Unsupported
operations fail closed.

SharePoint library selection records the `connector.microsoft_library_selected`
audit action. Connector state and credentials retain the existing forced-RLS
policies and tenant claims.

## Validation record

P17 automated validation uses deterministic Graph/OAuth fixtures and local
PostgreSQL migration/RLS tests. **Live Microsoft Entra OAuth and live Graph API
validation were not performed**; no Microsoft credentials are configured in
this repository. Fixture tests do not establish provider-tenant consent,
network availability, or behavior in a real Microsoft tenant.

See [SECURITY.md](SECURITY.md) and [TEST_PLAN.md](TEST_PLAN.md) for security
boundaries and the exact executed commands/results.

## Microsoft Graph references

- [driveItem delta](https://learn.microsoft.com/graph/api/driveitem-delta?view=graph-rest-1.0)
- [List organizations](https://learn.microsoft.com/graph/api/organization-list?view=graph-rest-1.0)
- [List a site's drives](https://learn.microsoft.com/graph/api/drive-list?view=graph-rest-1.0)
- [Remove a sharing permission](https://learn.microsoft.com/graph/api/permission-delete?view=graph-rest-1.0)
