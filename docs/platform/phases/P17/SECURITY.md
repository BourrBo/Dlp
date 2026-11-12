# P17 security boundaries and limitations

## Tenant separation

- A Microsoft tenant GUID is configured on each connector, under the DLP
  organization's existing row-level security boundary.
- OAuth uses that connector's tenant-specific authority. The Graph organization
  ID must match before the Vault credential is written and before sync or an
  action proceeds.
- Site, library, item, and tenant IDs are distinct. SharePoint selection checks
  the requested library against Graph results before storing it.
- Existing P16 forced RLS is retained for connector, state, and OAuth tables.
  The P17 migration changes provider and audit-action check constraints only.

## OAuth and secrets

- State is persistent, one use, tenant/provider/connector/principal/session
  bound, short lived, and PKCE protected through the P16 transaction service.
- OAuth and Graph transport allow only fixed Microsoft HTTPS hosts, reject
  redirects, bound responses, and do not log tokens, codes, response bodies, or
  opaque continuation links.
- Refresh tokens use only the existing encrypted P09 Vault. The client secret
  is supplied by deployment environment and is never committed.
- Callback failures use generic public details. A token is saved only after
  token response validation and tenant ID verification.

## Provider and action safety

- Delta links are treated as opaque but constrained to the Graph v1.0 host and
  length. A repeated continuation is an error; checkpoints advance only after
  all page scans and required actions complete.
- Provider-originated metadata is normalized and bounded. Deleted items are
  not rescanned. Inherited shares and unrecognized permissions are not
  converted into executable revocation targets.
- The only implemented destructive provider action is the existing P07
  `REVOKE_SHARE` path. It requires trusted backend metadata, connector identity,
  drive ID, item ID, permission ID, and a successful post-delete verification.
- No file content is downloaded. Content DLP detection remains outside this
  phase's scope. The Microsoft app scopes are delegated and include write
  permissions to support the narrow P07 share-revocation behavior.

## Validation boundary

The provider boundary is fixture-tested. Live Microsoft OAuth, consent, tenant
configuration, Graph permissions, and real tenant change feeds have not been
validated. Gitleaks availability, security-tool findings, and the full suite are
recorded in `TEST_PLAN.md` after the final validation run.
