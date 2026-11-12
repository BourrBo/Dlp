# P16 implementation record

## Status

P16 is **complete for the fixture/mock acceptance scope**. The required P16 test, PostgreSQL/RLS, migration, security-tool and documentation checks passed. No live Google validation was performed. The scope limits below remain documented; quarantine stays unsupported and returns HTTP 501.

## Connector base

- `backend/app/connectors/models.py` defines provider-neutral identity, lifecycle status, sync, exposure, and action contracts. Legal lifecycle transitions are validated.
- `backend/app/connectors/service.py` stores tenant-bound connector records and sync checkpoints. It sets authenticated transaction-local tenant claims and filters every operation by the authenticated organization.
- Migration `0014_connectors` creates `dlp_connectors` and `dlp_connector_state`, with forced PostgreSQL RLS, role grants and organization/provider constraints. Credentials are held by reference only.
- `backend/app/routes/connectors.py` exposes authenticated list/create/status, OAuth start/callback, sync, disconnect, share-revoke and quarantine operations under `/connectors`. Mutations require an interactive owner/admin. Responses are metadata-only and `no-store`.
- P10 `AuditService` and the existing connector audit actions are reused. P09 `SecretVault` stores OAuth refresh tokens. OAuth client ID/secret and the exact callback URI are configured with `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` and `GOOGLE_OAUTH_REDIRECT_URI`; no values are committed.

## OAuth and Google Drive

Authorization uses Google Authorization Code flow, PKCE S256, unpredictable state, a 10-minute one-use transaction, exact configured HTTPS callback URI, and fixed Google OAuth/API hosts. OAuth state is persisted in `dlp_oauth_transactions` with a SHA-256 state digest, tenant RLS, principal/member/session binding, provider, redirect URI, PKCE verifier, expiry, and `consumed_at`. Callback consumption is one atomic `UPDATE ... RETURNING`, so a concurrent replay has one winner. The callback checks that the member and application session remain active before exchanging the code. Access and refresh tokens are never returned by the API. The refresh token is stored as a P09 `refresh_token` secret; the access token remains ephemeral.

The connector requests `https://www.googleapis.com/auth/drive`. Google classifies `drive` as restricted. The narrower `drive.metadata.readonly` cannot change sharing permissions, while `drive.file` only covers files opened by or shared with the app; those scopes cannot implement an organization-wide change feed and revoke-share operation. The selected broad scope is therefore needed for the intended full-Drive monitoring and write actions, and requires Google restricted-scope review before production distribution. See Google's [Drive scope guide](https://developers.google.com/workspace/drive/api/guides/api-specific-auth) and [permission deletion method](https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/delete).

The implemented Google API adapter uses fixed `accounts.google.com`, `oauth2.googleapis.com` and `www.googleapis.com` hosts; bounded response reads; strict timeouts; disabled redirects; bounded retries for rate limits/transient failures; Drive v3 shared-drive flags; page-token loop detection; and normalized provider errors. It reads change pages and metadata, maps `anyone` discoverable access to `public`, `anyone` non-discoverable access to `link`, domain permissions to `domain`, direct user/group permissions to `users`, and unclassifiable permission records to `unknown`. The API follows Google's [change feed page-token model](https://developers.google.com/workspace/drive/api/guides/manage-changes).

Shortcut targets are exposed as stable deduplication identities. Shared-drive request flags are enabled. `revoke_share` verifies the current permission, deletes it, and reads metadata again to verify removal; already absent permissions are idempotent. Quarantine intentionally returns `quarantine_folder_not_configured`: no tenant-controlled quarantine folder provisioning/authorization/restore record exists, so the connector does not move or delete user files.

## Synchronization and boundaries

The OAuth callback obtains a Drive start page token before baseline enumeration and stores it as the incremental cursor. It marks initial inventory pending. Each sync invocation reads one bounded `files.list` page with shared-drive flags and a tenant-persisted page token; after metadata normalization and `scan()` handoff succeeds, the page cursor is committed. The saved change-feed token is unchanged during inventory. Only after the final inventory page is committed does a later sync read the changes feed from the earlier start token, covering changes that occurred during baseline enumeration. Incremental batches are also bounded and advance the page/change checkpoint in the same DB transaction as completion state, after all returned objects have been handed to `scan()`. Repeated provider page tokens are rejected. A failed provider call or scan leaves the old persisted checkpoint valid. External Google actions are not claimed to be exactly-once. Refresh authorization failures are marked `reauth_required`. Connector OAuth tokens remain in Vault.

For each non-deleted inventory or change-feed object, normalized Drive metadata is serialized into the existing P04 `ScanRequest` and passed to the existing `scan()` function with the authenticated tenant principal and a deterministic request ID. The configured P1 detector/classifier, P05 policy evaluator and P07 action processor are therefore used by the existing pipeline. This is a metadata scan only: P16 does not download content or add parsers/detectors. If the pipeline fails, or a `REVOKE_SHARE` decision does not complete, sync fails before committing the cursor. P16 cannot infer a permission target from arbitrary client scan metadata; executable revoke targets are attached only by the trusted connector route.

Known incomplete handoffs:

- OAuth state is restart/multi-worker-safe in PostgreSQL. Expired rows are cleaned opportunistically for the creating tenant; no separate scheduled purge job exists.
- Initial inventory and incremental feed paging are implemented as above. Inventory is metadata-only and is not a content crawl.
- `scan()` receives normalized metadata, not file contents. There is no Drive content download/export adapter, so content detection is not provided by P16.
- Share revocation is available only through the owner/admin route and only after the configured P05 decision is `REVOKE_SHARE`. P07 persists it as `pending_approval`; the endpoint returns HTTP 202 with the P07 approval ID. The configured Google Drive executor is shared by P07's approval route and uses the tenant's P09 refresh-token secret. It runs only after an authorized approver approves the action. The executor accepts opaque connector/object/permission identifiers only through a backend-only `ScanRequest` private attribute; caller-controlled scan context cannot authorize an external action. The tenant organization is bound from the verified principal. Quarantine is deliberately rejected with HTTP 501 until a controlled destination, authorization model and restore record exist.
- P07 approvals are one-time state transitions. P07 records an action as approved only after the external executor returns; an approved-state retry is rejected. Google permission deletion is idempotent at the provider adapter: if the permission is already absent it returns `already_absent`. This is safe retry behavior, not exactly-once execution; a process failure after Google's side effect but before database commit can cause another provider call on retry.
- Restored-file distinctions and Drive permission inheritance classification are not fully normalized. Inventory starts on the first sync request after OAuth rather than blocking the callback until the entire Drive is enumerated.
- Shortcut target deduplication is performed within fetched changes only; a durable cross-sync deduplication registry is not implemented.
- Tenant domains are not configured in connector metadata, so individual user/group permissions are represented as `users`; the connector cannot assert whether those users are external.
- Google API behavior was tested with deterministic transport fixtures only. No live Google credentials/provider request was used.
- OAuth application client ID/client secret are deployment-level bootstrap configuration (`GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET`), not tenant-owned Drive credentials. They remain environment configuration intentionally; per-tenant refresh tokens use P09 Vault. This deployment secret still needs the deployment platform's secret manager in production.
- No P16 frontend connector UI is implemented; no connector UI existed in the checked-in frontend.

## P14/P15 and P17 handoffs

Connector rows and state reference organizations with cascading deletion, and state cascades from its connector. OAuth refresh secrets remain normal P09 Vault entries, so Vault/P14 organization deletion controls their lifecycle. No connector content is included in audit metadata. No connector-specific subject export or retention category is currently registered.

P15 conventions are reused for authenticated principals, normalized errors, correlation IDs and tenant scopes; connectors remain on the authenticated `/connectors` API rather than the API-key `/api/v1` surface. P17 should implement OneDrive and SharePoint behind `Connector`, use provider-specific modules for OAuth/API operations, and add only provider capabilities to the shared contract when they are genuinely common.

## Validation

See [TEST_PLAN.md](TEST_PLAN.md) for executed fixture and PostgreSQL test commands and results.

## Acceptance evidence update — 2026-10-23

The sync handoff now passes each non-deleted Drive change from the actual `/connectors/{connector_id}/sync` handler through `GoogleDriveAPI.list_changes`, provider normalization, existing `scan()`, P05 `PolicyEngine`, P07 approval persistence and `GoogleDriveActionExecutor`. A deterministic provider-shaped change fixture exercises this boundary. Trusted action metadata is constructed from the verified connector and a live normalized `anyone` permission; the sync path does not guess a direct user/group/domain permission until policy identifies a specific target. Client-controlled scan context cannot set trusted metadata. Pending and rejected approval do not call the provider. Approval calls the mocked revoke with the normalized file and permission IDs and records approval/action audit events.

Checkpoint behavior is at-least-once at the change-feed boundary. The test simulates checkpoint persistence failure after P07 records successful revoke; retry consumes the same fixture change, reads the tenant-scoped durable action status, advances the checkpoint, and does not invoke the provider again. Exactly-once provider execution is not claimed for a crash before the action outcome is durably recorded. Google revoke treats an already-absent permission as success.

The mounted OAuth callback has PostgreSQL-backed HTTP validation: state is created in the real database, consumed by the callback, persisted only as a digest and rejected on replay, expiry, tenant-prefix tampering, principal mismatch and PKCE mismatch. Rejected cases do not write Vault credentials. A fixture transport validates the fixed Google token endpoint; no network request is made.

All nine registered connector routes have an explicit access classification and applicable credential, scope, role, tenant and forged-resource coverage documented in [TEST_PLAN.md](TEST_PLAN.md). API-key cases apply only to connector read operations; write operations require an interactive user. Synthetic secret markers cover OAuth responses/errors and state, Vault retrieval, P07 metadata/results, audits and public connector serialization. Twelve `detect-secrets` findings were reviewed: eight are **FALSE POSITIVE / SECURITY VOCABULARY** (`API_KEYS_*`, `API_KEY_*` and `SECRET_*` role/audit identifiers) and four are explicit synthetic `TEST_*_DO_NOT_LEAK` markers in the PostgreSQL callback fixture. No credential values were found. Configured pre-commit Gitleaks/hardcoded-secret detection passes; standalone Gitleaks CLI is unavailable.

Quarantine remains unsupported and fail-closed with HTTP 501 and no provider mutation. Fixture/mock Google validation is the only provider evidence; live Google validation was not performed. No P17 work is included.
