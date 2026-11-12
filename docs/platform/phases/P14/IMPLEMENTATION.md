# P14 implementation

## Data inventory (repository schema at P14)

| Resource | Tenant / subject scope | Security and dependency treatment | Retention / hold / deletion |
|---|---|---|---|
| `organizations` and `settings_json` | Tenant | Organization is referenced by audit and lifecycle rows | Retain as anonymized tombstone; clear settings |
| `members` | Tenant membership; `auth_subject_id` can be shared across tenants | Composite membership identity is distinct per organization | Delete only the target membership; preserve memberships in other organizations |
| `dlp_app_sessions` | Tenant and member | Token hash, IP and user agent are sensitive | Expired/revoked sessions use `sessions`; remove all target-tenant sessions at deletion |
| `dlp_api_keys`, `dlp_scim_credentials` | Tenant | Hash/prefix metadata only; secrets are not exportable | Revoked credentials use `revoked_credentials`; delete tenant credentials |
| `dlp_policies`, `dlp_policy_versions`, destinations, exceptions, suppressions | Tenant; authorship can identify a member | Policy rules and exception reasons may be sensitive | Not generic-retention controlled; deleted during staged tenant deletion |
| approvals and actions | Tenant; requester/decider subject data | May contain justification text; export is metadata only | No generic retention category; delete during tenant deletion |
| vault secrets and SSO configuration | Tenant | Vault ciphertext and provider secrets | Not generic-retention controlled; delete ciphertext/configuration without decryption |
| SSO identities, transactions, replays | Tenant; identity mapping | State/nonce are hashes; subject/email can be personal data | Expired transactions/replays use `sso_ephemera`; delete tenant mappings/configuration |
| SCIM users/groups/memberships | Tenant; users may map to members | External identifiers and names are personal data | No generic-retention category; delete tenant mappings and groups |
| `channels`, `events`, `dlp_scan_idempotency` | Tenant | Existing P2 gate/configuration state; event payload can include scan input metadata | `scan_records` deletes old events and idempotency results; tenant deletion removes both |
| `audit_events` | Tenant-keyed, hash-chained | Immutable accountability record, P10 trigger blocks mutation/deletion | Excluded from retention/export deletion; preserved with anonymized organization row |
| P14 lifecycle tables | Tenant | Hold reason and deletion state are sensitive | Holds/history remain; policies/runs are removed during deletion; deletion request retained |
| P1 detector/classification and P4 finding/incident data | Not present in P2 schema | No P1/P4 stores/adapters were found in the current P2 repository | `TenantDataLifecycleAdapter` is the explicit future handoff; no P1/P4 functionality is fabricated |

## Retention

Four supported categories are implemented: `sessions`, `scan_records`, `sso_ephemera`, and `revoked_credentials`. Each organization policy has duration, enabled state, effective time, updater and timestamps. Updating a policy resets `effective_at`; records are eligible only after both their age threshold and the policy effective time plus the configured duration have elapsed. This avoids retroactive deletion on first enable or duration change.

Execution is an explicit bounded API batch (maximum 500 rows per table/category call), not a scheduler. It physically deletes only expired/revoked/ephemeral operational rows. Active legal holds for the matching category or all categories suppress the batch. Hold creation/release and retention share a PostgreSQL transaction advisory lock keyed by organization. A batch failure is recorded and can be retried; completed deletions are idempotent. Immutable audit events are never retention targets.

## Legal holds

Owner/admin interactive users can create and inspect organization-scoped active/released holds and release them with a reason. A null category holds every P14-retained category. Subject-level holds are not supported because P2 does not have a single global subject-owned record graph. Hold reasons/releases are stored for lifecycle history but are never placed in audit metadata or subject exports.

## Organization deletion

The owner requests deletion by confirming the exact current organization name, then confirms it again. Active holds block destructive work and create a blocked state and audit entry. Once confirmed, deletion advances through a fixed dependency order using bounded batches, a saved table cursor and retryable failure state. New holds cannot be created once deletion is in progress. Authenticated access is restricted to deletion status/continuation during execution.

At finalization the current member and session are removed, organization settings are cleared, and the organization name is replaced with a tombstone. P10 audit rows and the deletion request remain to preserve the audit chain and lifecycle result. Other organizations' membership rows, sessions, credentials and shared identity are not targeted. Vault records are physically removed without decrypting; there is no cryptographic-erasure claim. External stores participate only through idempotent registered adapters.

## Subject export

The current subject can export its own data. Owner/admin can export another member only within the active organization. Results are deterministic and bounded to 500 rows per category and 1 MB total. Export includes scoped membership and safe metadata; omits token/key hashes, credentials, vault material, free-text policy/hold reasons and other organizations. Request/completion audit actions include no export body.

## Database, audit, identity integration

Alembic revision `0013_data_lifecycle` follows `0012_identity_management`, adds four tenant tables, constraints/indexes, RLS with `FORCE ROW LEVEL SECURITY`, and an owner/admin organization policy. It extends the immutable audit vocabulary while downgrade keeps historical P14 action values accepted. P13 session and membership identity remain organization-local; deletion removes only the current tenant's membership.

## P15 handoff

P15 may expose versioned public endpoints or webhooks, but must preserve the current organization lifecycle state, active-hold check, subject export scope, owner-only deletion authorization and P10 audit events. Public clients must not set organization IDs independently of verified credentials. Version new public schemas; do not bypass the staged deletion service or expose hold reasons/secrets by default.

## Acceptance status (2026-10-23)

P14 implementation remains based on checkpoint `94d731824e06bb58692bdfce9d300cecd8bf1442`; the prior validation checkpoint is `e0760085469d98915cda0daac340b0ddf3111400`. The database configured through ignored `.env.p03-test` answered PostgreSQL 16.15 for `dlp_p03_test`. The Docker CLI could not reach its configured Docker Desktop Linux engine pipe during this run, so container health was not independently reported by Docker; direct PostgreSQL connectivity and the actual server version were verified.

The focused P14 PostgreSQL acceptance/RLS and scratch-database migration tests passed: 14 passed, zero failed or skipped. The migration test traverses P14 upgrade, downgrade to P13, and re-upgrade, along with historical checkpoints, on an isolated temporary database. The complete backend suite passed: 293 passed, zero failed or skipped, with 21 dependency deprecation warnings. Frontend lint, typecheck, build, and 16 tests passed. Ruff lint, mypy (85 source files), pre-commit including its hardcoded-secret scan, pip-audit, and `git diff --check` passed. `ruff format --check .` continues to report 12 pre-existing out-of-scope files. Standalone Gitleaks is unavailable.

Acceptance has materially expanded: real PostgreSQL race tests exercise retention/hold creation, deletion/hold creation, simultaneous retention workers and retry after injected partial failures; cleanup tests inspect multi-org rows across P2 tables and vault ciphertext; export tests inspect a parsed 500-row bounded result, tenant scope and sensitive-field omission, and both oversize and failure-audit paths; HTTP tests verify authorization, cross-tenant IDs, inactive/nonexistent exports and audit actor/correlation metadata. A migration trigger interaction with immutable policy versions was fixed narrowly so only the P14 cleanup transaction may delete them; ordinary deletion remains rejected. Exported session user-agent metadata is sanitized.

## Owner-accepted non-blocking validation gaps

On 2026-10-23, the project owner explicitly accepted the following remaining limitations as non-blocking for this P14 milestone: (1) some HTTP lifecycle status/denial cases do not have independent tests; (2) the P14 audit success/failure matrix is not exhaustive; (3) standalone Gitleaks is unavailable (the pre-commit secret scan passed); and (4) `ruff format --check .` reports 12 pre-existing files outside P14. These are not reported as tested or passed. The owner accepts them as exceptions; no security or authorization controls were weakened.

Given that explicit acceptance, P14 status is **COMPLETE — OWNER-ACCEPTED EXCEPTIONS**, based on the executed evidence above and the documented exceptions. PostgreSQL container status could not be queried through Docker CLI during validation, but a direct PostgreSQL 16.15 connection and test execution succeeded. No P15 implementation was started.
