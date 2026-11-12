# P2 decisions

Statuses: [SRC] is explicit in a source document; [REC] is a proposed implementation
choice; NOT SPECIFIED IN SOURCE means a decision was needed. No item below claims
approval from P1, P3, or P4.

| ID | Decision | Status | Rationale / follow-up |
|---|---|---|---|
| D-001 | Use Alembic as the only migration system. | [SRC] permitted choice; [REC] selected | P01 permits Alembic or Supabase migrations. A greenfield Alembic baseline is executable in local tests and targets PostgreSQL. |
| D-002 | Contract version is 1.0.0, status PROPOSED; `contracts-v1` identifies a repository snapshot only. | [REC] | Source names seven contracts but does not define every field. A Git tag does not constitute approval or freeze external interfaces. |
| D-003 | Use strict, immutable Pydantic models with unknown fields rejected. | [REC] | Prevents silent boundary drift; source requires Pydantic v2 and snapshot tests. |
| D-004 | ScanRequest.content is a Pydantic SecretStr and must remain transient. | [REC] | The scan path accepts content, while source forbids raw content in logs and storage. |
| D-005 | Contract classification values follow the five named levels. | [SRC] | public, internal, confidential, restricted, highly_restricted. |
| D-006 | Severity vocabulary is low, medium, high, critical. | NOT SPECIFIED IN SOURCE; [REC] | A concrete enum is needed for an initial contract; revise only through the contract-change process. |
| D-007 | Use organizations.settings_json for organization-level settings. | [REC] | Resolves source conflict C10 without adding a feature table in P01. |
| D-008 | Use string-encoded UUID identifiers in the portable baseline schema. | [REC] | Keeps SQLite migration verification and PostgreSQL runtime compatibility straightforward. |
| D-009 | Baseline schema is created from zero; there is no prior database schema to preserve. | [SRC] in master implementation instructions | organizations, members, channels, and events are the P01 foundational tables; no data dump is used. |
| D-010 | P2 endpoint proposals use /scan and /gate/check; P3 asynchronous /scans endpoints are not implemented here. | [SRC] route reconciliation; P2-only boundary | No P3 route behavior is copied into P2. |
| D-011 | Cross-stream approval is not claimed. | User scope | This work is P2-only. The contract remains proposed until the user approves its field set. |
| D-012 | P01 originally added standalone secret scanning; the later security review adds P2-only PostgreSQL, test, and security CI. | User scope + P01 + security review | No P4 build/deployment features are added. |

## Unresolved

- Contract fields are implementation proposals where source documents did not specify them.
  User review is needed before any contract is called frozen.
- The source plan lists Pydantic v2 but does not specify a database connection lifecycle or
  production migration runner. P01 supplies migration artifacts only; runtime wiring is
  deferred to its owning P2 phase.

## P02

| ID | Decision | Status | Rationale / follow-up |
|---|---|---|---|
| D-013 | Use FastAPI routes and the shared `CurrentPrincipal` dependency. | [REC] | P02 source identifies routes but not a web framework in the phase specification. |
| D-014 | Verify JWT with exactly one configured HS256 secret or RS256/ES256 JWKS source. | [REC] | Fixed algorithms prevent unsigned and algorithm-confusion acceptance. |
| D-015 | Require `exp`, `sub`, and `aud`; use `authenticated` as default audience and 30-second bounded leeway. | [SRC]/[REC] | Source specifies expiry, audience, and small clock skew; implementation defaults are recommendations. |
| D-016 | Resolve role from `members.role`, not JWT role claims. | [REC] | Membership is the platform's organization-scoped authority. |
| D-017 | Use the role matrix and closed scopes in `docs/auth-and-roles.md`. | [REC] | Source calls for a matrix and scopes but does not define their exact permissions/names. |
| D-018 | API-key hashes are SHA-256 over the full cryptographically random token. | [REC] | Source explicitly accepts SHA-256 for long random keys. |
| D-019 | No API-key expiry is added. | NOT SPECIFIED IN SOURCE | P02 table has no expiry field; revisit only with product direction. |
| D-020 | Cross-org API-key revoke returns generic 403. | [SRC] | Follows P02 wrong-org response requirement without disclosing key details. |

P02 unresolved: product-owner confirmation of the role-permission matrix and scope names;
real Supabase provider configuration and integration. P03 will add RLS, database tenant
isolation, rate limits, and the `scan()` stub.

## P03

| ID | Decision | Status | Rationale / follow-up |
|---|---|---|---|
| D-021 | Apply PostgreSQL RLS to all five organization-owned tables, with Supabase `auth.jwt()` claims and forced RLS. | [SRC]/[REC] | Tenant tables come from P01/P02. Read policies are tenant-scoped; member/channel/event writes are not exposed to `authenticated`. |
| D-022 | The backend verifies identity using its Supabase service database role, then assumes `authenticated` transaction-locally and sets verified claims. | [REC] | Avoids trusting request-body org IDs and ensures subsequent database statements execute under RLS. Requires the service connection to be allowed to `SET ROLE authenticated`. |
| D-023 | Add `scan:request` to the closed scope set for Owner, Admin, and Analyst. | [REC] | Scan access needs role and scope enforcement; existing Viewer/Auditor roles remain denied. |
| D-024 | Rate limit each API key (or JWT subject) and organization in a fixed 60-second window; defaults 30/key and 300/org. | NOT SPECIFIED IN SOURCE; [REC] | Source requires per-key and per-org limits without numeric values. All values are environment-configurable. |
| D-025 | Use Valkey 6.2.0 for shared production counters and an atomic Lua increment; allow process-local memory only outside production. | [REC] | Prevents silently using a per-process limiter in production. |
| D-026 | P03 scan stub returns deterministic ALLOW with empty findings and does not inspect or persist content. | [REC] | Preserves P01 contracts while leaving detection for P04. |

P03 unresolved: live Supabase/PostgreSQL RLS and Valkey integration were unavailable.
Connection-role assumptions and policy syntax require validation before tagging P03.

## P03

| ID | Decision | Status | Rationale / follow-up |
|---|---|---|---|
| D-021 | Apply PostgreSQL RLS to all five organization-owned tables, with Supabase `auth.jwt()` claims and forced RLS. | [SRC]/[REC] | Tenant tables come from P01/P02. Read policies are tenant-scoped; member/channel/event writes are not exposed to `authenticated`. |
| D-022 | The backend verifies identity using its Supabase service database role, then assumes `authenticated` transaction-locally and sets verified claims. | [REC] | Avoids trusting request-body org IDs and ensures subsequent database statements execute under RLS. Requires the service connection to be allowed to `SET ROLE authenticated`. |
| D-023 | Add `scan:request` to the closed scope set for Owner, Admin, and Analyst. | [REC] | Scan access needs role and scope enforcement; existing Viewer/Auditor roles remain denied. |
| D-024 | Rate limit each API key (or JWT subject) and organization in a fixed 60-second window; defaults 30/key and 300/org. | NOT SPECIFIED IN SOURCE; [REC] | Source requires per-key and per-org limits without numeric values. All values are environment-configurable. |
| D-025 | Use Valkey 6.2.0 for shared production counters and an atomic Lua increment; allow process-local memory only outside production. | [REC] | Preserves Windows/WSL development and prevents silently using a per-process limiter in production. |
| D-026 | P03 scan stub returns deterministic ALLOW with empty findings and does not inspect or persist content. | [REC] | Preserves P01 contracts while leaving all detection behavior for P04. |

P03 validation: real PostgreSQL 16.15 RLS, grants, `SET ROLE`, transaction-local claims,
and migration downgrade/re-upgrade passed using the local test harness documented in
`docs/phases/P03/TEST_PLAN.md`. [UNV] Live Supabase hosted-project integration and a
Valkey server exercise were not run.
