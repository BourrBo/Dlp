# Schema reconciliation

## Starting state

The repository and database are greenfield. No existing application schema or database
dump was present. P01 therefore creates the foundational schema rather than attempting
to preserve or rewrite tables from an unavailable database.

## Baseline mapping

| Source concept | Greenfield table | P01 columns / notes |
|---|---|---|
| Organisations | organizations | id, name, settings_json, timestamps. settings_json is [REC] for C10. |
| Organisation membership | members | id, organization_id, auth_subject_id, role, created_at. Role enforcement begins in P02. |
| Channels | channels | id, organization_id, channel_type, name, enabled, created_at; no provider credentials or sync implementation. |
| Decision events | events | Organization, request and scan references; channel, destination, decision, safe reason, finding count, timestamps. No raw content. |

P02 adds API-key storage in its own migration. Later phases add their own tables using
new migrations; old migrations are not edited after completion. There are no duplicate
migration systems.

## P2 route reconciliation

P01 defines route names for planning only. It implements no HTTP endpoints.

| Method | Route | P2 phase | Ownership note |
|---|---|---|---|
| GET | /auth/me | P02 | P2 authentication identity |
| POST | /api-keys | P02 | Create key; plaintext shown once |
| GET | /api-keys | P02 | List metadata only |
| DELETE | /api-keys/{key_id} | P02 | Revoke |
| POST | /scan | P04 | P2 synchronous pipeline |
| POST | /gate/check | P04 | P2 gate API |
| POST | /v1/... | P15 | P2 versioned public API |

P3 asynchronous /scans job interface remains outside this P2 implementation. Route
names beyond those listed are not introduced in P01.
