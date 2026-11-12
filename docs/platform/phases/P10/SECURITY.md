# P10 Security Notes

## Threat model and controls

Audit rows support tenant-scoped accountability and should resist accidental or
ordinary application-level edits. Tenant identity is always derived from the verified
`Principal`. Forced PostgreSQL RLS limits SELECT and INSERT by the transaction-local
organization claim. The `authenticated` database role has no UPDATE or DELETE
privilege, and a trigger rejects those mutations for all ordinary database roles.

Each tenant has an ordered SHA-256 hash chain. Every event includes the prior event
hash and the row hash covers all event fields. `AuditService.verify_chain` detects
missing, reordered, or changed rows. This is tamper-evident integrity checking, not
cryptographic non-repudiation: a database superuser who can alter rows, disable
triggers, and recompute the complete chain can rewrite evidence. External signed
anchoring is not part of P10.

Without an external signed anchor, deleting the final tail of a chain cannot be
distinguished from a chain that ended earlier. Sequence gaps, interior deletion,
reordering, and row changes are detected; tail truncation is an explicit limitation.

Operators with `audit:read` can call `GET /audit/events/verify-chain` to run the
tenant-scoped verifier. It checks at most 10,000 rows and returns `valid`,
`checked_events`, `checked_at`, and `online_limit`. `checked_events` counts rows
examined, including the first invalid row when corruption is found. A larger chain returns HTTP 413
without reporting a partial verification as complete. The check is read-only and does
not add an audit event (which would change the chain during verification). The route
uses the authenticated tenant and existing PostgreSQL RLS; clients cannot select a
different organization. This is an on-demand online check, not a scheduled monitor,
external anchor, or alerting service.

## Sensitive data

Audit metadata has a 4 KiB serialized cap, maximum nesting depth, JSON-only values,
and a strict set of allowed keys. Other keys and fields matching password, secret,
token, API-key, authorization, cookie, credential, ciphertext, or key patterns are
redacted. Common bearer, JWT, API-key, private-key, GitHub-token, and Stripe-key
shapes are redacted even under an allowed field. Do not pass request bodies, secret
values, authorization headers, cookies, vault ciphertext, or decision justifications
to `record_event`.

API-key events identify the database key ID, never the key string. Vault events keep
only the secret ID, type, and key version. User-agent input is truncated and filtered;
the client peer address is used only when it is a parseable IP. `X-Forwarded-For` and
similar headers are not trusted. Server-generated UUID request IDs provide
correlation without accepting caller-controlled identifiers.

## Failure and limitations

Audit writes for database-backed mutations share the business transaction; a failed
audit insert aborts the operation. Authorization-denial records are separate writes
after the denied response has been determined. If that write fails, the caller gets a
generic 503 rather than a false claim that the event was recorded. Login/authentication
failures before a verified tenant exists cannot be safely attached to a tenant audit
stream and are not recorded here.

P07 external action execution cannot share a PostgreSQL transaction. If a provider
acts and the subsequent transaction or audit write fails, the provider action may
have occurred without a committed result event; the API returns a safe error and does
not claim successful auditing. Audit retention, legal hold, export, and deletion are
later-phase work. There is no audit deletion endpoint; the organization foreign key
also prevents ordinary deletion while evidence remains.
