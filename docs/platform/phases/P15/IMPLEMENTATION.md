# P15 — Public API v1 and webhook signing

## Public API

P15 adds an explicit `/api/v1` namespace, leaving existing internal routes and their paths unchanged. The initial surface is deliberately read-only:

- `GET /api/v1/policies` returns a bounded page of policy metadata.
- `GET /api/v1/policies/{policy_id}` returns one policy within the authenticated tenant.

Responses use explicit Pydantic models and omit policy conditions and database-only data. List filters are limited to `enabled` and the policy action enum. Pagination defaults to 50 rows, caps at 100, and bounds offsets at 1,000,000. Sorting is fixed by creation time and ID. There are no writes, so idempotency keys are not applicable to this surface.

Authentication reuses P02 Bearer API keys, including hashing, revocation and creator membership checks. Public routes require a service/API-key Principal plus the existing `identity:read` permission scope. A valid JWT alone is rejected. Tenant selection comes only from the verified API key; an `org_id` query parameter is ignored. Database queries also carry the same transaction-local claim and run under existing PostgreSQL RLS.

The existing P03 limiter is applied per API-key identity and organization. The configured backend may be process-local memory or Valkey; memory mode is per process and is not claimed as distributed. `429` responses include a `Retry-After` value. No new limiter or API-key table was added.

Public API failures use `{ "error": { "code", "message", "request_id" } }`; messages do not contain exception details. Correlation IDs reuse existing middleware and are returned as `X-Request-ID` on successful and error responses. OpenAPI describes the bearer security scheme, success/error envelopes, pagination and request/rate-limit headers. Raw audit endpoints, admin routes, vault values, SSO/SCIM credentials, scan internals, actions and approvals are intentionally not exposed in this initial public contract.

## Webhook signing foundation

`app.public_api.webhooks.WebhookSigner` is a reusable signing/verifying interface for later delivery/receiving callers. It does not know about subscriptions and creates no P4 subscription records. Secrets are referenced by P09 Vault UUID and read through `SecretVault.get_for_trusted_service` for the authenticated organization; only `generic_secret` vault entries are accepted. P09 remains responsible for creation, ciphertext storage, rotation and audit. No plaintext secret column or separate cryptography was added.

Signature header format is `X-DLP-Webhook-Signature: v1;t=<unix-seconds>;sig=<lowercase-hex>`. The MAC is HMAC-SHA256 over the ASCII timestamp, a literal period, then the exact raw body bytes. Verification uses `hmac.compare_digest`; parsed or re-serialized JSON is never used. The default freshness tolerance is 300 seconds, configurable through `DLP_WEBHOOK_TOLERANCE_SECONDS` (1–900) when constructed with `WebhookSigner.from_environment`. Payloads are bounded to 1 MiB.

Verification rejects missing/malformed/version-mismatched signatures, stale/future timestamps, modified bodies/timestamps, invalid/unavailable secret references and repeats. Missing/foreign secret references return the same `invalid_signature` result as an incorrect MAC to avoid tenant-existence disclosure. The replay key is a SHA-256 digest of tenant, Vault secret reference and exact signature; the bounded in-memory replay store fails closed when full. It protects a single process only. Multi-worker deployments must inject a shared atomic `ReplayStore` implementation before relying on cross-worker replay rejection. This P15 foundation does not claim shared replay state or dual-key overlap during secret rotation. Vault rotation remains the P09 operation and the signer reads the current Vault value by reference each call.

The verifier returns only a boolean and safe code; it never returns an expected MAC or secret. It is a library primitive, not an HTTP receiver endpoint. Public API GETs are not audited individually. Vault secret changes continue to use P09/P10 audit behavior; raw bodies, signatures, API keys and secret values are not audited by P15.

## Persistence and P16 handoff

No P15 migration is needed: P02 API key state, P05 policy state, P09 Vault state and P10 audit state are reused. P16 may call the public policy contract or the signer with a tenant-bound API key/Vault reference. A future shared replay store must implement the documented atomic claim contract; P16 must not supply an organization ID independently of authenticated tenant context. No P16 connector, SDK, webhook subscription manager, P20 gateway or P21 general hardening work is included.

## Boundaries

- Public API v1 is currently read-only and only exposes policy metadata.
- No idempotency store is needed until a public write operation is introduced.
- Rate limiting and replay protection are only process-wide in memory mode; Valkey rate limiting is available through the existing limiter. Replay storage has an injection boundary but no Valkey implementation yet.
- Webhook secret rotation is Vault-managed; no dual-secret transition is claimed.
- No P16/P20/P21 feature is implemented.

## Validation results (2026-10-23)

- Focused P15 run: 7 passed, zero failed or skipped across local public API/error tests and real PostgreSQL API-key/RLS/Vault signing tests.
- Full P01–P15 backend regression: 300 passed, zero failed, zero skipped; 21 existing dependency deprecation warnings.
- Real PostgreSQL: the P03 configured server reported PostgreSQL 16.15. P15 API key authorization, tenant scoping, direct RLS, Vault ciphertext, audit redaction and webhook signing/replay cases passed. No migration was added, so upgrade/downgrade/re-upgrade do not apply.
- Ruff lint, mypy (89 application source files), pre-commit including hardcoded-secret scan, pip-audit and `git diff --check` passed. Repository `ruff format --check .` still reports 12 pre-existing files outside P15. Standalone Gitleaks is unavailable; pre-commit scanning passed.
- Frontend lint, typecheck, build and 16 tests passed; no frontend files changed.
- P14 tag `p2-p14-complete` remained at commit `5b52e153327e33a4098f7bab677999f3405dc7cd` during P15 work.

No P16 implementation was started. Remaining limitations are process-local in-memory replay state, no P4 subscription/delivery queue, read-only API with no idempotent writes, and no standalone Gitleaks executable.
