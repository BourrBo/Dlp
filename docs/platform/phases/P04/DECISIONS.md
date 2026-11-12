# P04 decisions

| Decision | Status | Rationale |
|---|---|---|
| Keep P01 request/result/finding contracts unchanged | [SRC] | Existing v1.0.0 boundaries are sufficient |
| Add PostgreSQL idempotency table with forced tenant RLS | [REC] | Source leaves storage unspecified and recommends Redis TTL or a small RLS table; table allows atomic event/result commit without new service infrastructure |
| Use request_id as tenant-scoped idempotency key | [REC] | P01 contract already supplies stable request UUID; no extra header/field is invented |
| Only ALLOW passes `/gate/check` | [REC] | Gate pass semantics are not specified; conservative pass rule is explicit |
| Fail closed when production pipeline adapters are absent | [REC] | Prevents the fake policy from being mistaken for production evaluation |
| Limit content to 1 MiB UTF-8 by default | [REC] | Source requires request size limits but does not define the number |
| Do not expire idempotency records | NOT SPECIFIED IN SOURCE | No retention policy is invented; retention policy remains a future owner decision |
