# P02 decisions

| Decision | Status | Notes |
|---|---|---|
| JWT uses one configured verifier source: HS256 secret or RS256/ES256 JWKS. | [REC] | Prevents key-source and algorithm ambiguity. |
| Require `exp`, `sub`, and `aud`; default audience is `authenticated`. | [SRC]/[REC] | Signature, expiry, audience, and small leeway are explicit; `sub` and required-claim enforcement are implementation details. |
| Use `members.role` as authorization authority. | [REC] | Token role claims are not authoritative; the membership must match the verified subject and organization. |
| If JWT omits org claim, accept only one matching organization membership. | [REC] | Supports standard provider tokens without allowing body-selected tenant context. Ambiguous membership is rejected. |
| Owner/Admin manage API-key metadata; all roles can read own Principal. | [REC] | The source names a matrix but supplies no cells. |
| Scopes are `identity:read`, `api_keys:read`, `api_keys:write`. | [REC] | Closed, validated vocabulary; source does not specify strings. |
| API key has no expiry date. | NOT SPECIFIED IN SOURCE | Revisit with product owner; table has no expiry column in source. |
| Cross-org revoke lookup returns generic 403. | [SRC] | The source explicitly requires wrong-organization key access to return 403; no resource details are included. |
| API key hash is SHA-256 over the full random token. | [REC] | Matches the source's accepted long-random-key hashing approach. |

See `docs/decisions.md` for project-wide history. No P03 RLS or rate limit was added.
