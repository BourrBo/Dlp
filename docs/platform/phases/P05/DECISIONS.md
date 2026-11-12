# P05 decisions and traceability

| Decision | Choice | Basis |
|---|---|---|
| Condition dimensions | channel, destination class, user group, data type, classification, volume, file type | [SRC] P2 final phase plan |
| Policy actions | allow, warn, block, log | [SRC] P2 final phase plan |
| Conflicting policies | strictest matching action wins | [SRC] P2 final phase plan |
| Action strictness | block > warn > log > allow | [REC] Recommended order where the source specifies “strictest” but no numeric ranking |
| Same-action tie | lower numeric priority wins, then ascending policy UUID | [REC] Deterministic tie-breaks; source requests priority and equal-priority handling but does not define direction |
| Condition combination | AND between keys; OR among values in one list | [REC] Conventional, deterministic interpretation; no expression language |
| No matching rule | allow with an explicit default reason | [REC] No-match behavior is unspecified in source |
| Volume | exact UTF-8 byte count of the ephemeral input | [REC] No comparison operators or volume units are specified; policy values are non-negative byte counts |
| User group | use the verified P01 Principal role until a trusted group model exists | [REC] P01 has roles but no group claim or membership contract |
| File type | read from `ScanRequest.context.file_type` | [REC] P01 context is the existing typed metadata extension point |
| Finding dimensions | data type and classification must occur on the same normalized Finding | [REC] Avoids combining unrelated findings into one match |
| Domain patterns | case-insensitive normalized host; exact before wildcard, then longest pattern, class and UUID | [REC] Deterministic resolution |
| Wildcard apex | `*.example.com` matches subdomains, not `example.com` | [REC] Explicit boundary choice tested |
| Repository pattern | exact, case-insensitive repository path; wildcards rejected | [REC] No repository glob grammar is defined |
| Policy current version | starts at 1 and increments on update; no historical snapshot | [REC] Minimal concurrency/explanation metadata; snapshots and rollback belong to P06 |
| Configuration size | max 1000 policies and 1000 destinations per tenant; max 100 values per list condition | [REC] Source requires bounded evaluation but gives no numeric limits |
| Policy route scopes | reads use existing `identity:read`; writes use existing `api_keys:write` and require Owner/Admin | [REC] Keeps P02's closed scope set unchanged |
| Evaluation failure | fail closed through P04's existing policy failure path | [VER] P04 maps policy evaluation failures to a service error; it never converts them to allow |
| Persistence/RLS | PostgreSQL-only revision 0005, forced RLS, tenant claim on reads, Owner/Admin claim on writes | [SRC] Phase plan schema and isolation requirements |

The engine evaluates only fixed, validated condition keys and values. It never accepts
Python, SQL, regular-expression or general-purpose expression input from a policy.

## [UNV] / NOT SPECIFIED IN SOURCE

The source does not define a custom user-group model, volume operators or units, the
no-match result, priority direction, destination wildcard apex behavior, or numeric
configuration limits. The recommended choices above make each behavior explicit and
testable. P05 also does not define whether policy version history is retained; only the
current version counter is represented here, with immutable history deferred to P06.
