# Contracts v1 review checklist

This checklist is for review of the proposed implementation baseline in
[contracts-v1.md](contracts-v1.md). Its Git tag is a repository checkpoint, not an
owner approval. No cross-stream reviewer is recorded as approved until they complete
and date this checklist.

| Review owner | Boundary to review | Status | Reviewer/date | Required evidence |
| --- | --- | --- | --- | --- |
| P1 | Finding fields, classification/severity vocabularies, masked evidence, detector and classifier handoffs | Pending | Not recorded | Confirm producer fields and evidence/secret handling |
| P3 | Scan request/result and extraction/detection pipeline handoffs | Pending | Not recorded | Confirm input/output fields, size bounds, error behavior, and content lifetime |
| P4 | Public API/action/approval/connector handoffs used by response and integration flows | Pending | Not recorded | Confirm wire schemas, errors, tenant semantics, and compatibility expectations |
| P2 | Identity, tenant/RLS, policy, audit, Vault, connector and OAuth contracts | Implemented baseline; owner approval pending | Not recorded | Confirm current model/schema snapshots and breaking-change process |

## Review decision

- [ ] Approve this version as written.
- [ ] Approve with listed non-breaking clarifications.
- [ ] Request a breaking or migration proposal before approval.

Record requested changes and rationale below. Approval applies only to the named
version and boundary; it does not imply production acceptance.

### Review notes

None recorded.
