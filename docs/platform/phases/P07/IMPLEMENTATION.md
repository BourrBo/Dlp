# P07 — Advanced actions and approvals

## Source requirements and decisions

The P2 week plan names `redact`, `quarantine`, `revoke_share`, and
`require_approval`. It assigns action interfaces to P07 and the real redaction
engine and storage connectors to P1/P16–P18. The P2 phase plan also calls for a
justified user override, pending/approved/rejected/expired/escalated approval
states, timeout, and an approver notification handoff to P4. Names and numeric
values not fixed by those sources are implementation decisions described below.

Implementation decisions:

- Existing `allow`, `log`, `warn`, and `block` behavior remains intact. P07 adds the
  four source-defined actions already present in the frozen P01 `PolicyAction` enum.
- To retain deterministic strictest-wins evaluation, the P07-only order is
  `block` > `quarantine` = `revoke_share` > `redact` > `require_approval` > `warn` >
  `log` > `allow`. This ordering is an implementation decision because the source
  does not rank the new actions.
- A user override is a separately justified approval request tied to a scan request
  ID and exact policy/version. The requester cannot approve it, and only that same
  requester can consume it. An approved, unexpired override applies once when that
  same request ID and policy version are first evaluated; the scan response then
  reports `allow` and the internal override action becomes `succeeded`. It does not
  rewrite the original policy or an earlier idempotently cached scan result.
- A `require_approval` policy decision creates a pending action and approval. Approval
  changes the action to `approved`; it does not invent another external action.
- An unavailable redact/quarantine/revoke-share executor returns
  `pending_executor`. No P1 or P16–P18 action is claimed to have happened.
- Self-approval is prohibited. Owner/Admin are the only roles granted the explicit
  `approvals:decide` permission; API-key approvers also need that scope.
- Approval TTL is 24 hours; escalated status begins at 12 hours. These are defaults,
  not source-specified service-level targets. The first approval read or decision
  after a threshold refreshes state. P07 has no background worker.
- Approval notifications use a replaceable P4-owned notifier interface. The local
  default says `not_configured`; no Slack/email message is sent in P07.
- P07 stores safe policy identifiers, version, state, justification and timestamps.
  It never stores raw scan content or findings. P05 explanations contain identifiers
  and condition names only.

## Action and approval behavior

`ActionProcessor` receives structured `PolicyDecision` output in the shared P04 scan
pipeline after P05/P06 evaluation. Core P05 actions do not create P07 records.
Advanced actions create deterministic action IDs derived from tenant, request ID, and
action. A database uniqueness constraint provides retry-safe creation. For direct
external actions, the replaceable `ActionExecutor` receives the action ID as its
idempotency key. The default executor returns `pending_executor` for external work and
never reports success. Executor exceptions and invalid statuses become `failed`.

`require_approval` creates one `dlp_actions` row and one `dlp_approvals` row. Approval
and rejection use a transaction and `SELECT ... FOR UPDATE`, so only one final decision
can win. Decisions after expiry, cancellation, or another decision return 409. An
approved external action is passed to the executor; with the P07 default its state
remains `pending_executor`. An approved user override stays `approved` until it is
consumed by a scan with the matching request ID.

The escalation threshold is applied lazily on read or decision. State may become
`escalated`, after which an authorized approver may approve/reject it. Expiry applies
at the exact `expires_at` boundary. Cancellation is allowed to the requester or an
authorized approver. No unbounded retry loop or job queue is introduced.

## Authorization and API

The P02 permission model is extended with `approvals:decide`, assigned only to
Owner/Admin through the existing role map. Reads require `identity:read`; creating an
approval requires `scan:request`; approve/reject decisions require `approvals:decide`
and Owner/Admin. A requester cannot approve their own request. Tenant identity always
comes from the verified Principal. Unknown body fields such as `org_id` are rejected.

- `POST /approvals` creates an idempotent, tenant-scoped request for
  `redact`, `quarantine`, `revoke_share`, or a justified `user_override`.
- `GET /approvals` and `GET /approvals/{approval_id}` return tenant-local safe status.
- `POST /approvals/{approval_id}/approve`, `/reject`, and `/cancel` perform guarded
  state transitions.
- `GET /actions` returns tenant-local action IDs, policy references, status, and safe
  justification.

All routes use authentication, the existing rate limiter, permission checks, Pydantic
validation, tenant predicates, and safe 404/409/422 errors. Responses omit raw scan
input, findings, credentials, and internal exceptions.

## Database and RLS

Migration `0007_advanced_actions_approvals` creates `dlp_actions` and `dlp_approvals`,
their constraints, tenant indexes, tenant-consistent member/policy/action foreign
keys, idempotency uniqueness, lifecycle checks, and forced PostgreSQL RLS. Both
tables are hidden with no tenant claim and reject forged tenant inserts. Migration
downgrade removes only P07 tables and restores the P06 policy-action constraint; it
refuses to downgrade while advanced-action policies remain configured.

## P08 handoff

P08 can consume `/actions` and `/approvals`, including action/approval IDs, state,
request ID, policy/version reference, justification and timestamps. It should display
`pending_executor` as waiting for a connector capability, never as completed. Approval
notification delivery is not implemented; the P4 notifier interface is the handoff.
There is no action retry endpoint or durable audit log in P07.

## Known limitations

- External redaction, quarantine and share revocation are not implemented; P1/P16–P18
  own those executors.
- Slack/email delivery and proactive escalation scheduling are owned by P4. P07 only
  exposes a notifier interface and lazily updates escalation state.
- No durable P10 audit log is created. Approval/action rows preserve current workflow
  state and decision metadata only.
- `user_override` applies to a future first evaluation carrying the same request ID;
  it cannot change a prior scan result already returned from P04 idempotency storage.
- The action executor contract is idempotency-keyed, but no distributed queue or
  automatic retry worker exists.
