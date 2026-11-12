"""Persist policy action requests without retaining scan content."""

import json
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import create_engine, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine

from dlp_platform.actions.interfaces import ActionExecutor, UnavailableActionExecutor, resolve_action
from dlp_platform.approvals.notifier_interface import ApprovalNotifier, UnconfiguredApprovalNotifier
from dlp_platform.contracts.common import PolicyAction
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.scan.interfaces import PolicyDecision
from dlp_platform.tables import ACTIONS, APPROVALS


class ActionProcessor:
    def __init__(
        self,
        engine: Engine,
        approval_ttl: timedelta = timedelta(hours=24),
        executor: ActionExecutor | None = None,
        notifier: ApprovalNotifier | None = None,
    ) -> None:
        self.engine = engine
        self.approval_ttl = approval_ttl
        self.executor = executor or UnavailableActionExecutor()
        self.notifier = notifier or UnconfiguredApprovalNotifier()

    @classmethod
    def from_url(
        cls,
        database_url: str,
        notifier: ApprovalNotifier | None = None,
        executor: ActionExecutor | None = None,
    ) -> "ActionProcessor":
        return cls(
            create_engine(database_url, pool_pre_ping=True),
            notifier=notifier,
            executor=executor,
        )

    def process_policy_decision(
        self, decision: PolicyDecision, request: ScanRequest, principal: Principal
    ) -> PolicyDecision:
        decision = self._apply_approved_override(decision, request, principal)
        plan = resolve_action(decision.action)
        if plan is None:
            return decision
        trusted_metadata = request._trusted_action_metadata
        if trusted_metadata.get("provider") in {
            "aws_s3",
            "google_cloud_storage",
        } and decision.action in {PolicyAction.REVOKE_SHARE, PolicyAction.QUARANTINE}:
            return PolicyDecision(
                action=decision.action,
                reason=f"{decision.reason} P07 action status=failed."[:2048],
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                matched_conditions=decision.matched_conditions,
                evaluation_trace=decision.evaluation_trace,
            )
        if decision.action is PolicyAction.REVOKE_SHARE and (
            trusted_metadata.get("provider")
            not in {"google_drive", "microsoft_onedrive", "microsoft_sharepoint"}
            or not all(
                trusted_metadata.get(key)
                for key in ("connector_id", "drive_object_id", "permission_id")
            )
            or (
                trusted_metadata.get("provider") != "google_drive"
                and not trusted_metadata.get("drive_id")
            )
        ):
            return PolicyDecision(
                action=decision.action,
                reason=f"{decision.reason} P07 action status=failed."[:2048],
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                matched_conditions=decision.matched_conditions,
                evaluation_trace=decision.evaluation_trace,
            )
        org_id = str(principal.organization_id)
        request_id = str(request.request_id)
        action_id = uuid5(NAMESPACE_URL, f"dlp-p07:{org_id}:{request_id}:{decision.action.value}")
        approval_id = uuid5(NAMESPACE_URL, f"dlp-p07-approval:{action_id}")
        now = datetime.now(UTC)
        metadata = {
            key: value
            for key, value in {
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
            }.items()
            if value is not None
        }
        # Only backend code can set this Pydantic PrivateAttr. Client-controlled
        # context is never an authority to trigger an external connector action.
        for key in (
            "provider",
            "connector_id",
            "drive_object_id",
            "permission_id",
            "drive_id",
            "site_id",
        ):
            value = request._trusted_action_metadata.get(key)
            if isinstance(value, str) and 0 < len(value) <= 1024:
                metadata[key] = value
        if request._trusted_action_metadata.get("provider") in {
            "google_drive",
            "microsoft_onedrive",
            "microsoft_sharepoint",
        }:
            metadata["organization_id"] = org_id
        # P05 explanations contain policy identifiers and condition names only. Keep
        # the saved justification bounded and never persist request content/findings.
        justification = decision.reason[:1000]
        with self.engine.begin() as connection:
            if connection.dialect.name == "postgresql":
                connection.execute(text("SET LOCAL ROLE authenticated"))
                connection.execute(
                    text("SELECT set_config('request.jwt.claims', :claims, true)"),
                    {
                        "claims": json.dumps(
                            {
                                "role": "authenticated",
                                "aud": "authenticated",
                                "org_id": org_id,
                                "app_role": principal.role.value,
                            }
                        )
                    },
                )
            member_id = connection.execute(
                text("SELECT id FROM members WHERE organization_id=:org AND auth_subject_id=:sub"),
                {"org": org_id, "sub": principal.subject_id},
            ).scalar_one_or_none()
            if member_id is None:
                raise RuntimeError("verified scan principal has no tenant member")
            insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
            inserted = connection.execute(
                insert(ACTIONS)
                .values(
                    id=str(action_id),
                    org_id=org_id,
                    request_id=request_id,
                    policy_id=decision.policy_id,
                    policy_version=int(decision.policy_version)
                    if decision.policy_version
                    else None,
                    requested_by=str(member_id),
                    action=decision.action.value,
                    status=plan.status,
                    justification=justification,
                    metadata=metadata,
                    created_at=now,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=["org_id", "request_id", "action"])
            ).rowcount
            if plan.requires_approval:
                connection.execute(
                    insert(APPROVALS)
                    .values(
                        id=str(approval_id),
                        org_id=org_id,
                        action_id=str(action_id),
                        requested_by=str(member_id),
                        status="pending",
                        justification=justification,
                        expires_at=now + self.approval_ttl,
                        created_at=now,
                    )
                    .on_conflict_do_nothing(index_elements=["action_id"])
                )
            stored_status = connection.execute(
                select(ACTIONS.c.status).where(
                    ACTIONS.c.id == str(action_id), ACTIONS.c.org_id == org_id
                )
            ).scalar_one()
        if inserted == 1 and not plan.requires_approval:
            try:
                execution = self.executor.execute(str(action_id), decision.action, metadata)
                action_status = execution.status
            except Exception:
                action_status = "failed"
            if action_status not in {
                "pending_executor",
                "succeeded",
                "failed",
                "executing",
                "cancelled",
            }:
                action_status = "failed"
            with self.engine.begin() as connection:
                if connection.dialect.name == "postgresql":
                    connection.execute(text("SET LOCAL ROLE authenticated"))
                    connection.execute(
                        text("SELECT set_config('request.jwt.claims', :claims, true)"),
                        {
                            "claims": json.dumps(
                                {
                                    "role": "authenticated",
                                    "aud": "authenticated",
                                    "org_id": org_id,
                                    "app_role": principal.role.value,
                                }
                            )
                        },
                    )
                connection.execute(
                    update(ACTIONS)
                    .where(ACTIONS.c.id == str(action_id), ACTIONS.c.org_id == org_id)
                    .values(status=action_status, updated_at=datetime.now(UTC))
                )
            decision = PolicyDecision(
                action=decision.action,
                reason=f"{decision.reason} P07 action status={action_status}."[:2048],
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                matched_conditions=decision.matched_conditions,
                evaluation_trace=decision.evaluation_trace,
            )
        elif inserted == 1 and plan.requires_approval:
            with suppress(Exception):
                self.notifier.notify_approvers(org_id, str(approval_id))
            decision = PolicyDecision(
                action=decision.action,
                reason=f"{decision.reason} P07 action status=pending_approval."[:2048],
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                matched_conditions=decision.matched_conditions,
                evaluation_trace=decision.evaluation_trace,
            )
        elif inserted == 0:
            # A connector sync may be retried after its checkpoint commit failed.
            # Reuse the durable action outcome so successful external work is not
            # repeated and the retried sync can advance its cursor.
            decision = PolicyDecision(
                action=decision.action,
                reason=f"{decision.reason} P07 action status={stored_status}.",
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                matched_conditions=decision.matched_conditions,
                evaluation_trace=decision.evaluation_trace,
            )
        return decision

    def _apply_approved_override(
        self, decision: PolicyDecision, request: ScanRequest, principal: Principal
    ) -> PolicyDecision:
        if decision.action.value != "block":
            return decision
        org_id = str(principal.organization_id)
        claims = json.dumps(
            {
                "role": "authenticated",
                "aud": "authenticated",
                "org_id": org_id,
                "app_role": principal.role.value,
            }
        )
        with self.engine.begin() as connection:
            if connection.dialect.name == "postgresql":
                connection.execute(text("SET LOCAL ROLE authenticated"))
                connection.execute(
                    text("SELECT set_config('request.jwt.claims', :claims, true)"),
                    {"claims": claims},
                )
            requester_id = connection.execute(
                text("SELECT id FROM members WHERE organization_id=:org AND auth_subject_id=:sub"),
                {"org": org_id, "sub": principal.subject_id},
            ).scalar_one_or_none()
            if requester_id is None:
                return decision
            lock_suffix = " FOR UPDATE OF a" if connection.dialect.name == "postgresql" else ""
            approved = connection.execute(
                text(
                    """
                    SELECT a.id FROM dlp_actions AS a
                    JOIN dlp_approvals AS p ON p.action_id=a.id AND p.org_id=a.org_id
                    WHERE a.org_id=:org AND a.request_id=:request_id
                      AND a.action='user_override' AND a.status='approved'
                      AND p.status='approved' AND p.expires_at > :now
                      AND a.policy_id=:policy_id AND a.policy_version=:policy_version
                      AND a.requested_by=:requester
                """
                    + lock_suffix
                ),
                {
                    "org": org_id,
                    "request_id": str(request.request_id),
                    "policy_id": decision.policy_id,
                    "policy_version": int(decision.policy_version)
                    if decision.policy_version
                    else None,
                    "requester": str(requester_id),
                    "now": datetime.now(UTC),
                },
            ).scalar_one_or_none()
            if approved is None:
                return decision
            connection.execute(
                update(ACTIONS)
                .where(ACTIONS.c.id == approved, ACTIONS.c.org_id == org_id)
                .values(status="succeeded", updated_at=datetime.now(UTC))
            )
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            reason=f"Approved user override applied to policy decision: {decision.reason}"[:2048],
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            matched_conditions=decision.matched_conditions,
            evaluation_trace=decision.evaluation_trace,
        )
