"""Replaceable action execution contracts; unavailable connectors never report success."""

from dataclasses import dataclass
from typing import Protocol

from dlp_platform.contracts.common import PolicyAction


@dataclass(frozen=True)
class ActionPlan:
    action: PolicyAction
    status: str
    requires_approval: bool


@dataclass(frozen=True)
class ActionExecutionResult:
    status: str
    detail: str


class ActionExecutor(Protocol):
    def execute(
        self, idempotency_key: str, action: PolicyAction, safe_metadata: dict[str, str]
    ) -> ActionExecutionResult: ...


class UnavailableActionExecutor:
    """Safe default for P16+ actions. It does not call external systems."""

    def execute(
        self, idempotency_key: str, action: PolicyAction, safe_metadata: dict[str, str]
    ) -> ActionExecutionResult:
        del idempotency_key, safe_metadata
        if action in {PolicyAction.REDACT, PolicyAction.QUARANTINE, PolicyAction.REVOKE_SHARE}:
            return ActionExecutionResult("pending_executor", "No external executor is configured")
        return ActionExecutionResult("failed", "No executor is configured for this action")


def resolve_action(action: PolicyAction) -> ActionPlan | None:
    if action in {PolicyAction.ALLOW, PolicyAction.WARN, PolicyAction.BLOCK, PolicyAction.LOG}:
        return None
    if action is PolicyAction.REQUIRE_APPROVAL:
        return ActionPlan(action, "pending_approval", True)
    if action is PolicyAction.REVOKE_SHARE:
        return ActionPlan(action, "pending_approval", True)
    return ActionPlan(action, "pending_executor", False)
