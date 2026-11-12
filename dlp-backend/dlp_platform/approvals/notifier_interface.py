"""P4-owned notification handoff; P07 never sends Slack or email directly."""

from typing import Protocol


class ApprovalNotifier(Protocol):
    def notify_approvers(self, organization_id: str, approval_id: str) -> str: ...


class UnconfiguredApprovalNotifier:
    def notify_approvers(self, organization_id: str, approval_id: str) -> str:
        del organization_id, approval_id
        return "not_configured"
