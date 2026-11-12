"""Immutable policy snapshots and deterministic config diffs for P06."""

from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from sqlalchemy import insert
from sqlalchemy.orm import Session

from dlp_platform.contracts.policy import Policy
from dlp_platform.tables import POLICY_VERSIONS

SNAPSHOT_FIELDS = ("name", "enabled", "priority", "conditions", "action")


def policy_snapshot(policy: Policy | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(policy, Policy):
        return {
            "policy_id": str(policy.policy_id),
            "organization_id": str(policy.organization_id),
            "name": policy.name,
            "enabled": policy.enabled,
            "priority": policy.priority,
            "conditions": policy.conditions,
            "action": policy.action.value,
            "version": policy.version,
        }
    return {
        "policy_id": str(policy["id"] if "id" in policy else policy["policy_id"]),
        "organization_id": str(
            policy["org_id"] if "org_id" in policy else policy["organization_id"]
        ),
        "name": policy["name"],
        "enabled": bool(policy["enabled"]),
        "priority": int(policy["priority"]),
        "conditions": policy["conditions"],
        "action": str(policy["action"]),
        "version": int(policy["version"]),
    }


def add_policy_version(
    session: Session,
    *,
    snapshot: dict[str, Any],
    created_by: str,
    created_at: Any,
) -> None:
    session.execute(
        insert(POLICY_VERSIONS).values(
            id=str(uuid4()),
            policy_id=snapshot["policy_id"],
            org_id=snapshot["organization_id"],
            version=snapshot["version"],
            snapshot=snapshot,
            created_by=created_by,
            created_at=created_at,
        )
    )


def diff_snapshots(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return config-only, sorted leaf-level changes without volatile metadata."""
    changes: list[dict[str, Any]] = []

    def compare(path: str, old: Any, new: Any) -> None:
        if isinstance(old, Mapping) and isinstance(new, Mapping):
            for key in sorted(set(old) | set(new)):
                compare(f"{path}.{key}" if path else key, old.get(key), new.get(key))
        elif old != new:
            changes.append({"path": path, "before": old, "after": new})

    for key in SNAPSHOT_FIELDS:
        compare(key, before.get(key), after.get(key))
    return changes
