"""Time-limited, tenant-scoped allow exceptions for matched P05 policies."""

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.engine import Engine

from dlp_platform.contracts.common import PolicyAction
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.matching import policy_matches, resolve_destination_class
from dlp_platform.policy.models import Destination, validate_conditions
from dlp_platform.tables import EXCEPTIONS


def exception_scope_matches(
    scope: dict[str, Any],
    request: ScanRequest,
    principal: Principal,
    findings: tuple[Any, ...],
    destinations: tuple[Destination, ...],
) -> bool:
    checked = validate_conditions(scope)
    destination_class = resolve_destination_class(request.destination, destinations)
    return bool(checked) and policy_matches(
        checked, request, principal, findings, destination_class
    )


class ExceptionRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def active_for_tenant(self, organization_id: UUID, at: datetime) -> tuple[dict[str, Any], ...]:
        try:
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
                                    "org_id": str(organization_id),
                                }
                            )
                        },
                    )
                rows = (
                    connection.execute(
                        select(EXCEPTIONS)
                        .where(
                            EXCEPTIONS.c.org_id == str(organization_id),
                            EXCEPTIONS.c.enabled.is_(True),
                            EXCEPTIONS.c.expires_at > at,
                        )
                        .order_by(EXCEPTIONS.c.expires_at, EXCEPTIONS.c.id)
                    )
                    .mappings()
                    .all()
                )
            return tuple(dict(row) for row in rows)
        except Exception as exc:
            raise RuntimeError("exception configuration could not be loaded") from exc


def apply_exceptions(
    *,
    policies: tuple[Policy, ...],
    exceptions: tuple[dict[str, Any], ...],
    request: ScanRequest,
    principal: Principal,
    findings: tuple[Any, ...],
    destinations: tuple[Destination, ...],
) -> tuple[tuple[Policy, ...], tuple[tuple[str, str], ...]]:
    """Override only each targeted policy's action; other strict P05 matches remain."""
    applicable: dict[str, list[str]] = {}
    for item in exceptions:
        target = str(item["policy_id"])
        policy = next((p for p in policies if str(p.policy_id) == target and p.enabled), None)
        if policy is None:
            continue
        if not policy_matches(
            policy.conditions,
            request,
            principal,
            findings,
            resolve_destination_class(request.destination, destinations),
        ):
            continue
        if exception_scope_matches(item["scope"], request, principal, findings, destinations):
            applicable.setdefault(target, []).append(str(item["id"]))

    modified: list[Policy] = []
    applied: list[tuple[str, str]] = []
    for policy in policies:
        ids = applicable.get(str(policy.policy_id), [])
        if ids:
            policy = policy.model_copy(update={"action": PolicyAction.ALLOW})
            applied.extend((exception_id, str(policy.policy_id)) for exception_id in sorted(ids))
        modified.append(policy)
    return tuple(modified), tuple(sorted(applied))
