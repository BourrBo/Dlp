"""Tenant-filtered policy/destination loading for one scan evaluation."""

import json
from uuid import UUID

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine

from dlp_platform.contracts.policy import Policy
from dlp_platform.policy.engine import PolicyEvaluationError
from dlp_platform.policy.models import Destination, validate_conditions
from dlp_platform.tables import DESTINATIONS, POLICIES

MAX_TENANT_POLICIES = 1000
MAX_TENANT_DESTINATIONS = 1000


class PolicyRepository:
    """Loads one tenant's enabled policies and destination map with two bounded queries."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    @classmethod
    def from_url(cls, database_url: str) -> "PolicyRepository":
        return cls(create_engine(database_url, pool_pre_ping=True))

    def load(self, organization_id: UUID) -> tuple[tuple[Policy, ...], tuple[Destination, ...]]:
        org_id = str(organization_id)
        try:
            with self.engine.begin() as connection:
                if connection.dialect.name == "postgresql":
                    connection.execute(text("SET LOCAL ROLE authenticated"))
                    connection.execute(
                        text("SELECT set_config('request.jwt.claims', :claims, true)"),
                        {
                            "claims": json.dumps(
                                {"role": "authenticated", "aud": "authenticated", "org_id": org_id}
                            )
                        },
                    )
                policy_rows = (
                    connection.execute(
                        select(POLICIES)
                        .where(POLICIES.c.org_id == org_id, POLICIES.c.enabled.is_(True))
                        .order_by(POLICIES.c.priority, POLICIES.c.id)
                        .limit(MAX_TENANT_POLICIES + 1)
                    )
                    .mappings()
                    .all()
                )
                destination_rows = (
                    connection.execute(
                        select(DESTINATIONS)
                        .where(DESTINATIONS.c.org_id == org_id)
                        .order_by(
                            DESTINATIONS.c.kind,
                            DESTINATIONS.c.pattern,
                            DESTINATIONS.c.id,
                        )
                        .limit(MAX_TENANT_DESTINATIONS + 1)
                    )
                    .mappings()
                    .all()
                )
            if len(policy_rows) > MAX_TENANT_POLICIES:
                raise PolicyEvaluationError("tenant policy limit exceeded")
            if len(destination_rows) > MAX_TENANT_DESTINATIONS:
                raise PolicyEvaluationError("tenant destination limit exceeded")
            policies = tuple(
                Policy(
                    policy_id=UUID(row["id"]),
                    organization_id=UUID(row["org_id"]),
                    name=row["name"],
                    enabled=row["enabled"],
                    priority=row["priority"],
                    conditions=validate_conditions(row["conditions"]),
                    action=row["action"],
                    version=row["version"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
                for row in policy_rows
            )
            destinations = tuple(
                Destination(
                    destination_id=UUID(row["id"]),
                    organization_id=UUID(row["org_id"]),
                    destination_class=row["destination_class"],
                    kind=row["kind"],
                    pattern=row["pattern"],
                )
                for row in destination_rows
            )
            return policies, destinations
        except Exception as exc:
            raise PolicyEvaluationError("policy configuration could not be loaded") from exc
