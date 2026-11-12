"""Exact-match, tenant-scoped suppression rules using existing Finding metadata."""

import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.engine import Engine

from dlp_platform.clock import Clock, SystemClock
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.scan.interfaces import SuppressionOutcome
from dlp_platform.tables import SUPPRESSIONS


def suppression_matches(match: dict[str, Any], finding: Finding) -> bool:
    """Use exact metadata matching only; no regex, glob or raw-content matching."""
    if set(match) == {"fingerprint"}:
        expected = match["fingerprint"]
        return (
            isinstance(expected, str)
            and finding.fingerprint is not None
            and finding.fingerprint == expected
        )
    if set(match) == {"path"}:
        expected = match["path"]
        return (
            isinstance(expected, str)
            and finding.location is not None
            and finding.location.path == expected
        )
    if set(match) == {"pattern"}:
        # P1's detector identifier is a stable pattern identity, not a regex.
        expected = match["pattern"]
        return isinstance(expected, str) and finding.detector == expected
    return False


class DatabaseSuppressor:
    def __init__(self, engine: Engine, clock: Clock | None = None) -> None:
        self.engine = engine
        self.clock = clock or SystemClock()

    def suppress(self, findings: Sequence[Finding], principal: Principal) -> SuppressionOutcome:
        return self.suppress_at(findings, principal, self.clock.now())

    def suppress_at(
        self,
        findings: Sequence[Finding],
        principal: Principal,
        scan_started_at: datetime,
    ) -> SuppressionOutcome:
        if scan_started_at.tzinfo is None:
            raise ValueError("scan start time must be timezone-aware")
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
                                    "org_id": str(principal.organization_id),
                                }
                            )
                        },
                    )
                rows = (
                    connection.execute(
                        select(SUPPRESSIONS)
                        .where(
                            SUPPRESSIONS.c.org_id == str(principal.organization_id),
                            SUPPRESSIONS.c.enabled.is_(True),
                            SUPPRESSIONS.c.expires_at > scan_started_at,
                        )
                        .order_by(SUPPRESSIONS.c.expires_at, SUPPRESSIONS.c.id)
                    )
                    .mappings()
                    .all()
                )
            active = tuple(dict(row) for row in rows)
            suppressed_ids = {
                str(rule["id"])
                for rule in active
                if any(suppression_matches(rule["match"], finding) for finding in findings)
            }
            remaining = tuple(
                finding
                for finding in findings
                if not any(suppression_matches(rule["match"], finding) for rule in active)
            )
            return SuppressionOutcome(remaining, tuple(sorted(suppressed_ids)))
        except Exception as exc:
            raise RuntimeError("suppression configuration could not be evaluated") from exc
