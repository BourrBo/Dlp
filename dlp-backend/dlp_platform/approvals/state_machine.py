"""Deterministic approval transitions."""

from datetime import datetime

FINAL_STATES = frozenset({"approved", "rejected", "expired", "cancelled"})


def refreshed_state(status: str, expires_at: datetime, now: datetime) -> str:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=now.tzinfo)
    if status in {"pending", "escalated"} and expires_at <= now:
        return "expired"
    return status


def decide(status: str, decision: str) -> str:
    if status not in {"pending", "escalated"}:
        raise ValueError("approval is already final")
    if decision not in {"approved", "rejected"}:
        raise ValueError("invalid approval decision")
    return decision
