"""Explicit handoff boundary for P1/P4-owned stores outside the P2 schema."""

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID


class TenantDataLifecycleAdapter(Protocol):
    """Idempotent operations supplied by a feature that owns external tenant data."""

    name: str

    def delete_organization(self, organization_id: UUID) -> None: ...

    def export_subject(self, organization_id: UUID, member_id: UUID) -> dict[str, object]: ...


_adapters: list[TenantDataLifecycleAdapter] = []


def register_adapter(adapter: TenantDataLifecycleAdapter) -> None:
    if any(item.name == adapter.name for item in _adapters):
        raise ValueError("A tenant lifecycle adapter with this name is already registered")
    _adapters.append(adapter)


def clear_adapters() -> None:
    """Reset adapters for isolated tests and application lifecycle management."""
    _adapters.clear()


def adapters() -> Sequence[TenantDataLifecycleAdapter]:
    return tuple(_adapters)
