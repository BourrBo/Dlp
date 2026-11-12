"""Authenticated caller context; tenant identity comes from this object."""

from uuid import UUID

from pydantic import Field

from .common import ActorType, AuthMethod, ContractModel, Role


class Principal(ContractModel):
    organization_id: UUID
    subject_id: str = Field(min_length=1, max_length=256)
    actor_type: ActorType
    role: Role
    scopes: tuple[str, ...] = ()
    auth_method: AuthMethod
    member_id: UUID | None = None
    session_id: UUID | None = None
