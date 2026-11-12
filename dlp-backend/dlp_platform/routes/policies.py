"""Tenant-scoped policy CRUD and validation for P05."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session

from dlp_platform.auth.permissions import require_permission, require_role
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.common import DataChannel, PolicyAction, Role
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.database import get_session
from dlp_platform.policy.admin_audit import record_admin_change
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.policy.models import P05_ACTIONS, ConditionValue, validate_conditions
from dlp_platform.policy.repository import MAX_TENANT_POLICIES, PolicyRepository
from dlp_platform.policy.sandbox import evaluate_sandbox, policy_from_snapshot
from dlp_platform.policy.versions import add_policy_version, diff_snapshots, policy_snapshot
from dlp_platform.routes.p06_support import engine_for_session, rate_limit_p06
from dlp_platform.tables import POLICIES, POLICY_VERSIONS

router = APIRouter(prefix="/policies", tags=["policies"], dependencies=[Depends(rate_limit_p06)])
SessionDependency = Annotated[Session, Depends(get_session)]


class PolicyWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    priority: int = Field(default=100, ge=0)
    conditions: dict[str, ConditionValue] = Field(default_factory=dict, max_length=7)
    action: PolicyAction

    @field_validator("conditions")
    @classmethod
    def valid_conditions(cls, value: dict[str, ConditionValue]) -> dict[str, ConditionValue]:
        try:
            validate_conditions(value)
        except ValueError as exc:
            raise ValueError("Invalid policy conditions") from exc
        return value

    @field_validator("action")
    @classmethod
    def valid_action(cls, value: PolicyAction) -> PolicyAction:
        if value not in P05_ACTIONS:
            raise ValueError("Unsupported P05 action")
        return value


class PolicySample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: DataChannel
    destination: str | None = Field(default=None, max_length=2048)
    content: SecretStr
    context: dict[str, str | int | bool] = Field(default_factory=dict, max_length=32)
    findings: list[Finding] = Field(default_factory=list, max_length=100)

    @field_validator("content")
    @classmethod
    def bounded_content(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) > 1_048_576:
            raise ValueError("Sample content exceeds the scan input limit")
        return value


class PolicyTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: PolicyWrite
    sample: PolicySample


class PolicySandboxResult(BaseModel):
    policy_id: UUID
    policy_version: str
    decision: PolicyAction
    reason: str
    evaluation_mode: str
    matched_conditions: tuple[str, ...] = ()
    evaluation_trace: tuple[str, ...] = ()


class PolicyVersionRead(BaseModel):
    policy_id: UUID
    organization_id: UUID
    version: int
    snapshot: dict[str, Any]
    created_by: str
    created_at: datetime


class PolicyDiffRead(BaseModel):
    policy_id: UUID
    from_version: int
    to_version: int
    changes: list[dict[str, Any]]


class RollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_version: int = Field(ge=1)


def _read(principal: CurrentPrincipal) -> None:
    require_permission(principal, Permission.IDENTITY_READ)


def _write(principal: CurrentPrincipal) -> None:
    require_permission(principal, Permission.API_KEYS_WRITE)
    require_role(principal, Role.OWNER, Role.ADMIN)


def _model(row: RowMapping | dict[str, Any]) -> Policy:
    data = dict(row)
    return Policy(
        policy_id=UUID(data["id"]),
        organization_id=UUID(data["org_id"]),
        name=data["name"],
        enabled=data["enabled"],
        priority=data["priority"],
        conditions=data["conditions"],
        action=data["action"],
        version=data["version"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


@router.get("", response_model=list[Policy])
def list_policies(principal: CurrentPrincipal, session: SessionDependency) -> list[Policy]:
    _read(principal)
    rows = session.execute(
        select(POLICIES)
        .where(POLICIES.c.org_id == str(principal.organization_id))
        .order_by(POLICIES.c.priority, POLICIES.c.id)
    ).mappings()
    return [_model(row) for row in rows]


@router.post("", response_model=Policy, status_code=status.HTTP_201_CREATED)
def create_policy(
    body: PolicyWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Policy:
    _write(principal)
    member = session.execute(
        text("SELECT id FROM members WHERE organization_id=:org AND auth_subject_id=:sub"),
        {"org": str(principal.organization_id), "sub": principal.subject_id},
    ).scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=403, detail="Forbidden")
    policy_count = session.execute(
        select(func.count())
        .select_from(POLICIES)
        .where(POLICIES.c.org_id == str(principal.organization_id))
    ).scalar_one()
    if policy_count >= MAX_TENANT_POLICIES:
        raise HTTPException(status_code=409, detail="Tenant policy limit reached")
    now, policy_id = datetime.now(UTC), uuid4()
    values = {
        "id": str(policy_id),
        "org_id": str(principal.organization_id),
        **body.model_dump(mode="json"),
        "version": 1,
        "created_by": member,
        "created_at": now,
        "updated_at": now,
    }
    session.execute(insert(POLICIES).values(**values))
    try:
        add_policy_version(
            session,
            snapshot=policy_snapshot(values),
            created_by=str(member),
            created_at=now,
        )
        record_admin_change(
            session,
            request,
            principal,
            resource="policy",
            resource_id=str(policy_id),
            operation="create",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=503, detail="Policy operation unavailable") from exc
    return _model(values)


def _sample_request(sample: PolicySample) -> ScanRequest:
    return ScanRequest(
        channel=sample.channel,
        destination=sample.destination,
        content=sample.content,
        context=sample.context,
    )


def _version_row(
    session: SessionDependency, policy_id: UUID, version: int, org_id: UUID
) -> PolicyVersionRead:
    row = (
        session.execute(
            select(POLICY_VERSIONS).where(
                POLICY_VERSIONS.c.policy_id == str(policy_id),
                POLICY_VERSIONS.c.version == version,
                POLICY_VERSIONS.c.org_id == str(org_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    data = dict(row)
    return PolicyVersionRead(
        policy_id=UUID(data["policy_id"]),
        organization_id=UUID(data["org_id"]),
        version=data["version"],
        snapshot=data["snapshot"],
        created_by=data["created_by"],
        created_at=data["created_at"],
    )


@router.post("/test", response_model=PolicySandboxResult)
def test_draft_policy(
    body: PolicyTestRequest,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> PolicySandboxResult:
    """Evaluate an unpublished draft against sample metadata without writing state."""
    _write(principal)
    now = datetime.now(UTC)
    draft_id = uuid4()
    draft = Policy(
        policy_id=draft_id,
        organization_id=principal.organization_id,
        name=body.policy.name,
        enabled=body.policy.enabled,
        priority=body.policy.priority,
        conditions=body.policy.conditions,
        action=body.policy.action,
        version=1,
        created_at=now,
        updated_at=now,
    )
    _, destinations = PolicyRepository(engine_for_session(session)).load(principal.organization_id)
    decision, config_version = evaluate_sandbox(
        engine=PolicyEngine(),
        draft=draft,
        request=_sample_request(body.sample),
        principal=principal,
        findings=body.sample.findings,
        destinations=destinations,
        mode="sandbox",
    )
    return PolicySandboxResult(
        policy_id=draft_id,
        policy_version=config_version,
        decision=decision.action,
        reason=decision.reason,
        evaluation_mode="sandbox",
        matched_conditions=decision.matched_conditions,
        evaluation_trace=decision.evaluation_trace,
    )


@router.post("/{policy_id}/versions/{version}/test", response_model=PolicySandboxResult)
def test_historical_policy_version(
    policy_id: UUID,
    version: int,
    sample: PolicySample,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> PolicySandboxResult:
    _read(principal)
    stored = _version_row(session, policy_id, version, principal.organization_id)
    policy = policy_from_snapshot(
        stored.snapshot, created_at=stored.created_at, policy_id=policy_id
    )
    _, destinations = PolicyRepository(engine_for_session(session)).load(principal.organization_id)
    decision, version_label = evaluate_sandbox(
        engine=PolicyEngine(),
        draft=policy,
        request=_sample_request(sample),
        principal=principal,
        findings=sample.findings,
        destinations=destinations,
        mode="historical",
    )
    return PolicySandboxResult(
        policy_id=policy_id,
        policy_version=f"{version_label}:{version}",
        decision=decision.action,
        reason=decision.reason,
        evaluation_mode="historical",
        matched_conditions=decision.matched_conditions,
        evaluation_trace=decision.evaluation_trace,
    )


@router.get("/{policy_id}/versions", response_model=list[PolicyVersionRead])
def list_policy_versions(
    policy_id: UUID, principal: CurrentPrincipal, session: SessionDependency
) -> list[PolicyVersionRead]:
    _read(principal)
    rows = (
        session.execute(
            select(POLICY_VERSIONS)
            .where(
                POLICY_VERSIONS.c.policy_id == str(policy_id),
                POLICY_VERSIONS.c.org_id == str(principal.organization_id),
            )
            .order_by(POLICY_VERSIONS.c.version)
        )
        .mappings()
        .all()
    )
    return [
        PolicyVersionRead(
            policy_id=UUID(row["policy_id"]),
            organization_id=UUID(row["org_id"]),
            version=row["version"],
            snapshot=row["snapshot"],
            created_by=row["created_by"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


@router.get("/{policy_id}/versions/{version}", response_model=PolicyVersionRead)
def get_policy_version(
    policy_id: UUID,
    version: int,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> PolicyVersionRead:
    _read(principal)
    return _version_row(session, policy_id, version, principal.organization_id)


@router.get("/{policy_id}/diff", response_model=PolicyDiffRead)
def get_policy_diff(
    policy_id: UUID,
    from_version: int,
    to_version: int,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> PolicyDiffRead:
    _read(principal)
    before = _version_row(session, policy_id, from_version, principal.organization_id)
    after = _version_row(session, policy_id, to_version, principal.organization_id)
    return PolicyDiffRead(
        policy_id=policy_id,
        from_version=from_version,
        to_version=to_version,
        changes=diff_snapshots(before.snapshot, after.snapshot),
    )


@router.post("/{policy_id}/rollback", response_model=Policy)
def rollback_policy(
    policy_id: UUID,
    body: RollbackRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Policy:
    _write(principal)
    current = (
        session.execute(
            select(POLICIES)
            .where(
                POLICIES.c.id == str(policy_id),
                POLICIES.c.org_id == str(principal.organization_id),
            )
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if current is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    target = _version_row(session, policy_id, body.target_version, principal.organization_id)
    actor, now = _member_for_policy(session, principal), datetime.now(UTC)
    snapshot = dict(target.snapshot)
    values = {
        "name": snapshot["name"],
        "enabled": snapshot["enabled"],
        "priority": snapshot["priority"],
        "conditions": snapshot["conditions"],
        "action": snapshot["action"],
        "version": current["version"] + 1,
        "updated_at": now,
    }
    next_snapshot = policy_snapshot({**dict(current), **values})
    try:
        session.execute(
            update(POLICIES)
            .where(
                POLICIES.c.id == str(policy_id),
                POLICIES.c.org_id == str(principal.organization_id),
            )
            .values(**values)
        )
        add_policy_version(session, snapshot=next_snapshot, created_by=actor, created_at=now)
        record_admin_change(
            session,
            request,
            principal,
            resource="policy",
            resource_id=str(policy_id),
            operation="rollback",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=503, detail="Policy rollback unavailable") from exc
    return _model({**dict(current), **values})


def _member_for_policy(session: SessionDependency, principal: CurrentPrincipal) -> str:
    member = session.execute(
        text("SELECT id FROM members WHERE organization_id=:org AND auth_subject_id=:sub"),
        {"org": str(principal.organization_id), "sub": principal.subject_id},
    ).scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=403, detail="Forbidden")
    return str(member)


@router.get("/{policy_id}", response_model=Policy)
def get_policy(policy_id: UUID, principal: CurrentPrincipal, session: SessionDependency) -> Policy:
    _read(principal)
    row = (
        session.execute(
            select(POLICIES).where(
                POLICIES.c.id == str(policy_id), POLICIES.c.org_id == str(principal.organization_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _model(row)


@router.put("/{policy_id}", response_model=Policy)
def update_policy(
    policy_id: UUID,
    body: PolicyWrite,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Policy:
    _write(principal)
    row = (
        session.execute(
            select(POLICIES)
            .where(
                POLICIES.c.id == str(policy_id), POLICIES.c.org_id == str(principal.organization_id)
            )
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    now = datetime.now(UTC)
    values = {**body.model_dump(mode="json"), "version": row["version"] + 1, "updated_at": now}
    next_snapshot = policy_snapshot({**dict(row), **values})
    try:
        session.execute(
            update(POLICIES)
            .where(
                POLICIES.c.id == str(policy_id),
                POLICIES.c.org_id == str(principal.organization_id),
            )
            .values(**values)
        )
        add_policy_version(
            session,
            snapshot=next_snapshot,
            created_by=_member_for_policy(session, principal),
            created_at=now,
        )
        record_admin_change(
            session,
            request,
            principal,
            resource="policy",
            resource_id=str(policy_id),
            operation="update",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=503, detail="Policy operation unavailable") from exc
    return _model({**dict(row), **values})


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDependency,
) -> Response:
    _write(principal)
    row = (
        session.execute(
            select(POLICIES)
            .where(
                POLICIES.c.id == str(policy_id),
                POLICIES.c.org_id == str(principal.organization_id),
            )
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    now = datetime.now(UTC)
    values = {"enabled": False, "version": row["version"] + 1, "updated_at": now}
    try:
        session.execute(
            update(POLICIES)
            .where(
                POLICIES.c.id == str(policy_id),
                POLICIES.c.org_id == str(principal.organization_id),
            )
            .values(**values)
        )
        add_policy_version(
            session,
            snapshot=policy_snapshot({**dict(row), **values}),
            created_by=_member_for_policy(session, principal),
            created_at=now,
        )
        record_admin_change(
            session,
            request,
            principal,
            resource="policy",
            resource_id=str(policy_id),
            operation="disable",
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=503, detail="Policy operation unavailable") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
