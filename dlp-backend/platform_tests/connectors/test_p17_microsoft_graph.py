"""Fixture-only tests for P17 Microsoft OAuth, Graph and scan handoff boundaries."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from dlp_platform.actions.service import ActionProcessor
from dlp_platform.auth.principal import get_principal
from dlp_platform.connectors.microsoft_action_executor import MicrosoftGraphActionExecutor
from dlp_platform.connectors.microsoft_graph import (
    MAX_GRAPH_RESPONSE_BYTES,
    MICROSOFT_LOGIN_HOSTS,
    MICROSOFT_SCOPES,
    MicrosoftGraphAPI,
    MicrosoftOAuthSettings,
    MicrosoftProviderFailure,
    _validate_graph_url,
)
from dlp_platform.connectors.models import ExposureKind, ShareRevocation
from dlp_platform.connectors.oauth import authorization_url
from dlp_platform.contracts.common import ActorType, AuthMethod, PolicyAction, Role
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_result import ScanResult
from dlp_platform.database import get_session
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import approvals, connectors
from dlp_platform.scan.idempotency import InMemoryIdempotencyStore
from dlp_platform.scan.pipeline import configure_action_processor, configure_pipeline, fake_stages
from dlp_platform.tables import (
    ACTIONS,
    APPROVALS,
    AUDIT_EVENTS,
    DLP_CONNECTOR_STATE,
    DLP_CONNECTORS,
    MEMBERS,
    ORGANIZATIONS,
    metadata,
)


class GraphFixture:
    def __init__(self, payloads: list[object]) -> None:
        self.payloads = payloads
        self.calls: list[tuple[str, str]] = []

    def request(self, method, url, *, headers, body=None, max_bytes=MAX_GRAPH_RESPONSE_BYTES):
        del headers, body
        self.calls.append((method, url))
        next_payload = self.payloads.pop(0)
        if isinstance(next_payload, Exception):
            raise next_payload
        assert isinstance(next_payload, dict)
        payload = json.dumps(next_payload).encode()
        assert len(payload) <= max_bytes
        return payload, {}


def test_tenant_bound_authority_and_pkce_authorization_url():
    tenant = str(uuid4())
    endpoint = f"{MicrosoftOAuthSettings.authority(tenant)}/authorize"
    url = authorization_url(
        endpoint=endpoint,
        allowed_hosts=MICROSOFT_LOGIN_HOSTS,
        client_id="fixture-client",
        redirect_uri="https://dlp.example.test/connectors/oauth/microsoft/callback",
        scopes=MICROSOFT_SCOPES,
        state="opaque-one-time-state",
        challenge="pkce-challenge",
    )
    query = parse_qs(urlparse(url).query)
    assert urlparse(url).path.endswith(f"/{tenant}/oauth2/v2.0/authorize")
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == ["opaque-one-time-state"]
    assert "offline_access" in query["scope"][0].split()
    with pytest.raises(MicrosoftProviderFailure):
        MicrosoftOAuthSettings.authority("common")


def test_graph_continuation_links_are_fixed_host_versioned_and_bounded():
    valid = "https://graph.microsoft.com/v1.0/drives/delta?$skiptoken=opaque"
    assert _validate_graph_url(valid) == valid
    for malicious in (
        "https://attacker.invalid/v1.0/drives/delta",
        "https://graph.microsoft.com.evil.invalid/v1.0/drives/delta",
        "https://graph.microsoft.com/beta/me/drive",
        "https://graph.microsoft.com/v1.0/" + "x" * 8193,
    ):
        with pytest.raises(MicrosoftProviderFailure):
            _validate_graph_url(malicious)


def test_graph_delta_pagination_keeps_tenant_site_drive_item_ids_distinct():
    tenant_id, site_id, drive_id = str(uuid4()), "site,opaque,id", "library:opaque"
    next_link = "https://graph.microsoft.com/v1.0/drives/delta?$skiptoken=next"
    transport = GraphFixture(
        [
            {
                "value": [
                    {
                        "id": "item/opaque",
                        "name": "one.txt",
                        "file": {"mimeType": "text/plain"},
                        "size": 5,
                        "permissions": [
                            {"id": "public-link", "link": {"scope": "anonymous"}},
                            {"id": "tenant-link", "link": {"scope": "organization"}},
                            {
                                "id": "inherited",
                                "inheritedFrom": {"id": "parent"},
                                "link": {"scope": "anonymous"},
                            },
                        ],
                    }
                ],
                "@odata.nextLink": next_link,
            },
            {
                "value": [
                    {"id": "public-link", "link": {"scope": "anonymous"}},
                    {"id": "tenant-link", "link": {"scope": "organization"}},
                    {
                        "id": "inherited",
                        "inheritedFrom": {"id": "parent"},
                        "link": {"scope": "anonymous"},
                    },
                ]
            },
            {
                "value": [],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/delta?$deltatoken=done",
            },
        ]
    )
    api = MicrosoftGraphAPI("fixture-access-token", tenant_id, transport)
    first = api.delta_page(
        "microsoft_sharepoint", drive_id=drive_id, site_id=site_id, tenant_id=tenant_id
    )
    obj = first.objects[0]
    assert (obj.tenant_id, obj.site_id, obj.drive_id, obj.object_id) == (
        tenant_id,
        site_id,
        drive_id,
        "item/opaque",
    )
    assert first.next_link == next_link
    kinds = {row.kind for row in api.detect_exposure(obj)}
    assert {ExposureKind.PUBLIC, ExposureKind.ORGANIZATION} <= kinds
    assert any(
        row.kind is ExposureKind.PUBLIC and row.inherited for row in api.detect_exposure(obj)
    )
    from dlp_platform.routes.connectors import _microsoft_action_context

    assert _microsoft_action_context(obj) == {"permission_id": "public-link"}
    second = api.delta_page(
        "microsoft_sharepoint",
        drive_id=drive_id,
        site_id=site_id,
        tenant_id=tenant_id,
        page_link=first.next_link,
    )
    assert second.delta_link and second.next_link is None
    assert urlparse(transport.calls[0][1]).path.endswith("/drives/library%3Aopaque/root/delta")
    assert "/permissions?" in transport.calls[1][1]
    assert transport.calls[2][1] == next_link


def test_removed_delta_item_and_bad_provider_shapes_fail_safely():
    tenant_id = str(uuid4())
    api = MicrosoftGraphAPI(
        "fixture-access-token",
        tenant_id,
        GraphFixture([{"value": [{"id": "gone", "name": "gone", "deleted": {}}]}]),
    )
    page = api.delta_page("microsoft_onedrive", drive_id="drive", site_id=None, tenant_id=tenant_id)
    assert page.changes[0].change_type == "deleted"
    with pytest.raises(MicrosoftProviderFailure):
        MicrosoftGraphAPI("token", tenant_id, GraphFixture([])).delta_page(
            "microsoft_onedrive",
            drive_id="drive",
            site_id=None,
            tenant_id=tenant_id,
            page_link="https://attacker.invalid/v1.0/delta",
        )


def test_delta_repeated_page_link_is_rejected():
    tenant_id = str(uuid4())
    repeated = "https://graph.microsoft.com/v1.0/me/drive/root/delta?$skiptoken=again"
    api = MicrosoftGraphAPI(
        "fixture-access-token",
        tenant_id,
        GraphFixture([{"value": [], "@odata.nextLink": repeated}]),
    )
    with pytest.raises(MicrosoftProviderFailure, match="repeated_page_link"):
        api.delta_page(
            "microsoft_onedrive",
            drive_id="drive",
            site_id=None,
            tenant_id=tenant_id,
            page_link=repeated,
        )


def test_microsoft_scan_handoff_attaches_provider_owned_revocation_target(monkeypatch):
    principal = Principal(
        organization_id=uuid4(),
        subject_id="p17-user",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request",),
        auth_method=AuthMethod.SSO,
    )
    tenant_id, connector_id = str(uuid4()), uuid4()
    from dlp_platform.connectors.models import DriveObject

    obj = DriveObject(
        object_id="graph-item",
        name="doc.txt",
        mime_type="text/plain",
        tenant_id=tenant_id,
        site_id="site-42",
        drive_id="drive-73",
    )
    observed = {}

    def fake_scan(request, actual_principal):
        observed["request"] = request
        observed["principal"] = actual_principal
        return ScanResult(
            scan_id=uuid4(),
            request_id=request.request_id,
            decision=PolicyAction.REVOKE_SHARE,
            reason="fixture P07 action",
            completed_at=datetime.now(UTC),
        )

    monkeypatch.setattr(connectors, "scan", fake_scan)
    result = connectors._scan_drive_object(
        principal,
        connector_id,
        obj,
        provider="microsoft_sharepoint",
        extra_context={"permission_id": "link-1"},
        trusted_action_metadata={
            "permission_id": "link-1",
            "drive_id": "drive-73",
            "tenant_id": tenant_id,
        },
    )
    request = observed["request"]
    assert observed["principal"] is principal
    assert request._trusted_action_metadata == {
        "provider": "microsoft_sharepoint",
        "connector_id": str(connector_id),
        "drive_object_id": "graph-item",
        "permission_id": "link-1",
        "drive_id": "drive-73",
        "tenant_id": tenant_id,
    }
    assert result["decision"] == PolicyAction.REVOKE_SHARE.value


def test_graph_delta_page_flows_through_p05_p07_approval_audit_and_checkpoint(monkeypatch):
    """Fixture Graph pages use the production scan/approval/checkpoint routes."""
    from sqlalchemy import select, update

    import dlp_platform.connectors.microsoft_action_executor as action_module
    import dlp_platform.connectors.microsoft_graph as graph_module
    import dlp_platform.scan.pipeline as scan_pipeline

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    metadata.create_all(
        engine,
        tables=[
            ORGANIZATIONS,
            MEMBERS,
            ACTIONS,
            APPROVALS,
            AUDIT_EVENTS,
            DLP_CONNECTORS,
            DLP_CONNECTOR_STATE,
        ],
    )
    org_id, connector_id = uuid4(), uuid4()
    owner_id, approver_id = uuid4(), uuid4()
    tenant_id = str(uuid4())
    secret_id = uuid4()
    now = datetime.now(UTC)
    owner = Principal(
        organization_id=org_id,
        subject_id="p17-owner",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request", "approvals:decide", "identity:read", "connectors:write"),
        auth_method=AuthMethod.SSO,
        member_id=owner_id,
    )
    approver = Principal(
        organization_id=org_id,
        subject_id="p17-approver",
        actor_type=ActorType.USER,
        role=Role.ADMIN,
        scopes=("approvals:decide", "identity:read"),
        auth_method=AuthMethod.SSO,
        member_id=approver_id,
    )
    with engine.begin() as connection:
        connection.execute(
            ORGANIZATIONS.insert().values(
                id=str(org_id), name="P17 fixture", settings_json={}, created_at=now, updated_at=now
            )
        )
        connection.execute(
            MEMBERS.insert(),
            [
                {
                    "id": str(owner_id),
                    "organization_id": str(org_id),
                    "auth_subject_id": owner.subject_id,
                    "role": "owner",
                    "active": True,
                    "created_at": now,
                },
                {
                    "id": str(approver_id),
                    "organization_id": str(org_id),
                    "auth_subject_id": approver.subject_id,
                    "role": "admin",
                    "active": True,
                    "created_at": now,
                },
            ],
        )
        connection.execute(
            DLP_CONNECTORS.insert().values(
                id=str(connector_id),
                org_id=str(org_id),
                provider="microsoft_onedrive",
                name="P17 fixture connector",
                status="connected",
                credential_secret_id=str(secret_id),
                config_json={"microsoft_tenant_id": tenant_id},
                last_sync_at=None,
                last_error_code=None,
                created_at=now,
                updated_at=now,
            )
        )
        connection.execute(
            DLP_CONNECTOR_STATE.insert().values(
                connector_id=str(connector_id),
                org_id=str(org_id),
                provider="microsoft_onedrive",
                checkpoint="microsoft_graph_delta_v1",
                state_json={"drive_id": "drive-17", "delta_link": None},
                updated_at=now,
            )
        )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    action_trace: list[str] = []
    graph_payloads = [
        {"value": [{"id": tenant_id}]},
        {
            "value": [{"id": "item-17", "name": "exposed.txt", "file": {"mimeType": "text/plain"}}],
            "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/drive/root/delta?$deltatoken=p17",
        },
        {"value": [{"id": "permission-17", "link": {"scope": "anonymous"}}]},
        {"value": [{"id": tenant_id}]},
        {"value": [{"id": "permission-17"}]},
        {},
        {"value": []},
        {"value": [{"id": tenant_id}]},
        {
            "value": [{"id": "item-17", "name": "exposed.txt", "file": {"mimeType": "text/plain"}}],
            "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/drive/root/delta?$deltatoken=p17",
        },
        {"value": [{"id": "permission-17", "link": {"scope": "anonymous"}}]},
        {"value": [{"id": tenant_id}]},
        {
            "value": [{"id": "item-17", "name": "exposed.txt", "file": {"mimeType": "text/plain"}}],
            "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/drive/root/delta?$deltatoken=p17",
        },
        {"value": [{"id": "permission-17", "link": {"scope": "anonymous"}}]},
    ]
    graph_transport = GraphFixture(graph_payloads)
    monkeypatch.setattr(graph_module, "MicrosoftHTTPTransport", lambda: graph_transport)
    monkeypatch.setattr(
        graph_module.MicrosoftOAuthSettings,
        "from_environment",
        classmethod(
            lambda _cls: graph_module.MicrosoftOAuthSettings(
                "fixture", "secret", "https://dlp.test/callback"
            )
        ),
    )

    class OAuthFixture:
        def __init__(self, _settings, _transport):
            pass

        def refresh(self, refresh_token, requested_tenant):
            action_trace.append("oauth_refresh")
            assert refresh_token == "fixture-refresh"
            assert requested_tenant == tenant_id
            return {"access_token": "fixture-access"}

    monkeypatch.setattr(graph_module, "MicrosoftOAuthClient", OAuthFixture)

    class VaultFixture:
        def get_for_trusted_service(
            self, _session, requested_org, requested_secret, *, allowed_types
        ):
            action_trace.append("vault_get")
            assert requested_org == org_id
            assert requested_secret == secret_id
            assert {item.value for item in allowed_types} == {"refresh_token"}
            return SecretStr("fixture-refresh")

    class ConnectorFixture:
        def __init__(self):
            self.checkpoints = []
            self.fail_next_checkpoint = True

        def sync_inputs(self, session, _principal, _connector_id):
            state = (
                session.execute(
                    select(
                        DLP_CONNECTOR_STATE.c.checkpoint, DLP_CONNECTOR_STATE.c.state_json
                    ).where(DLP_CONNECTOR_STATE.c.connector_id == str(connector_id))
                )
                .mappings()
                .one()
            )
            return secret_id, state["checkpoint"], dict(state["state_json"])

        def get(self, _session, _principal, requested_id):
            assert requested_id == connector_id
            return type(
                "Health",
                (),
                {"identity": type("Identity", (), {"provider": "microsoft_onedrive"})()},
            )()

        def configuration(self, _session, _principal, _connector_id):
            return {"microsoft_tenant_id": tenant_id}

        def _rls(self, _session, _principal):
            pass

        def complete_sync(self, _session, _principal, _connector_id, **kwargs):
            if self.fail_next_checkpoint:
                self.fail_next_checkpoint = False
                raise connectors.ConnectorOperationFailed("fixture persistence failure")
            _session.execute(
                update(DLP_CONNECTOR_STATE)
                .where(DLP_CONNECTOR_STATE.c.connector_id == str(connector_id))
                .values(checkpoint=kwargs["checkpoint"], state_json=kwargs["state_json"])
            )
            _session.commit()
            self.checkpoints.append(kwargs["state_json"])

        def mark_degraded(self, *_args, **_kwargs):
            pass

    class PolicyFixture:
        def __init__(self):
            self.policy = Policy(
                policy_id=uuid4(),
                organization_id=org_id,
                name="Review public sharing",
                enabled=True,
                priority=1,
                conditions={},
                action=PolicyAction.REVOKE_SHARE,
                version=1,
                created_at=now,
                updated_at=now,
            )
            self.engine = PolicyEngine()

        def evaluate(self, findings, request, principal):
            return self.engine.evaluate(
                organization_id=principal.organization_id,
                request=request,
                principal=principal,
                findings=findings,
                policies=(self.policy,),
                destinations=(),
            )

    action_executor = MicrosoftGraphActionExecutor.__new__(MicrosoftGraphActionExecutor)
    action_executor.engine = engine
    processor = ActionProcessor(engine, executor=action_executor)
    monkeypatch.setattr(scan_pipeline, "_action_processor", None)
    monkeypatch.setattr(scan_pipeline, "_default_pipeline", None)
    configure_action_processor(processor)
    configure_pipeline(replace(fake_stages(), policy=PolicyFixture()), InMemoryIdempotencyStore())
    connector_service = ConnectorFixture()
    monkeypatch.setattr(connectors, "_service", connector_service)
    monkeypatch.setattr(connectors, "_oauth", lambda: (None, OAuthFixture(None, None)))
    monkeypatch.setattr(approvals, "_executor", action_executor)
    monkeypatch.setattr(action_module, "MicrosoftOAuthClient", OAuthFixture)
    monkeypatch.setattr(
        action_module.SecretVault,
        "from_environment",
        classmethod(lambda _cls: (action_trace.append("action_vault_init"), VaultFixture())[1]),
    )
    current_principal = {"value": owner}
    app = FastAPI()
    app.include_router(connectors.router)
    app.include_router(approvals.router)
    app.dependency_overrides[get_principal] = lambda: current_principal["value"]
    app.dependency_overrides[get_session] = lambda: factory()
    app.dependency_overrides[get_rate_limiter] = lambda: type(
        "Limiter",
        (),
        {"check": lambda _self, *_args: type("Allowed", (), {"allowed": True, "retry_after": 0})()},
    )()
    app.dependency_overrides[connectors._vault] = lambda: VaultFixture()
    try:
        with TestClient(app) as client:
            pending = client.post(f"/connectors/{connector_id}/sync")
        assert pending.status_code == 503, pending.text
        assert connector_service.checkpoints == []
        with factory() as session:
            action = session.execute(ACTIONS.select()).mappings().one()
            approval = session.execute(APPROVALS.select()).mappings().one()
            assert action["metadata"]["provider"] == "microsoft_onedrive"
            assert action["metadata"]["drive_id"] == "drive-17"
            approval_id = approval["id"]
        current_principal["value"] = approver
        with TestClient(app) as client:
            approved = client.post(f"/approvals/{approval_id}/approve", json={})
        assert approved.status_code == 200
        assert approved.json()["action_status"] == "succeeded", approved.json()
        assert action_trace.count("action_vault_init") == 1
        assert action_trace.count("oauth_refresh") == 2
        delete_calls = [call for call in graph_transport.calls if call[0] == "DELETE"]
        assert len(delete_calls) == 1
        current_principal["value"] = owner
        with TestClient(app) as client:
            persistence_failure = client.post(f"/connectors/{connector_id}/sync")
        assert persistence_failure.status_code == 503
        assert connector_service.checkpoints == []
        with factory() as session:
            old_state = session.execute(
                select(DLP_CONNECTOR_STATE.c.state_json).where(
                    DLP_CONNECTOR_STATE.c.connector_id == str(connector_id)
                )
            ).scalar_one()
        assert old_state["delta_link"] is None
        with TestClient(app) as client:
            completed = client.post(f"/connectors/{connector_id}/sync")
        assert completed.status_code == 200, completed.text
        assert connector_service.checkpoints[-1]["delta_link"].endswith("$deltatoken=p17")
        assert len([call for call in graph_transport.calls if call[0] == "DELETE"]) == 1
        with factory() as session:
            audit_events = session.execute(AUDIT_EVENTS.select()).mappings().all()
        assert any(event["action"] == "action.executed" for event in audit_events)
        assert "fixture-access" not in completed.text
        assert "fixture-refresh" not in completed.text
    finally:
        engine.dispose()


def test_graph_revoke_reads_before_and_verifies_after_provider_delete():
    transport = GraphFixture(
        [
            {"value": [{"id": "permission-42"}]},
            {},
            {"value": []},
        ]
    )
    api = MicrosoftGraphAPI("fixture-access-token", str(uuid4()), transport)
    result = api.revoke_share(
        ShareRevocation(drive_id="drive-42", object_id="item-42", permission_id="permission-42")
    )
    assert result.succeeded is True
    assert result.outcome == "revoked"
    assert [method for method, _url in transport.calls] == ["GET", "DELETE", "GET"]
    assert "/drives/drive-42/items/item-42/permissions/permission-42" in transport.calls[1][1]


def test_graph_revoke_provider_failure_is_not_reported_as_success():
    transport = GraphFixture(
        [
            {"value": [{"id": "permission-42"}]},
            MicrosoftProviderFailure("forbidden"),
        ]
    )
    api = MicrosoftGraphAPI("fixture-access-token", str(uuid4()), transport)
    result = api.revoke_share(
        ShareRevocation(drive_id="drive-42", object_id="item-42", permission_id="permission-42")
    )
    assert result.succeeded is False
    assert result.outcome == "forbidden"
    assert [method for method, _url in transport.calls] == ["GET", "DELETE"]


def test_graph_revoke_retry_after_success_is_idempotent():
    transport = GraphFixture([{"value": []}])
    api = MicrosoftGraphAPI("fixture-access-token", str(uuid4()), transport)
    result = api.revoke_share(
        ShareRevocation(drive_id="drive-42", object_id="item-42", permission_id="permission-42")
    )
    assert result.succeeded is True
    assert result.outcome == "already_absent"
    assert [method for method, _url in transport.calls] == ["GET"]
