"""P16 route enumeration, authorization, tenant hiding and destructive denial tests."""

from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import get_principal
from dlp_platform.auth.roles import Permission
from dlp_platform.connectors.models import ConnectorHealth, ConnectorIdentity, ConnectorStatus
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import connectors

VAULT_DEPENDENCY = connectors._vault


class FakeSession:
    bind = None

    def execute(self, _statement):
        return type("Query", (), {"scalar_one_or_none": lambda self: None})()


class AllowLimiter:
    def check(self, *args):
        del args
        return type("RateResult", (), {"allowed": True, "retry_after": 0})()


class TenantService:
    def __init__(self, records):
        self.records = records
        self.lookups = []

    def get(self, _session, principal, connector_id):
        require_permission(principal, Permission.CONNECTORS_READ)
        self.lookups.append((principal.organization_id, connector_id))
        record = self.records.get(connector_id)
        if record is None or record.identity.organization_id != principal.organization_id:
            raise HTTPException(status_code=404, detail="Connector not found")
        return record

    def sync_inputs(self, _session, principal, connector_id):
        self.lookups.append((principal.organization_id, connector_id))
        record = self.records.get(connector_id)
        if record is None or record.identity.organization_id != principal.organization_id:
            raise HTTPException(status_code=404, detail="Connector not found")
        raise AssertionError("foreign sync request must not proceed")


def _principal(org_id: UUID, *, role=Role.OWNER, scopes=None, actor=ActorType.USER):
    return Principal(
        organization_id=org_id,
        subject_id=f"user-{org_id}",
        actor_type=actor,
        role=role,
        scopes=tuple(scopes if scopes is not None else ("connectors:read", "connectors:write")),
        auth_method=AuthMethod.SSO,
        member_id=uuid4() if actor is ActorType.USER else None,
        session_id=uuid4() if actor is ActorType.USER else None,
    )


def _app(monkeypatch, principal=None):
    app = FastAPI()
    app.include_router(connectors.router)
    app.dependency_overrides[get_session] = lambda: FakeSession()
    app.dependency_overrides[get_rate_limiter] = lambda: AllowLimiter()
    app.dependency_overrides[VAULT_DEPENDENCY] = lambda: object()
    if principal is not None:
        app.dependency_overrides[get_principal] = lambda: principal
    return app


def _health(org_id, connector_id):
    return ConnectorHealth(
        identity=ConnectorIdentity(
            organization_id=org_id, connector_id=connector_id, provider="google_drive"
        ),
        status=ConnectorStatus.CONNECTED,
    )


def test_p16_http_router_exposes_exact_registered_endpoint_set():
    expected = {
        ("GET", "/connectors"),
        ("POST", "/connectors"),
        ("GET", "/connectors/{connector_id}"),
        ("POST", "/connectors/{connector_id}/oauth/start"),
        ("GET", "/connectors/oauth/google/callback"),
        ("POST", "/connectors/{connector_id}/sync"),
        ("POST", "/connectors/{connector_id}/revoke-share"),
        ("POST", "/connectors/{connector_id}/quarantine"),
        ("POST", "/connectors/{connector_id}/disconnect"),
    }
    actual = {
        (method, route.path) for route in connectors.router.routes for method in route.methods or ()
    }
    assert actual == expected


def test_p16_all_registered_routes_reject_missing_and_invalid_credentials(monkeypatch):
    connector_id = uuid4()
    requests = (
        ("get", "/connectors"),
        ("post", "/connectors", {"provider": "google_drive", "name": "fixture"}),
        ("get", f"/connectors/{connector_id}"),
        ("post", f"/connectors/{connector_id}/oauth/start"),
        ("post", f"/connectors/{connector_id}/sync"),
        (
            "post",
            f"/connectors/{connector_id}/revoke-share",
            {"object_id": "file", "permission_id": "permission"},
        ),
        ("post", f"/connectors/{connector_id}/quarantine", {"object_id": "file"}),
        ("post", f"/connectors/{connector_id}/disconnect"),
    )
    for method, path, *body in requests:
        kwargs = {"json": body[0]} if body else {}
        with TestClient(_app(monkeypatch)) as client:
            missing = getattr(client, method)(path, **kwargs)
            invalid = getattr(client, method)(
                path,
                headers={"Authorization": "Bearer invalid-credential"},
                **kwargs,
            )
        assert missing.status_code == 401, (method, path, missing.text)
        assert invalid.status_code == 401, (method, path, invalid.text)


def test_p16_oauth_callback_uses_persisted_state_not_a_bearer_header(monkeypatch):
    path = "/connectors/oauth/google/callback?state=fixture&code=fixture"
    with TestClient(_app(monkeypatch)) as client:
        no_bearer = client.get(path)
        invalid_bearer = client.get(path, headers={"Authorization": "Bearer invalid-credential"})
    assert no_bearer.status_code == 400
    assert invalid_bearer.status_code == 400
    assert no_bearer.json() == invalid_bearer.json()
    assert no_bearer.json() == {"detail": "OAuth state is invalid or expired"}


def test_p16_read_and_write_permission_gates_cover_all_tenant_routes(monkeypatch):
    org, connector_id = uuid4(), uuid4()
    service = TenantService({connector_id: _health(org, connector_id)})
    monkeypatch.setattr(connectors, "_service", service)

    class PermissionService(TenantService):
        def list(self, _session, principal):
            require_permission(principal, Permission.CONNECTORS_READ)
            raise AssertionError("read-denied request reached connector listing")

    monkeypatch.setattr(connectors, "_service", PermissionService({}))
    no_read = _principal(org, role=Role.ANALYST, scopes=("identity:read",))
    with TestClient(_app(monkeypatch, no_read)) as client:
        list_denied = client.get("/connectors")
        status_denied = client.get(f"/connectors/{connector_id}")
    assert list_denied.status_code == 403
    assert status_denied.status_code == 403

    write_requests = (
        ("post", "/connectors", {"provider": "google_drive", "name": "fixture"}),
        ("post", f"/connectors/{connector_id}/oauth/start", None),
        ("post", f"/connectors/{connector_id}/sync", None),
        (
            "post",
            f"/connectors/{connector_id}/revoke-share",
            {"object_id": "file", "permission_id": "permission"},
        ),
        ("post", f"/connectors/{connector_id}/quarantine", {"object_id": "file"}),
        ("post", f"/connectors/{connector_id}/disconnect", None),
    )
    no_write = _principal(org, role=Role.ANALYST, scopes=("connectors:read",))
    with TestClient(_app(monkeypatch, no_write)) as client:
        for method, path, body in write_requests:
            response = getattr(client, method)(path, **({"json": body} if body else {}))
            assert response.status_code == 403, (path, response.text)


def test_p16_status_is_tenant_scoped_and_hides_foreign_resource_existence(monkeypatch):
    org_a, org_b = uuid4(), uuid4()
    connector_a, connector_b = uuid4(), uuid4()
    service = TenantService(
        {connector_a: _health(org_a, connector_a), connector_b: _health(org_b, connector_b)}
    )
    monkeypatch.setattr(connectors, "_service", service)
    principal_a = _principal(org_a)
    app = _app(monkeypatch, principal_a)
    with TestClient(app) as client:
        own = client.get(f"/connectors/{connector_a}")
        foreign = client.get(f"/connectors/{connector_b}")
        forged_org = client.get(f"/connectors/{connector_b}?org_id={org_a}")
    with TestClient(_app(monkeypatch, _principal(org_b))) as client:
        reverse_foreign = client.get(f"/connectors/{connector_a}")
    assert own.status_code == 200
    assert foreign.status_code == forged_org.status_code == 404
    assert reverse_foreign.status_code == 404
    assert foreign.json() == forged_org.json() == {"detail": "Connector not found"}
    assert str(org_b) not in foreign.text
    assert service.lookups == [
        (org_a, connector_a),
        (org_a, connector_b),
        (org_a, connector_b),
        (org_b, connector_a),
    ]


def test_p16_status_denies_missing_permission_and_missing_authentication(monkeypatch):
    org, connector_id = uuid4(), uuid4()
    monkeypatch.setattr(
        connectors, "_service", TenantService({connector_id: _health(org, connector_id)})
    )
    no_permission = _principal(org, role=Role.ANALYST, scopes=("identity:read",))
    with TestClient(_app(monkeypatch, no_permission)) as client:
        denied = client.get(f"/connectors/{connector_id}")
    with TestClient(_app(monkeypatch)) as client:
        unauthenticated = client.get(f"/connectors/{connector_id}")
    assert denied.status_code == 403
    assert unauthenticated.status_code == 401


def test_p16_revoke_denies_foreign_connector_before_vault_or_provider(monkeypatch):
    org_a, org_b = uuid4(), uuid4()
    foreign_id = uuid4()
    service = TenantService({foreign_id: _health(org_b, foreign_id)})
    monkeypatch.setattr(connectors, "_service", service)
    calls = {"oauth": 0, "vault": 0, "scan": 0, "audit": 0}

    def vault():
        calls["vault"] += 1
        raise AssertionError("foreign connector must be denied before Vault access")

    def oauth():
        calls["oauth"] += 1
        raise AssertionError("foreign connector must be denied before provider access")

    monkeypatch.setattr(connectors, "_vault", vault)
    monkeypatch.setattr(connectors, "_oauth", oauth)
    monkeypatch.setattr(connectors, "scan", lambda *_: calls.__setitem__("scan", 1))
    monkeypatch.setattr(
        connectors, "_audit_drive_action", lambda *_a, **_k: calls.__setitem__("audit", 1)
    )
    principal = _principal(org_a)
    app = _app(monkeypatch, principal)
    # The dependency captured the original provider Vault factory when the router was built.
    with TestClient(app) as client:
        response = client.post(
            f"/connectors/{foreign_id}/revoke-share",
            json={"object_id": "file-a", "permission_id": "permission-a"},
        )
    assert response.status_code == 404
    assert calls == {"oauth": 0, "vault": 0, "scan": 0, "audit": 0}
    assert service.lookups == [(org_a, foreign_id)]


def test_p16_all_tenant_action_routes_hide_foreign_connector_resources(monkeypatch):
    org_a, org_b = uuid4(), uuid4()
    foreign_id = uuid4()
    service = TenantService({foreign_id: _health(org_b, foreign_id)})
    monkeypatch.setattr(connectors, "_service", service)
    calls = {"vault_read": 0, "oauth": 0, "audit": 0}

    class CountingVault:
        def get_for_trusted_service(self, *_args, **_kwargs):
            calls["vault_read"] += 1
            raise AssertionError("foreign connector cannot reach Vault")

    app = _app(monkeypatch, _principal(org_a))
    app.dependency_overrides[connectors._vault] = lambda: CountingVault()
    monkeypatch.setattr(connectors, "_oauth", lambda: calls.__setitem__("oauth", 1))
    monkeypatch.setattr(
        connectors, "_audit_drive_action", lambda *_a, **_k: calls.__setitem__("audit", 1)
    )
    with TestClient(app) as client:
        sync = client.post(f"/connectors/{foreign_id}/sync")
        quarantine = client.post(
            f"/connectors/{foreign_id}/quarantine", json={"object_id": "file-b"}
        )
        disconnect = client.post(f"/connectors/{foreign_id}/disconnect")
    assert sync.status_code == quarantine.status_code == disconnect.status_code == 404
    assert calls == {"vault_read": 0, "oauth": 0, "audit": 0}


def test_p16_revoke_requires_write_permission_and_does_not_reach_provider(monkeypatch):
    org, connector_id = uuid4(), uuid4()
    service = TenantService({connector_id: _health(org, connector_id)})
    monkeypatch.setattr(connectors, "_service", service)
    calls = []
    monkeypatch.setattr(connectors, "_oauth", lambda: calls.append("oauth"))
    analyst = _principal(org, role=Role.ANALYST, scopes=("connectors:read",))
    app = _app(monkeypatch, analyst)
    with TestClient(app) as client:
        response = client.post(
            f"/connectors/{connector_id}/revoke-share",
            json={"object_id": "file-a", "permission_id": "permission-a"},
        )
    assert response.status_code == 403
    assert calls == []
    assert service.lookups == []


def test_p16_revoke_rejects_service_actor_before_provider_call(monkeypatch):
    org, connector_id = uuid4(), uuid4()
    service = TenantService({connector_id: _health(org, connector_id)})
    monkeypatch.setattr(connectors, "_service", service)
    calls = []
    monkeypatch.setattr(connectors, "_oauth", lambda: calls.append("oauth"))
    principal = _principal(org, actor=ActorType.SERVICE)
    with TestClient(_app(monkeypatch, principal)) as client:
        response = client.post(
            f"/connectors/{connector_id}/revoke-share",
            json={"object_id": "file-a", "permission_id": "permission-a"},
        )
    assert response.status_code == 403
    assert calls == []
    assert service.lookups == []


def test_p16_mutation_bodies_reject_forged_tenant_and_resource_metadata(monkeypatch):
    org, connector_id = uuid4(), uuid4()
    monkeypatch.setattr(connectors, "_service", TenantService({}))
    app = _app(monkeypatch, _principal(org))
    with TestClient(app) as client:
        create = client.post(
            "/connectors",
            json={"provider": "google_drive", "name": "forged", "org_id": str(uuid4())},
        )
        revoke = client.post(
            f"/connectors/{connector_id}/revoke-share",
            json={
                "object_id": "file",
                "permission_id": "permission",
                "org_id": str(uuid4()),
                "connector_id": str(uuid4()),
            },
        )
    assert create.status_code == 422
    assert revoke.status_code == 422


def test_p16_quarantine_never_claims_success_and_has_no_provider_call(monkeypatch):
    org, connector_id = uuid4(), uuid4()
    service = TenantService({connector_id: _health(org, connector_id)})
    monkeypatch.setattr(connectors, "_service", service)
    calls = []
    monkeypatch.setattr(connectors, "_oauth", lambda: calls.append("oauth"))
    monkeypatch.setattr(connectors, "_audit_drive_action", lambda *_a, **_k: calls.append("audit"))
    app = _app(monkeypatch, _principal(org))
    with TestClient(app) as client:
        response = client.post(
            f"/connectors/{connector_id}/quarantine", json={"object_id": "file-a"}
        )
    assert response.status_code == 501
    assert response.json() == {"detail": "Google Drive quarantine is not configured"}
    assert "status" not in response.json()
    assert "oauth" not in calls
    assert calls == ["audit", "audit"]
