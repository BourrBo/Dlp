"""HTTP boundary tests for the existing P16 Google OAuth callback route."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from dlp_platform.auth.principal import get_principal
from dlp_platform.connectors import google_drive, oauth
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import connectors
from dlp_platform.vault.models import SecretType

VAULT_DEPENDENCY = connectors._vault


class AllowLimiter:
    def check(self, *args):
        del args
        return SimpleNamespace(allowed=True, retry_after=0)


class FakeSession:
    bind = None

    def __init__(self, *, active=True):
        self.active = active

    def execute(self, statement):
        del statement
        return SimpleNamespace(scalar_one_or_none=lambda: "active-member" if self.active else None)

    def rollback(self):
        pass


class FakeVault:
    def __init__(self):
        self.writes = []
        self.disabled = []

    def set(self, session, principal, **kwargs):
        del session, principal
        self.writes.append(kwargs)
        return SimpleNamespace(secret_id=uuid4())

    def disable(self, *args, **kwargs):
        self.disabled.append((args, kwargs))


class FakeService:
    def __init__(self):
        self.connected = []
        self.failed = []

    def _rls(self, *args):
        pass

    def set_connection(self, *args, **kwargs):
        self.connected.append((args, kwargs))

    def mark_connect_failed(self, *args, **kwargs):
        self.failed.append((args, kwargs))


class FakeOAuth:
    def __init__(self, *, failure=None, expected_verifier="stored-verifier"):
        self.failure = failure
        self.expected_verifier = expected_verifier
        self.calls = []

    def exchange(self, code, verifier, redirect_uri):
        self.calls.append((code, verifier, redirect_uri))
        if verifier != self.expected_verifier or self.failure is not None:
            raise self.failure or google_drive.ProviderFailure("invalid_oauth_response")
        return {
            "access_token": "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
            "refresh_token": "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
            "scope": google_drive.GOOGLE_DRIVE_SCOPE,
            "token_type": "Bearer",
        }


def _transaction(principal: Principal, **overrides):
    values = {
        "state": "tenant-state.synthetic",
        "verifier": "stored-verifier",
        "organization_id": principal.organization_id,
        "principal_id": principal.subject_id,
        "binding_id": str(uuid4()),
        "role": principal.role,
        "member_id": principal.member_id,
        "session_id": principal.session_id,
        "scopes": principal.scopes,
        "auth_method": principal.auth_method,
        "provider": "google_drive",
        "redirect_uri": "https://dlp.example.test/connectors/oauth/google/callback",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).timestamp(),
    }
    values.update(overrides)
    return oauth.OAuthTransaction(**values)


def _client(
    monkeypatch,
    principal: Principal | None,
    transaction=None,
    consume_error=None,
    *,
    session_active=True,
):
    api = FastAPI()
    api.include_router(connectors.router)
    session = FakeSession(active=session_active)
    vault = FakeVault()
    fake_service = FakeService()
    provider = FakeOAuth()
    consumed = False

    def consume_callback(_session, state, *, provider):
        nonlocal consumed
        if consume_error is not None:
            raise consume_error
        if (
            consumed
            or transaction is None
            or state != transaction.state
            or provider != transaction.provider
            or transaction.expires_at <= datetime.now(UTC).timestamp()
        ):
            raise oauth.OAuthRejected("invalid or consumed transaction")
        consumed = True
        return transaction

    monkeypatch.setattr(connectors, "_service", fake_service)
    monkeypatch.setattr(connectors, "_oauth", lambda: (SimpleNamespace(), provider))
    monkeypatch.setattr(
        connectors,
        "_oauth_transactions",
        SimpleNamespace(consume_callback=consume_callback),
    )
    monkeypatch.setattr(connectors, "_vault", lambda: vault)
    monkeypatch.setattr(connectors, "get_session", lambda: session)
    monkeypatch.setattr(connectors, "get_rate_limiter", lambda: AllowLimiter())
    api.dependency_overrides[get_session] = lambda: session
    api.dependency_overrides[get_rate_limiter] = lambda: AllowLimiter()
    api.dependency_overrides[VAULT_DEPENDENCY] = lambda: vault
    if principal is not None:
        api.dependency_overrides[get_principal] = lambda: principal

    class FakeDrive:
        def __init__(self, access_token):
            assert access_token == "TEST_ACCESS_TOKEN_DO_NOT_LEAK"

        def get_start_page_token(self):
            return "fixture-start-token"

    monkeypatch.setattr(google_drive, "GoogleDriveAPI", FakeDrive)
    monkeypatch.setattr(connectors, "GoogleDriveAPI", FakeDrive)
    return api, provider, vault, fake_service


def _get(api, path, *, params=None):
    with TestClient(api) as client:
        return client.get(path, params=params, follow_redirects=False)


def _principal(**changes):
    values = {
        "organization_id": uuid4(),
        "subject_id": "oauth-test-user",
        "actor_type": ActorType.USER,
        "role": Role.OWNER,
        "scopes": ("connectors:write",),
        "auth_method": AuthMethod.SSO,
        "member_id": uuid4(),
        "session_id": uuid4(),
    }
    values.update(changes)
    return Principal(**values)


def test_oauth_callback_http_valid_uses_stored_pkce_and_never_returns_tokens(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, fake_service = _client(monkeypatch, principal, transaction)

    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )

    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/settings/connectors?connected=google_drive"
    assert "TEST_ACCESS_TOKEN_DO_NOT_LEAK" not in response.text
    assert "TEST_REFRESH_TOKEN_DO_NOT_LEAK" not in response.text
    assert "TEST_OAUTH_CODE_DO_NOT_LEAK" not in response.text
    assert len(provider.calls) == 1
    assert provider.calls[0] == (
        "TEST_OAUTH_CODE_DO_NOT_LEAK",
        transaction.verifier,
        transaction.redirect_uri,
    )
    assert len(vault.writes) == 1
    assert vault.writes[0]["secret_type"] is SecretType.REFRESH_TOKEN
    assert vault.writes[0]["value"].get_secret_value() == "TEST_REFRESH_TOKEN_DO_NOT_LEAK"
    assert len(fake_service.connected) == 1


def test_oauth_callback_http_rejects_revoked_or_inactive_initiator_session(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, fake_service = _client(
        monkeypatch, None, transaction, session_active=False
    )
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )
    assert response.status_code == 401
    assert provider.calls == []
    assert vault.writes == []
    assert fake_service.connected == []
    assert "TEST_OAUTH_CODE_DO_NOT_LEAK" not in response.text
    assert "TEST_REFRESH_TOKEN_DO_NOT_LEAK" not in response.text


def test_oauth_error_callback_does_not_mutate_for_inactive_initiator(monkeypatch):
    transaction = _transaction(_principal())
    client, provider, vault, fake_service = _client(
        monkeypatch, None, transaction, session_active=False
    )
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "error": "access_denied"},
    )
    assert response.status_code == 401
    assert fake_service.failed == []
    assert provider.calls == [] and vault.writes == []


@pytest.mark.parametrize(
    "error",
    [
        oauth.OAuthRejected("invalid"),
        oauth.OAuthRejected("expired"),
        oauth.OAuthRejected("already consumed"),
        oauth.OAuthRejected("tampered"),
        oauth.OAuthRejected("wrong provider"),
    ],
    ids=["invalid-state", "expired-state", "replay", "tampered-state", "wrong-provider"],
)
def test_oauth_callback_http_rejects_state_failures_safely(monkeypatch, error):
    principal = _principal()
    client, provider, vault, fake_service = _client(monkeypatch, principal, consume_error=error)
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": "invalid-or-expired", "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "OAuth state is invalid or expired"
    assert provider.calls == [] and vault.writes == [] and fake_service.connected == []
    assert "TEST_OAUTH_CODE_DO_NOT_LEAK" not in response.text


@pytest.mark.parametrize(
    ("params", "expected_status"),
    [({}, 422), ({"state": "s"}, 400), ({"state": "s", "code": ""}, 400)],
    ids=["missing-state", "missing-code", "empty-code"],
)
def test_oauth_callback_http_rejects_missing_or_empty_callback_values(
    monkeypatch, params, expected_status
):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, _service_double = _client(monkeypatch, principal, transaction)
    response = _get(client, "/connectors/oauth/google/callback", params=params)
    assert response.status_code == expected_status
    assert provider.calls == [] and vault.writes == []


def test_oauth_callback_http_uses_persisted_state_without_bearer_header(monkeypatch):
    transaction = _transaction(_principal())
    client, provider, vault, _service_double = _client(monkeypatch, None, transaction)
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )
    assert response.status_code == 303
    assert len(provider.calls) == 1
    assert len(vault.writes) == 1


def test_oauth_callback_http_sanitizes_provider_and_pkce_failures(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, fake_service = _client(monkeypatch, principal, transaction)
    provider.failure = google_drive.ProviderFailure("TEST_CLIENT_SECRET_DO_NOT_LEAK")
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )
    assert response.status_code == 503
    for secret in (
        "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
        "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
        "TEST_OAUTH_CODE_DO_NOT_LEAK",
        "TEST_CLIENT_SECRET_DO_NOT_LEAK",
    ):
        assert secret not in response.text
    assert vault.writes == []
    assert fake_service.connected == []


def test_oauth_callback_http_uses_transaction_redirect_without_request_override(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, _service_double = _client(monkeypatch, principal, transaction)
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={
            "state": transaction.state,
            "code": "TEST_OAUTH_CODE_DO_NOT_LEAK",
            "redirect_uri": "https://attacker.invalid/callback",
        },
    )
    assert response.status_code == 303, response.text
    assert provider.calls[0][2] == transaction.redirect_uri
    assert vault.writes


def test_oauth_callback_http_replay_cannot_write_vault_twice(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, _service_double = _client(monkeypatch, principal, transaction)
    params = {"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"}
    first = _get(client, "/connectors/oauth/google/callback", params=params)
    replay = _get(client, "/connectors/oauth/google/callback", params=params)
    assert first.status_code == 303
    assert replay.status_code == 400
    assert len(vault.writes) == 1
    assert len(provider.calls) == 1


def test_oauth_callback_http_expired_transaction_is_rejected(monkeypatch):
    principal = _principal()
    transaction = _transaction(
        principal, expires_at=(datetime.now(UTC) - timedelta(seconds=1)).timestamp()
    )
    client, provider, vault, _service_double = _client(monkeypatch, principal, transaction)
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )
    assert response.status_code == 400
    assert provider.calls == [] and vault.writes == []


def test_oauth_callback_http_pkce_mismatch_does_not_persist_refresh_token(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal, verifier="tampered-verifier")
    client, provider, vault, fake_service = _client(monkeypatch, principal, transaction)
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )
    assert response.status_code == 503
    assert len(provider.calls) == 1
    assert vault.writes == []
    assert fake_service.connected == []
    assert "tampered-verifier" not in response.text


def test_oauth_callback_http_provider_denial_is_safe_and_has_no_token_side_effects(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, fake_service = _client(monkeypatch, principal, transaction)
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "error": "access_denied"},
    )
    assert response.status_code == 400
    assert provider.calls == [] and vault.writes == []
    assert fake_service.failed


def test_oauth_callback_http_invalid_provider_configuration_is_sanitized(monkeypatch):
    principal = _principal()
    transaction = _transaction(principal)
    client, provider, vault, fake_service = _client(monkeypatch, principal, transaction)

    def unavailable_configuration():
        raise HTTPException(status_code=503, detail="Google Drive is not configured")

    monkeypatch.setattr(connectors, "_oauth", unavailable_configuration)
    response = _get(
        client,
        "/connectors/oauth/google/callback",
        params={"state": transaction.state, "code": "TEST_OAUTH_CODE_DO_NOT_LEAK"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "Google Drive is not configured"}
    assert provider.calls == [] and vault.writes == [] and fake_service.connected == []
    assert "TEST_OAUTH_CODE_DO_NOT_LEAK" not in response.text
