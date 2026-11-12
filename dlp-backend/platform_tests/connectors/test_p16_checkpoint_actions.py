"""Checkpoint advancement depends on scan and connector action completion."""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException, Response
from pydantic import SecretStr
from starlette.requests import Request

from dlp_platform.connectors.models import DriveObject
from dlp_platform.contracts.common import ActorType, AuthMethod, PolicyAction, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.routes import connectors


class FakeService:
    def __init__(self):
        self.completions = []
        self.degraded = []

    def sync_inputs(self, session, principal, connector_id):
        del session, principal
        return uuid4(), "checkpoint-before", {}

    def complete_sync(self, *args, **kwargs):
        self.completions.append((args, kwargs))

    def mark_degraded(self, *args, **kwargs):
        self.degraded.append((args, kwargs))


class FakeSession:
    def rollback(self):
        pass


class FakeVault:
    def get_for_trusted_service(self, *args, **kwargs):
        del args, kwargs
        return SecretStr("TEST_REFRESH_TOKEN_DO_NOT_LEAK")


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/connectors/00000000-0000-4000-8000-000000000001/sync",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "state": {},
        }
    )


def _principal() -> Principal:
    return Principal(
        organization_id=uuid4(),
        subject_id="sync-owner",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("connectors:write",),
        auth_method=AuthMethod.SSO,
        member_id=uuid4(),
        session_id=uuid4(),
    )


def _run_sync(monkeypatch, scan_result):
    service = FakeService()
    connector_id = uuid4()
    principal = _principal()

    class FakeOAuth:
        def refresh(self, token):
            assert token == "TEST_REFRESH_TOKEN_DO_NOT_LEAK"
            return {"access_token": "TEST_ACCESS_TOKEN_DO_NOT_LEAK"}

    class FakeDrive:
        def __init__(self, access_token):
            assert access_token == "TEST_ACCESS_TOKEN_DO_NOT_LEAK"

        @staticmethod
        def detect_exposure(obj):
            del obj
            return ()

        def list_changes(self, sync_request):
            assert sync_request.checkpoint == "checkpoint-before"
            obj = DriveObject(object_id="drive-file", name="fixture", mime_type="text/plain")
            return SimpleNamespace(
                changes=(SimpleNamespace(change_type="modified", object=obj),),
                next_checkpoint="checkpoint-after",
                has_more=False,
            )

    monkeypatch.setattr(connectors, "_service", service)
    monkeypatch.setattr(connectors, "_oauth", lambda: (None, FakeOAuth()))
    monkeypatch.setattr(connectors, "GoogleDriveAPI", FakeDrive)
    monkeypatch.setattr(connectors, "_scan_drive_object", lambda *_args, **_kwargs: scan_result)
    result = connectors.sync_google_drive(
        connector_id,
        _request(),
        Response(),
        principal,
        FakeSession(),
        FakeVault(),
    )
    return result, service


def test_checkpoint_advances_after_scan_allow_or_log(monkeypatch):
    result, service = _run_sync(
        monkeypatch,
        {
            "object_id": "drive-file",
            "decision": PolicyAction.ALLOW.value,
            "finding_count": 0,
            "action_status": "not_executed",
        },
    )
    assert result["status"] == "connected"
    assert len(service.completions) == 1
    assert service.completions[0][1]["checkpoint"] == "checkpoint-after"


def test_checkpoint_does_not_advance_after_revoke_action_failure(monkeypatch):
    service = FakeService()
    connector_id = uuid4()
    principal = _principal()

    class FakeOAuth:
        def refresh(self, token):
            del token
            return {"access_token": "TEST_ACCESS_TOKEN_DO_NOT_LEAK"}

    class FakeDrive:
        def __init__(self, access_token):
            del access_token

        @staticmethod
        def detect_exposure(obj):
            del obj
            return ()

        def list_changes(self, sync_request):
            del sync_request
            return SimpleNamespace(
                changes=(
                    SimpleNamespace(
                        change_type="modified",
                        object=DriveObject(
                            object_id="drive-file", name="fixture", mime_type="text/plain"
                        ),
                    ),
                ),
                next_checkpoint="must-not-commit",
                has_more=False,
            )

    monkeypatch.setattr(connectors, "_service", service)
    monkeypatch.setattr(connectors, "_oauth", lambda: (None, FakeOAuth()))
    monkeypatch.setattr(connectors, "GoogleDriveAPI", FakeDrive)
    monkeypatch.setattr(
        connectors,
        "_scan_drive_object",
        lambda *_args, **_kwargs: {
            "object_id": "drive-file",
            "decision": PolicyAction.REVOKE_SHARE.value,
            "finding_count": 1,
            "action_status": "failed",
        },
    )
    with pytest.raises(HTTPException) as error:
        connectors.sync_google_drive(
            connector_id,
            _request(),
            Response(),
            principal,
            FakeSession(),
            FakeVault(),
        )
    assert error.value.status_code == 503
    assert service.completions == []
    assert service.degraded


def test_checkpoint_advances_after_successful_action_result(monkeypatch):
    result, service = _run_sync(
        monkeypatch,
        {
            "object_id": "drive-file",
            "decision": PolicyAction.REVOKE_SHARE.value,
            "finding_count": 1,
            "action_status": "succeeded",
        },
    )
    assert result["status"] == "connected"
    assert len(service.completions) == 1
    assert service.completions[0][1]["checkpoint"] == "checkpoint-after"
