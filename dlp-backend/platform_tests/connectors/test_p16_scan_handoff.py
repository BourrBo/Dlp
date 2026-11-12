"""P16 must route normalized Drive metadata through the shared scan boundary."""

from datetime import UTC, datetime
from uuid import uuid4

from dlp_platform.connectors import models
from dlp_platform.contracts.common import ActorType, AuthMethod, DataChannel, PolicyAction, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_result import ScanResult
from dlp_platform.routes import connectors


def test_drive_object_is_sent_to_existing_scan_pipeline(monkeypatch) -> None:
    principal = Principal(
        organization_id=uuid4(),
        subject_id="drive-user",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        auth_method=AuthMethod.SSO,
    )
    connector_id = uuid4()
    obj = models.DriveObject(
        object_id="drive-file-1",
        name="Quarterly.txt",
        mime_type="text/plain",
        permissions=({"id": "public", "type": "anyone", "role": "reader"},),
    )
    observed: dict[str, object] = {}

    def fake_scan(request, actual_principal):
        observed["request"] = request
        observed["principal"] = actual_principal
        return ScanResult(
            scan_id=uuid4(),
            request_id=request.request_id,
            decision=PolicyAction.BLOCK,
            reason="fixture policy decision",
            completed_at=datetime.now(UTC),
        )

    monkeypatch.setattr(connectors, "scan", fake_scan)
    result = connectors._scan_drive_object(principal, connector_id, obj)

    request = observed["request"]
    assert observed["principal"] is principal
    assert request.channel is DataChannel.CLOUD_STORAGE
    assert request.context["connector_id"] == str(connector_id)
    assert request.context["object_id"] == obj.object_id
    assert '"name":"Quarterly.txt"' in request.content.get_secret_value()
    assert result == {
        "object_id": obj.object_id,
        "decision": "block",
        "finding_count": 0,
        "action_status": "not_executed",
        "request_id": str(request.request_id),
    }


def test_connector_action_metadata_uses_backend_only_private_channel(monkeypatch) -> None:
    principal = Principal(
        organization_id=uuid4(),
        subject_id="drive-owner",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        auth_method=AuthMethod.SSO,
    )
    connector_id = uuid4()
    obj = models.DriveObject(object_id="file-1", name="doc", mime_type="text/plain")
    observed = {}

    def fake_scan(request, actual_principal):
        observed["request"] = request
        observed["principal"] = actual_principal
        return ScanResult(
            scan_id=uuid4(),
            request_id=request.request_id,
            decision=PolicyAction.REVOKE_SHARE,
            reason="fixture action",
            completed_at=datetime.now(UTC),
        )

    monkeypatch.setattr(connectors, "scan", fake_scan)
    connectors._scan_drive_object(
        principal,
        connector_id,
        obj,
        extra_context={
            "permission_id": "permission-1",
            "requested_action": "revoke_share",
            "organization_id": str(uuid4()),
        },
    )

    request = observed["request"]
    assert observed["principal"] is principal
    assert request.context["organization_id"] == str(principal.organization_id)
    assert request._trusted_action_metadata == {
        "provider": "google_drive",
        "connector_id": str(connector_id),
        "drive_object_id": obj.object_id,
        "permission_id": "permission-1",
    }
