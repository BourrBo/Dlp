from pydantic import SecretStr

from dlp_platform.contracts import DataChannel, ScanRequest


def test_scan_content_is_secret_and_serializes_redacted() -> None:
    request = ScanRequest(
        channel=DataChannel.API,
        content=SecretStr("synthetic sensitive sample"),
    )
    assert "synthetic sensitive sample" not in repr(request)
    assert "synthetic sensitive sample" not in request.model_dump_json()
    assert "**********" in request.model_dump_json()


def test_tenant_identity_is_not_a_scan_request_field() -> None:
    properties = ScanRequest.model_json_schema()["properties"]
    assert "organization_id" not in properties
    assert "org_id" not in properties
    assert "user_id" not in properties
