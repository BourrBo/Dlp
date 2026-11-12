"""Deterministic connector/OAuth/provider tests; no real Google credentials or traffic."""

import base64
import hashlib
import json
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest

from dlp_platform.connectors.google_drive import (
    GOOGLE_API_HOSTS,
    GOOGLE_AUTHORIZATION_ENDPOINT,
    GOOGLE_DRIVE_SCOPE,
    GoogleDriveAPI,
    GoogleOAuthClient,
    GoogleOAuthSettings,
    ProviderFailure,
)
from dlp_platform.connectors.models import (
    ConnectorIdentity,
    ConnectorStatus,
    DriveObject,
    ExposureKind,
    ShareRevocation,
    SyncRequest,
    validate_status_transition,
)
from dlp_platform.connectors.oauth import (
    OAuthRejected,
    OAuthTransactions,
    authorization_url,
    validate_provider_endpoint,
)


class FixtureTransport:
    def __init__(self, responses: list[bytes | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def request(self, method, url, *, headers, body=None, max_bytes=2_000_000):
        self.calls.append((method, url, dict(headers), body))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        assert len(response) <= max_bytes
        return response


def test_oauth_state_is_bound_to_principal_tenant_provider_and_one_time() -> None:
    store = OAuthTransactions()
    org, other_org = uuid4(), uuid4()
    transaction, challenge = store.create(
        organization_id=org,
        principal_id="user-a",
        provider="google_drive",
        redirect_uri="https://dlp.example.com/connectors/google/callback",
    )
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(transaction.verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    assert challenge == expected
    with pytest.raises(OAuthRejected):
        store.consume(
            transaction.state,
            organization_id=other_org,
            principal_id="user-a",
            provider="google_drive",
        )
    with pytest.raises(OAuthRejected):
        store.consume(
            transaction.state, organization_id=org, principal_id="forged", provider="google_drive"
        )
    assert (
        store.consume(
            transaction.state, organization_id=org, principal_id="user-a", provider="google_drive"
        )
        == transaction
    )
    with pytest.raises(OAuthRejected):
        store.consume(
            transaction.state, organization_id=org, principal_id="user-a", provider="google_drive"
        )


def test_authorization_url_uses_fixed_google_host_and_pkce() -> None:
    url = authorization_url(
        endpoint=GOOGLE_AUTHORIZATION_ENDPOINT,
        allowed_hosts=frozenset({"accounts.google.com"}),
        client_id="synthetic-client",
        redirect_uri="https://dlp.example/callback",
        scopes=(GOOGLE_DRIVE_SCOPE,),
        state="random-state",
        challenge="challenge",
    )
    params = parse_qs(urlparse(url).query)
    assert params["code_challenge_method"] == ["S256"]
    assert params["access_type"] == ["offline"]
    assert params["scope"] == [GOOGLE_DRIVE_SCOPE]
    with pytest.raises(OAuthRejected):
        authorization_url(
            endpoint="https://127.0.0.1/token",
            allowed_hosts=frozenset({"accounts.google.com"}),
            client_id="x",
            redirect_uri="https://dlp.example/callback",
            scopes=(),
            state="x",
            challenge="x",
        )


def test_oauth_code_exchange_and_token_refresh_use_fixed_endpoint_and_pkce() -> None:
    transport = FixtureTransport(
        [
            b'{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","scope":"drive","token_type":"Bearer"}',
            b'{"access_token":"synthetic-new-access","expires_in":3600}',
        ]
    )
    client = GoogleOAuthClient(
        GoogleOAuthSettings(
            client_id="synthetic-client",
            client_secret="synthetic-secret",
            redirect_uri="https://dlp.example/callback",
        ),
        transport,
    )
    code_result = client.exchange(
        "synthetic-code", "synthetic-verifier", "https://dlp.example/callback"
    )
    refreshed = client.refresh("synthetic-refresh")
    assert code_result["refresh_token"] == "synthetic-refresh"
    assert refreshed["access_token"] == "synthetic-new-access"
    assert all("oauth2.googleapis.com/token" in call[1] for call in transport.calls)
    assert b"code_verifier=synthetic-verifier" in transport.calls[0][3]
    assert b"synthetic-secret" in transport.calls[0][3]
    with pytest.raises(ProviderFailure, match="invalid_oauth_callback"):
        client.exchange("code", "verifier", "https://attacker.example/callback")


def test_refresh_invalid_grant_requires_reauthentication() -> None:
    transport = FixtureTransport([ProviderFailure("authorization_failed")])
    client = GoogleOAuthClient(
        GoogleOAuthSettings(
            client_id="synthetic-client",
            client_secret="synthetic-secret",
            redirect_uri="https://dlp.example/callback",
        ),
        transport,
    )
    with pytest.raises(ProviderFailure, match="reauth_required"):
        client.refresh("synthetic-refresh")
    with pytest.raises(OAuthRejected):
        validate_provider_endpoint("https://internal.example/metadata", GOOGLE_API_HOSTS)
    with pytest.raises(OAuthRejected):
        validate_provider_endpoint("https://www.googleapis.com:444/drive/v3", GOOGLE_API_HOSTS)


def test_drive_change_pagination_advances_only_to_successful_checkpoint() -> None:
    transport = FixtureTransport(
        [
            json.dumps(
                {
                    "changes": [
                        {
                            "fileId": "f1",
                            "file": {"id": "f1", "name": "A", "mimeType": "text/plain"},
                        }
                    ],
                    "nextPageToken": "page-2",
                }
            ).encode(),
            json.dumps(
                {
                    "changes": [
                        {
                            "fileId": "f2",
                            "removed": True,
                            "file": {"id": "f2", "name": "B", "mimeType": "text/plain"},
                        }
                    ],
                    "newStartPageToken": "checkpoint-2",
                }
            ).encode(),
        ]
    )
    api = GoogleDriveAPI(
        "synthetic-token", transport, sleeper=lambda _: None, random_value=lambda: 0
    )
    result = api.list_changes(
        SyncRequest(
            identity=ConnectorIdentity(
                connector_id=uuid4(), organization_id=uuid4(), provider="google_drive"
            ),
            checkpoint="checkpoint-1",
            max_changes=10,
        )
    )
    assert [change.change_type for change in result.changes] == ["modified", "deleted"]
    assert [change.object.object_id for change in result.changes] == ["f1", "f2"]
    assert result.next_checkpoint == "checkpoint-2" and result.has_more is False
    assert all(
        "supportsAllDrives=true" in call[1] or "pageToken=" in call[1] for call in transport.calls
    )


def test_drive_initial_inventory_is_bounded_paged_and_shared_drive_aware() -> None:
    transport = FixtureTransport(
        [
            json.dumps(
                {
                    "files": [
                        {"id": "doc-1", "name": "One", "mimeType": "text/plain"},
                        {"id": "doc-2", "name": "Two", "mimeType": "text/plain", "trashed": True},
                    ],
                    "nextPageToken": "next-page",
                }
            ).encode()
        ]
    )
    page = GoogleDriveAPI("synthetic-token", transport).list_inventory_page(page_size=2)
    assert [obj.object_id for obj in page.objects] == ["doc-1", "doc-2"]
    assert page.next_page_token == "next-page"
    params = parse_qs(urlparse(transport.calls[0][1]).query)
    assert params["supportsAllDrives"] == ["true"]
    assert params["includeItemsFromAllDrives"] == ["true"]
    assert params["corpora"] == ["allDrives"]
    assert params["q"] == ["trashed = false"]
    assert "pageToken" not in params

    second_transport = FixtureTransport([b'{"files":[]}'])
    GoogleDriveAPI("synthetic-token", second_transport).list_inventory_page(
        page_token="next-page", page_size=2
    )
    assert parse_qs(urlparse(second_transport.calls[0][1]).query)["pageToken"] == ["next-page"]


def test_drive_pagination_repeated_tokens_fail_bounded() -> None:
    same_page = json.dumps({"changes": [], "nextPageToken": "loop"}).encode()
    transport = FixtureTransport([same_page, same_page])
    api = GoogleDriveAPI("synthetic-token", transport, sleeper=lambda _: None)
    request = SyncRequest(
        identity=ConnectorIdentity(
            connector_id=uuid4(), organization_id=uuid4(), provider="google_drive"
        ),
        checkpoint="loop",
    )
    with pytest.raises(ProviderFailure, match="repeated_page_token"):
        api.list_changes(request)


def test_drive_retry_is_bounded_and_nonretryable_is_not_retried() -> None:
    transport = FixtureTransport(
        [ProviderFailure("rate_limited", retryable=True), b'{"startPageToken":"next"}']
    )
    sleeps: list[float] = []
    api = GoogleDriveAPI(
        "synthetic-token", transport, sleeper=sleeps.append, random_value=lambda: 0
    )
    assert api.get_start_page_token() == "next"
    assert len(transport.calls) == 2 and len(sleeps) == 1
    denied = FixtureTransport([ProviderFailure("authorization_failed")])
    with pytest.raises(ProviderFailure):
        GoogleDriveAPI("synthetic-token", denied, sleeper=sleeps.append).get_start_page_token()
    assert len(denied.calls) == 1


@pytest.mark.parametrize(
    ("permission", "expected"),
    [
        ({"id": "p1", "type": "anyone", "allowFileDiscovery": True}, ExposureKind.PUBLIC),
        ({"id": "p2", "type": "anyone", "allowFileDiscovery": False}, ExposureKind.LINK),
        ({"id": "p3", "type": "domain", "domain": "outside.test"}, ExposureKind.DOMAIN),
        ({"id": "p4", "type": "user", "emailAddress": "x@outside.test"}, ExposureKind.USERS),
        ({"id": "p5", "type": "mystery"}, ExposureKind.UNKNOWN),
    ],
)
def test_exposure_classifies_google_permission_types(permission, expected) -> None:
    obj = DriveObject(
        object_id="file-1", name="synthetic", mime_type="text/plain", permissions=(permission,)
    )
    exposure = GoogleDriveAPI.detect_exposure(obj)[0]
    assert exposure.kind == expected
    assert exposure.object_id == "file-1"


def test_share_revocation_uses_encoded_ids_and_normalizes_absent_permission() -> None:
    file_with_permission = b'{"id":"file /x","permissions":[{"id":"permission?1"}]}'
    file_without_permission = b'{"id":"file /x","permissions":[]}'
    transport = FixtureTransport([file_with_permission, b"{}", file_without_permission])
    api = GoogleDriveAPI("synthetic-token", transport)
    result = api.revoke_share(ShareRevocation(object_id="file /x", permission_id="permission?1"))
    assert result.succeeded and result.outcome == "revoked"
    assert len(transport.calls) == 3
    assert "/files/file%20%2Fx/permissions/permission%3F1" in transport.calls[1][1]
    already_gone = FixtureTransport([b'{"id":"f","permissions":[]}'])
    result = GoogleDriveAPI("synthetic-token", already_gone).revoke_share(
        ShareRevocation(object_id="f", permission_id="p")
    )
    assert result.succeeded and result.outcome == "already_absent"


def test_connector_lifecycle_rejects_unsafe_jumps() -> None:
    validate_status_transition(ConnectorStatus.DISCONNECTED, ConnectorStatus.CONNECTING)
    validate_status_transition(ConnectorStatus.CONNECTED, ConnectorStatus.REAUTH_REQUIRED)
    with pytest.raises(ValueError, match="Invalid connector transition"):
        validate_status_transition(ConnectorStatus.DISCONNECTED, ConnectorStatus.CONNECTED)


def test_shortcut_deduplication_key_and_quarantine_is_honest() -> None:
    obj = GoogleDriveAPI._file(
        {
            "id": "shortcut-1",
            "name": "Shortcut",
            "mimeType": "application/vnd.google-apps.shortcut",
            "shortcutDetails": {"targetId": "real-1"},
        }
    )
    assert obj.is_shortcut and obj.shortcut_target_id == "real-1"
    identity = obj.shortcut_target_id or obj.object_id
    assert identity == "real-1"
    quarantine = GoogleDriveAPI("synthetic-token", FixtureTransport([])).quarantine("real-1")
    assert not quarantine.succeeded and quarantine.outcome == "quarantine_folder_not_configured"


def test_google_metadata_normalization_rejects_malformed_response_and_caps_permissions() -> None:
    with pytest.raises(ProviderFailure, match="malformed_provider_response"):
        GoogleDriveAPI._file([])
    raw = {
        "id": "file",
        "permissions": [{"id": str(index), "type": "user"} for index in range(1001)],
    }
    with pytest.raises(ProviderFailure, match="malformed_provider_response"):
        GoogleDriveAPI._file(raw)
