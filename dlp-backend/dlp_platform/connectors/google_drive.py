"""Google Drive v3 integration. Only fixed Google hosts and normalized metadata leave here."""

import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from dlp_platform.connectors.models import (
    ActionResult,
    ConnectorHealth,
    ConnectorIdentity,
    ConnectorStatus,
    DriveObject,
    Exposure,
    ExposureKind,
    InventoryPage,
    NormalizedChange,
    ShareRevocation,
    SyncRequest,
    SyncResult,
)
from dlp_platform.connectors.oauth import OAuthRejected, validate_provider_endpoint

logger = logging.getLogger(__name__)
GOOGLE_OAUTH_HOSTS = frozenset({"accounts.google.com", "oauth2.googleapis.com"})
GOOGLE_API_HOSTS = frozenset({"www.googleapis.com"})
GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
GOOGLE_DRIVE_BASE = "https://www.googleapis.com/drive/v3"
# Broad restricted scope is necessary here: this connector monitors existing
# Drive objects, changes sharing permissions and moves exposed objects.
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
MAX_RESPONSE_BYTES = 2_000_000


class ProviderFailure(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class ProviderTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> bytes: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class GoogleTransport:
    """Bounded HTTPS transport with redirects disabled and exact host validation."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> bytes:
        parsed = urllib.parse.urlparse(url)
        if parsed.path.startswith("/drive/"):
            validate_provider_endpoint(url, GOOGLE_API_HOSTS)
        elif parsed.hostname in GOOGLE_OAUTH_HOSTS:
            validate_provider_endpoint(url, GOOGLE_OAUTH_HOSTS)
        else:
            raise OAuthRejected("Google endpoint is not allowlisted")
        opener = urllib.request.build_opener(_NoRedirect)
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with opener.open(request, timeout=10) as response:
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise ProviderFailure("response_too_large")
                return cast(bytes, data)
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504):
                raise ProviderFailure(
                    "rate_limited" if exc.code == 429 else "transient_provider_error",
                    retryable=True,
                ) from None
            if exc.code == 400 and parsed.path == "/token":
                raise ProviderFailure("authorization_failed") from None
            if exc.code == 403:
                try:
                    payload = json.loads(exc.read(MAX_RESPONSE_BYTES))
                    error = payload.get("error", {})
                    reasons = {
                        item.get("reason")
                        for item in error.get("errors", [])
                        if isinstance(item, dict)
                    }
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                    reasons = set()
                if reasons & {"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"}:
                    raise ProviderFailure("rate_limited", retryable=True) from None
                raise ProviderFailure("authorization_failed") from None
            if exc.code == 401:
                raise ProviderFailure("authorization_failed") from None
            if exc.code == 404:
                raise ProviderFailure("not_found") from None
            raise ProviderFailure("provider_request_failed") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProviderFailure("transient_provider_error", retryable=True) from None


def _json(data: bytes) -> dict[str, object]:
    try:
        result = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderFailure("malformed_provider_response") from None
    if not isinstance(result, dict):
        raise ProviderFailure("malformed_provider_response")
    return result


@dataclass(frozen=True)
class GoogleOAuthSettings:
    client_id: str
    client_secret: str
    redirect_uri: str

    @classmethod
    def from_environment(cls) -> "GoogleOAuthSettings":
        import os

        client_id, secret, redirect = (
            os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
            os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""),
            os.getenv("GOOGLE_OAUTH_REDIRECT_URI", ""),
        )
        if not client_id or not secret or not redirect:
            raise ProviderFailure("provider_not_configured")
        parsed = urllib.parse.urlparse(redirect)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ProviderFailure("invalid_provider_configuration")
        return cls(client_id, secret, redirect)


class GoogleOAuthClient:
    def __init__(self, settings: GoogleOAuthSettings, transport: ProviderTransport) -> None:
        self.settings, self.transport = settings, transport

    def exchange(self, code: str, verifier: str, redirect_uri: str) -> dict[str, object]:
        if redirect_uri != self.settings.redirect_uri or not code or len(code) > 4096:
            raise ProviderFailure("invalid_oauth_callback")
        body = urllib.parse.urlencode(
            {
                "code": code,
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": verifier,
            }
        ).encode()
        return _json(
            self.transport.request(
                "POST",
                GOOGLE_TOKEN_ENDPOINT,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body,
            )
        )

    def refresh(self, refresh_token: str) -> dict[str, object]:
        body = urllib.parse.urlencode(
            {
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
        ).encode()
        try:
            return _json(
                self.transport.request(
                    "POST",
                    GOOGLE_TOKEN_ENDPOINT,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=body,
                )
            )
        except ProviderFailure as exc:
            if exc.code == "authorization_failed":
                raise ProviderFailure("reauth_required") from None
            raise

    def revoke(self, token: str) -> None:
        body = urllib.parse.urlencode({"token": token}).encode()
        self.transport.request(
            "POST",
            GOOGLE_REVOKE_ENDPOINT,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )


class GoogleDriveAPI:
    def __init__(
        self,
        access_token: str,
        transport: ProviderTransport | None = None,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        random_value: Callable[[], float] = random.random,
    ) -> None:
        if not access_token or len(access_token) > 8192:
            raise ValueError("Invalid access token")
        self._token = access_token
        self._http = transport or GoogleTransport()
        self._sleep, self._random = sleeper, random_value

    def _request(
        self, method: str, path: str, params: Mapping[str, str] | None = None
    ) -> dict[str, object]:
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("Invalid Drive API path")
        query = urllib.parse.urlencode(params or {})
        url = f"{GOOGLE_DRIVE_BASE}{path}" + (f"?{query}" if query else "")
        for attempt in range(4):
            try:
                data = self._http.request(
                    method,
                    url,
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Accept": "application/json",
                    },
                )
                return _json(data) if data else {}
            except ProviderFailure as exc:
                if not exc.retryable or attempt == 3:
                    raise
                self._sleep(min(8.0, 0.25 * (2**attempt)) * (0.5 + self._random()))
        raise ProviderFailure("transient_provider_error", retryable=True)

    @staticmethod
    def _file(raw: object) -> DriveObject:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise ProviderFailure("malformed_provider_response")
        shortcut = raw.get("shortcutDetails")
        shortcut_target = shortcut.get("targetId") if isinstance(shortcut, dict) else None
        raw_permissions = raw.get("permissions", [])
        if not isinstance(raw_permissions, list) or len(raw_permissions) > 1000:
            raise ProviderFailure("malformed_provider_response")
        permissions: list[dict[str, str | bool | None]] = []
        for permission in raw_permissions:
            if not isinstance(permission, dict):
                raise ProviderFailure("malformed_provider_response")
            fields = {
                key: permission.get(key)
                for key in (
                    "id",
                    "type",
                    "role",
                    "emailAddress",
                    "domain",
                    "allowFileDiscovery",
                    "deleted",
                )
            }
            if any(
                value is not None and not isinstance(value, (str, bool))
                for value in fields.values()
            ):
                raise ProviderFailure("malformed_provider_response")
            permissions.append(fields)
        return DriveObject(
            object_id=raw["id"],
            name=str(raw.get("name", ""))[:1024],
            mime_type=str(raw.get("mimeType", "application/octet-stream"))[:256],
            size_bytes=int(raw["size"])
            if raw.get("size") is not None and str(raw["size"]).isdigit()
            else None,
            modified_at=raw.get("modifiedTime"),
            web_view_link=raw.get("webViewLink"),
            shared_drive_id=raw.get("driveId"),
            is_shortcut=isinstance(shortcut, dict),
            shortcut_target_id=shortcut_target if isinstance(shortcut_target, str) else None,
            removed=raw.get("trashed") is True or raw.get("removed") is True,
            permissions=tuple(permissions),
        )

    def get_start_page_token(self, *, include_shared_drives: bool = True) -> str:
        data = self._request(
            "GET",
            "/changes/startPageToken",
            {"supportsAllDrives": "true", "includeItemsFromAllDrives": "true"}
            if include_shared_drives
            else {},
        )
        token = data.get("startPageToken")
        if not isinstance(token, str) or not token or len(token) > 2048:
            raise ProviderFailure("malformed_provider_response")
        return token

    def list_inventory_page(
        self, *, page_token: str | None = None, page_size: int = 100
    ) -> InventoryPage:
        """Fetch one bounded inventory page; callers persist the cursor per page."""
        if not 1 <= page_size <= 1000:
            raise ValueError("Invalid Drive inventory page size")
        if page_token is not None and (not page_token or len(page_token) > 2048):
            raise ValueError("Invalid Drive inventory page token")
        params = {
            "pageSize": str(page_size),
            "q": "trashed = false",
            "corpora": "allDrives",
            "includeItemsFromAllDrives": "true",
            "supportsAllDrives": "true",
            "spaces": "drive",
            "fields": (
                "nextPageToken,files(id,name,mimeType,size,modifiedTime,webViewLink,driveId,"
                "shortcutDetails,permissions(id,type,role,emailAddress,domain,"
                "allowFileDiscovery,deleted,permissionDetails(inherited)))"
            ),
        }
        if page_token is not None:
            params["pageToken"] = page_token
        raw = self._request("GET", "/files", params)
        items = raw.get("files", [])
        if not isinstance(items, list) or len(items) > page_size:
            raise ProviderFailure("malformed_provider_response")
        objects = tuple(self._file(item) for item in items)
        next_token = raw.get("nextPageToken")
        if next_token is not None and (
            not isinstance(next_token, str) or not next_token or len(next_token) > 2048
        ):
            raise ProviderFailure("malformed_provider_response")
        if next_token == page_token:
            raise ProviderFailure("repeated_page_token")
        return InventoryPage(objects=objects, next_page_token=next_token)

    def list_changes(self, request: SyncRequest) -> SyncResult:
        token = request.checkpoint or self.get_start_page_token()
        seen: set[str] = set()
        result: list[NormalizedChange] = []
        seen_objects: set[str] = set()
        cursor = token
        while len(result) < request.max_changes:
            if cursor in seen:
                raise ProviderFailure("repeated_page_token")
            seen.add(cursor)
            raw = self._request(
                "GET",
                "/changes",
                {
                    "pageToken": cursor,
                    "pageSize": str(min(100, request.max_changes - len(result))),
                    "supportsAllDrives": "true",
                    "includeItemsFromAllDrives": "true",
                    "fields": (
                        "nextPageToken,newStartPageToken,changes(fileId,removed,file("
                        "id,name,mimeType,size,modifiedTime,webViewLink,driveId,"
                        "shortcutDetails,permissions(id,type,role,emailAddress,domain,"
                        "allowFileDiscovery,deleted)))"
                    ),
                },
            )
            batch = raw.get("changes", [])
            if not isinstance(batch, list):
                raise ProviderFailure("malformed_provider_response")
            for change in batch:
                if not isinstance(change, dict):
                    raise ProviderFailure("malformed_provider_response")
                file_raw = change.get("file")
                if file_raw is None:
                    file_raw = {"id": change.get("fileId"), "removed": change.get("removed", False)}
                if not isinstance(file_raw, dict):
                    raise ProviderFailure("malformed_provider_response")
                obj = self._file(file_raw)
                dedupe_id = obj.shortcut_target_id if obj.is_shortcut else obj.object_id
                if dedupe_id is not None and dedupe_id in seen_objects:
                    continue
                if dedupe_id is not None:
                    seen_objects.add(dedupe_id)
                kind = "deleted" if change.get("removed") is True else "modified"
                result.append(NormalizedChange(object=obj, change_type=kind))
                if len(result) == request.max_changes:
                    break
            next_token = raw.get("nextPageToken")
            if isinstance(next_token, str):
                cursor = next_token
                continue
            checkpoint = raw.get("newStartPageToken")
            if checkpoint is not None and (
                not isinstance(checkpoint, str) or len(checkpoint) > 2048
            ):
                raise ProviderFailure("malformed_provider_response")
            return SyncResult(
                changes=tuple(result), next_checkpoint=checkpoint or cursor, has_more=False
            )
        return SyncResult(changes=tuple(result), next_checkpoint=cursor, has_more=True)

    def get_file(self, file_id: str) -> DriveObject:
        if not file_id or len(file_id) > 1024:
            raise ValueError("Invalid Google Drive file identifier")
        encoded = urllib.parse.quote(file_id, safe="")
        data = self._request(
            "GET",
            f"/files/{encoded}",
            {
                "supportsAllDrives": "true",
                "fields": (
                    "id,name,mimeType,size,modifiedTime,webViewLink,driveId,shortcutDetails,"
                    "permissions(id,type,role,emailAddress,domain,allowFileDiscovery,deleted)"
                ),
            },
        )
        return self._file(data)

    @staticmethod
    def detect_exposure(
        obj: DriveObject, *, tenant_domains: frozenset[str] = frozenset()
    ) -> tuple[Exposure, ...]:
        kind = ExposureKind.PRIVATE
        principals: list[str] = []
        permissions: list[str] = []
        for permission in obj.permissions:
            if permission.get("deleted") is True:
                continue
            ptype = permission.get("type")
            identifier = permission.get("id")
            if isinstance(identifier, str):
                permissions.append(identifier)
            if ptype == "anyone":
                kind = (
                    ExposureKind.PUBLIC
                    if permission.get("allowFileDiscovery") is True
                    else ExposureKind.LINK
                )
            elif ptype == "domain":
                domain = permission.get("domain")
                principals.append(
                    f"domain:{domain}" if isinstance(domain, str) else "domain:unknown"
                )
                if kind not in {ExposureKind.PUBLIC, ExposureKind.LINK}:
                    kind = ExposureKind.DOMAIN if isinstance(domain, str) else ExposureKind.UNKNOWN
            elif ptype == "user" or ptype == "group":
                email = permission.get("emailAddress")
                if isinstance(email, str):
                    principals.append(email)
                    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
                    if not domain or not tenant_domains or domain not in tenant_domains:
                        kind = ExposureKind.USERS if kind == ExposureKind.PRIVATE else kind
                elif kind == ExposureKind.PRIVATE:
                    kind = ExposureKind.UNKNOWN
            elif ptype is not None and ptype not in {"user", "group", "domain", "anyone"}:
                kind = ExposureKind.UNKNOWN
        return (
            Exposure(
                object_id=obj.object_id,
                kind=kind,
                principals=tuple(principals),
                permission_ids=tuple(permissions),
            ),
        )

    def revoke_share(self, action: ShareRevocation) -> ActionResult:
        current = self.get_file(action.object_id)
        if not any(item.get("id") == action.permission_id for item in current.permissions):
            return ActionResult(succeeded=True, outcome="already_absent")
        file_id, permission_id = (
            urllib.parse.quote(action.object_id, safe=""),
            urllib.parse.quote(action.permission_id, safe=""),
        )
        try:
            self._request(
                "DELETE",
                f"/files/{file_id}/permissions/{permission_id}",
                {"supportsAllDrives": "true"},
            )
            remaining = self.get_file(action.object_id)
            if any(item.get("id") == action.permission_id for item in remaining.permissions):
                return ActionResult(succeeded=False, outcome="verification_failed")
            return ActionResult(succeeded=True, outcome="revoked")
        except ProviderFailure as exc:
            if exc.code == "not_found":
                return ActionResult(succeeded=True, outcome="already_absent")
            return ActionResult(succeeded=False, outcome=exc.code)

    def quarantine(self, object_id: str) -> ActionResult:
        # No unsafe implicit move: deployments must first provision and authorize
        # a tenant-controlled quarantine folder and bind it in trusted config.
        if not object_id or len(object_id) > 1024:
            raise ValueError("Invalid Google Drive file identifier")
        return ActionResult(succeeded=False, outcome="quarantine_folder_not_configured")


class GoogleDriveConnector:
    """Provider implementation composed behind the provider-neutral connector contract."""

    def __init__(self, api: GoogleDriveAPI) -> None:
        self.api = api
        self._states: dict[str, ConnectorStatus] = {}

    def connect(self, identity: ConnectorIdentity) -> ConnectorHealth:
        self._states[str(identity.connector_id)] = ConnectorStatus.CONNECTED
        return ConnectorHealth(identity=identity, status=ConnectorStatus.CONNECTED)

    def status(self, identity: ConnectorIdentity) -> ConnectorHealth:
        return ConnectorHealth(
            identity=identity,
            status=self._states.get(str(identity.connector_id), ConnectorStatus.DISCONNECTED),
        )

    def sync(self, request: SyncRequest) -> SyncResult:
        try:
            return self.api.list_changes(request)
        except ProviderFailure as exc:
            self._states[str(request.identity.connector_id)] = (
                ConnectorStatus.REAUTH_REQUIRED
                if exc.code == "reauth_required"
                else ConnectorStatus.DEGRADED
            )
            raise

    def detect_exposure(self, obj: DriveObject) -> tuple[Exposure, ...]:
        return self.api.detect_exposure(obj)

    def revoke_share(self, action: ShareRevocation) -> ActionResult:
        return self.api.revoke_share(action)

    def quarantine(self, object_id: str) -> ActionResult:
        return self.api.quarantine(object_id)

    def disconnect(self, identity: ConnectorIdentity) -> ConnectorHealth:
        self._states[str(identity.connector_id)] = ConnectorStatus.DISCONNECTED
        return ConnectorHealth(identity=identity, status=ConnectorStatus.DISCONNECTED)
