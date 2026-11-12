"""Microsoft Graph OAuth and drive metadata adapter with fixed-host transport."""

import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from dlp_platform.connectors.models import (
    ActionResult,
    DriveObject,
    Exposure,
    ExposureKind,
    NormalizedChange,
    ShareRevocation,
)
from dlp_platform.connectors.oauth import OAuthRejected, validate_provider_endpoint

logger = logging.getLogger(__name__)
MICROSOFT_LOGIN_HOSTS = frozenset({"login.microsoftonline.com"})
MICROSOFT_GRAPH_HOSTS = frozenset({"graph.microsoft.com"})
MICROSOFT_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
MICROSOFT_SCOPES = (
    "openid",
    "profile",
    "offline_access",
    "User.Read",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
)
MAX_GRAPH_RESPONSE_BYTES = 2_000_000
MAX_GRAPH_LINK_LENGTH = 8192
MAX_GRAPH_PAGE_SIZE = 100


class MicrosoftProviderFailure(RuntimeError):
    """Safe Microsoft provider failure code with no response-body details."""

    def __init__(
        self, code: str, *, retryable: bool = False, retry_after: float | None = None
    ) -> None:
        self.code = code
        self.retryable = retryable
        self.retry_after = retry_after
        super().__init__(code)


class MicrosoftTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        max_bytes: int = MAX_GRAPH_RESPONSE_BYTES,
    ) -> tuple[bytes, Mapping[str, str]]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class MicrosoftHTTPTransport:
    """Bounded HTTPS client; only fixed Microsoft OAuth and Graph hosts are reachable."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        max_bytes: int = MAX_GRAPH_RESPONSE_BYTES,
    ) -> tuple[bytes, Mapping[str, str]]:
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname in MICROSOFT_GRAPH_HOSTS:
            _validate_graph_url(url)
        elif parsed.hostname in MICROSOFT_LOGIN_HOSTS:
            try:
                validate_provider_endpoint(url, MICROSOFT_LOGIN_HOSTS)
            except OAuthRejected:
                raise MicrosoftProviderFailure("provider_endpoint_rejected") from None
            if "/oauth2/v2.0/" not in parsed.path:
                raise MicrosoftProviderFailure("provider_endpoint_rejected")
        else:
            raise MicrosoftProviderFailure("provider_endpoint_rejected")
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=10) as response:
                payload = response.read(max_bytes + 1)
                if len(payload) > max_bytes:
                    raise MicrosoftProviderFailure("response_too_large")
                return payload, response.headers
        except urllib.error.HTTPError as exc:
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            if exc.code in {429, 500, 502, 503, 504}:
                code = "rate_limited" if exc.code == 429 else "transient_provider_error"
                try:
                    delay = min(max(float(retry_after), 0.0), 60.0) if retry_after else None
                except ValueError:
                    delay = None
                raise MicrosoftProviderFailure(code, retryable=True, retry_after=delay) from None
            if exc.code == 401:
                raise MicrosoftProviderFailure("reauth_required") from None
            if exc.code == 400 and "/token" in parsed.path:
                raise MicrosoftProviderFailure("authorization_failed") from None
            if exc.code == 404:
                raise MicrosoftProviderFailure("not_found") from None
            if exc.code == 403:
                raise MicrosoftProviderFailure("authorization_failed") from None
            del retry_after
            raise MicrosoftProviderFailure("provider_request_failed") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise MicrosoftProviderFailure("transient_provider_error", retryable=True) from None


def _validate_graph_url(url: str) -> str:
    try:
        validate_provider_endpoint(url, MICROSOFT_GRAPH_HOSTS)
    except OAuthRejected:
        raise MicrosoftProviderFailure("provider_endpoint_rejected") from None
    parsed = urllib.parse.urlparse(url)
    if not parsed.path.startswith("/v1.0/") or len(url) > MAX_GRAPH_LINK_LENGTH:
        raise MicrosoftProviderFailure("provider_endpoint_rejected")
    return url


def _json(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MicrosoftProviderFailure("malformed_provider_response") from None
    if not isinstance(value, dict):
        raise MicrosoftProviderFailure("malformed_provider_response")
    return value


@dataclass(frozen=True)
class MicrosoftOAuthSettings:
    client_id: str
    client_secret: str
    redirect_uri: str

    @classmethod
    def from_environment(cls) -> "MicrosoftOAuthSettings":
        import os

        client_id = os.getenv("MICROSOFT_OAUTH_CLIENT_ID", "")
        client_secret = os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET", "")
        redirect_uri = os.getenv("MICROSOFT_OAUTH_REDIRECT_URI", "")
        if not client_id or not client_secret or not redirect_uri:
            raise MicrosoftProviderFailure("provider_not_configured")
        parsed = urllib.parse.urlparse(redirect_uri)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise MicrosoftProviderFailure("invalid_provider_configuration")
        return cls(client_id, client_secret, redirect_uri)

    @staticmethod
    def authority(tenant_id: str) -> str:
        try:
            normalized = str(UUID(tenant_id))
        except ValueError:
            raise MicrosoftProviderFailure("invalid_provider_configuration") from None
        return f"https://login.microsoftonline.com/{normalized}/oauth2/v2.0"


class MicrosoftOAuthClient:
    def __init__(self, settings: MicrosoftOAuthSettings, transport: MicrosoftTransport) -> None:
        self.settings = settings
        self.transport = transport

    def exchange(
        self, code: str, verifier: str, redirect_uri: str, tenant_id: str
    ) -> dict[str, object]:
        if redirect_uri != self.settings.redirect_uri or not code or len(code) > 4096:
            raise MicrosoftProviderFailure("invalid_oauth_callback")
        body = urllib.parse.urlencode(
            {
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": verifier,
            }
        ).encode()
        payload, _ = self.transport.request(
            "POST",
            f"{self.settings.authority(tenant_id)}/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        return _json(payload)

    def refresh(self, refresh_token: str, tenant_id: str) -> dict[str, object]:
        body = urllib.parse.urlencode(
            {
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": " ".join(MICROSOFT_SCOPES),
            }
        ).encode()
        payload, _ = self.transport.request(
            "POST",
            f"{self.settings.authority(tenant_id)}/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        return _json(payload)


@dataclass(frozen=True)
class MicrosoftDrivePage:
    objects: tuple[DriveObject, ...]
    next_link: str | None
    delta_link: str | None
    changes: tuple[NormalizedChange, ...]


class MicrosoftGraphAPI:
    def __init__(
        self,
        access_token: str,
        tenant_id: str,
        transport: MicrosoftTransport | None = None,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        random_value: Callable[[], float] = random.random,
    ) -> None:
        if not access_token or len(access_token) > 8192:
            raise ValueError("Invalid Microsoft access token")
        try:
            self.tenant_id = str(UUID(tenant_id))
        except ValueError:
            raise ValueError("Invalid Microsoft tenant identifier") from None
        self._token = access_token
        self._http = transport or MicrosoftHTTPTransport()
        self._sleep = sleeper
        self._random = random_value

    def _request(
        self,
        path_or_url: str,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, object]:
        if path_or_url.startswith("https://"):
            url = _validate_graph_url(path_or_url)
            if params:
                raise ValueError("Cannot add query parameters to a provider continuation URL")
        else:
            if not path_or_url.startswith("/v1.0/") or ".." in path_or_url.split("/"):
                raise ValueError("Invalid Microsoft Graph path")
            url = f"{MICROSOFT_GRAPH_BASE}{path_or_url[5:]}"
            if params:
                url += "?" + urllib.parse.urlencode(params)
            _validate_graph_url(url)
        for attempt in range(4):
            try:
                payload, _ = self._http.request(
                    "GET",
                    url,
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Accept": "application/json",
                    },
                )
                return _json(payload)
            except MicrosoftProviderFailure as exc:
                if not exc.retryable or attempt == 3:
                    raise
                delay = exc.retry_after
                self._sleep(delay if delay is not None else min((2**attempt) + self._random(), 30))
        raise MicrosoftProviderFailure("transient_provider_error", retryable=True)

    def organization_tenant_id(self) -> str:
        raw = self._request("/v1.0/organization", {"$select": "id"}).get("value")
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
            raise MicrosoftProviderFailure("invalid_organization_response")
        identifier = raw[0].get("id")
        try:
            return str(UUID(str(identifier)))
        except ValueError:
            raise MicrosoftProviderFailure("invalid_organization_response") from None

    def onedrive_id(self) -> str:
        raw = self._request("/v1.0/me/drive", {"$select": "id"})
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= 1024:
            raise MicrosoftProviderFailure("malformed_provider_response")
        return identifier

    def search_sites(
        self, query: str, *, page_link: str | None = None
    ) -> tuple[list[dict[str, str]], str | None]:
        if not query or len(query) > 200:
            raise ValueError("Site search query is invalid")
        raw = self._request(
            page_link or "/v1.0/sites",
            None
            if page_link
            else {
                "search": query,
                "$select": "id,name,displayName,webUrl",
                "$top": str(MAX_GRAPH_PAGE_SIZE),
            },
        )
        return self._site_records(raw), self._next_link(raw)

    def list_site_drives(
        self, site_id: str, *, page_link: str | None = None
    ) -> tuple[list[dict[str, str]], str | None]:
        if not site_id or len(site_id) > 1024:
            raise ValueError("SharePoint site identifier is invalid")
        path = page_link or f"/v1.0/sites/{urllib.parse.quote(site_id, safe='')}/drives"
        raw = self._request(
            path,
            None
            if page_link
            else {"$select": "id,name,driveType,webUrl", "$top": str(MAX_GRAPH_PAGE_SIZE)},
        )
        value = raw.get("value")
        if not isinstance(value, list) or len(value) > MAX_GRAPH_PAGE_SIZE:
            raise MicrosoftProviderFailure("malformed_provider_response")
        drives: list[dict[str, str]] = []
        for item in value:
            if not isinstance(item, dict):
                raise MicrosoftProviderFailure("malformed_provider_response")
            identifier, name = item.get("id"), item.get("name")
            drive_type = item.get("driveType")
            if not isinstance(identifier, str) or not isinstance(name, str):
                raise MicrosoftProviderFailure("malformed_provider_response")
            record = {"id": identifier[:1024], "name": name[:1024]}
            if isinstance(drive_type, str):
                record["drive_type"] = drive_type[:64]
            drives.append(record)
        return drives, self._next_link(raw)

    def delta_page(
        self,
        provider: str,
        *,
        drive_id: str,
        site_id: str | None,
        tenant_id: str,
        page_link: str | None = None,
    ) -> MicrosoftDrivePage:
        if not drive_id or len(drive_id) > 1024:
            raise ValueError("Microsoft drive identifier is invalid")
        if provider == "microsoft_onedrive":
            initial_path = "/v1.0/me/drive/root/delta"
        elif provider == "microsoft_sharepoint" and site_id and len(site_id) <= 1024:
            initial_path = f"/v1.0/drives/{urllib.parse.quote(drive_id, safe='')}/root/delta"
        else:
            raise ValueError("Microsoft provider identity is invalid")
        raw = self._request(
            page_link or initial_path,
            None
            if page_link
            else {
                "$top": str(MAX_GRAPH_PAGE_SIZE),
                "$select": (
                    "id,name,size,lastModifiedDateTime,webUrl,file,folder,deleted,"
                    "parentReference,sharepointIds"
                ),
            },
        )
        values = raw.get("value", [])
        if not isinstance(values, list) or len(values) > MAX_GRAPH_PAGE_SIZE:
            raise MicrosoftProviderFailure("malformed_provider_response")
        changes: list[NormalizedChange] = []
        for value in values:
            if not isinstance(value, dict):
                raise MicrosoftProviderFailure("malformed_provider_response")
            if not isinstance(value.get("deleted"), dict):
                value["permissions"] = self.list_permissions(drive_id, str(value.get("id", "")))
            obj = self._drive_object(value, tenant_id=tenant_id, site_id=site_id, drive_id=drive_id)
            change_type = "deleted" if isinstance(value.get("deleted"), dict) else "modified"
            changes.append(NormalizedChange(object=obj, change_type=change_type))
        next_link = self._next_link(raw)
        delta_link = raw.get("@odata.deltaLink")
        if delta_link is not None and (
            not isinstance(delta_link, str) or len(delta_link) > MAX_GRAPH_LINK_LENGTH
        ):
            raise MicrosoftProviderFailure("malformed_provider_response")
        if isinstance(delta_link, str):
            _validate_graph_url(delta_link)
        if next_link is not None and page_link is not None and next_link == page_link:
            raise MicrosoftProviderFailure("repeated_page_link")
        if next_link is not None and delta_link is not None:
            raise MicrosoftProviderFailure("malformed_provider_response")
        return MicrosoftDrivePage(
            objects=tuple(change.object for change in changes),
            next_link=next_link,
            delta_link=delta_link if isinstance(delta_link, str) else None,
            changes=tuple(changes),
        )

    def list_permissions(self, drive_id: str, item_id: str) -> list[dict[str, object]]:
        """Read all direct/inherited sharing grants for one changed item, bounded."""
        if not drive_id or not item_id or len(drive_id) > 1024 or len(item_id) > 1024:
            raise ValueError("Microsoft permission target is invalid")
        path = (
            f"/v1.0/drives/{urllib.parse.quote(drive_id, safe='')}/items/"
            f"{urllib.parse.quote(item_id, safe='')}/permissions"
        )
        permissions: list[dict[str, object]] = []
        seen: set[str] = set()
        for _ in range(10):
            raw = self._request(
                path,
                {"$select": "id,link,inheritedFrom,grantedToV2,grantedToIdentitiesV2"}
                if not seen
                else None,
            )
            values = raw.get("value")
            if not isinstance(values, list) or len(values) > MAX_GRAPH_PAGE_SIZE:
                raise MicrosoftProviderFailure("malformed_provider_response")
            for item in values:
                if not isinstance(item, dict):
                    raise MicrosoftProviderFailure("malformed_provider_response")
                permissions.append(item)
                if len(permissions) > MAX_GRAPH_PAGE_SIZE * 10:
                    raise MicrosoftProviderFailure("too_many_permissions")
            next_link = self._next_link(raw)
            if next_link is None:
                return permissions
            if next_link in seen:
                raise MicrosoftProviderFailure("repeated_page_link")
            seen.add(next_link)
            path = next_link
        raise MicrosoftProviderFailure("too_many_permission_pages")

    @staticmethod
    def _site_records(raw: dict[str, object]) -> list[dict[str, str]]:
        value = raw.get("value")
        if not isinstance(value, list) or len(value) > MAX_GRAPH_PAGE_SIZE:
            raise MicrosoftProviderFailure("malformed_provider_response")
        records: list[dict[str, str]] = []
        for site in value:
            if not isinstance(site, dict):
                raise MicrosoftProviderFailure("malformed_provider_response")
            identifier = site.get("id")
            if not isinstance(identifier, str) or not identifier or len(identifier) > 1024:
                raise MicrosoftProviderFailure("malformed_provider_response")
            name = site.get("displayName") or site.get("name") or ""
            url = site.get("webUrl")
            record = {"id": identifier, "name": str(name)[:1024]}
            if isinstance(url, str) and urllib.parse.urlparse(url).scheme == "https":
                record["web_url"] = url[:2048]
            records.append(record)
        return records

    @staticmethod
    def _next_link(raw: dict[str, object]) -> str | None:
        value = raw.get("@odata.nextLink")
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > MAX_GRAPH_LINK_LENGTH:
            raise MicrosoftProviderFailure("malformed_provider_response")
        return _validate_graph_url(value)

    @staticmethod
    def _drive_object(
        raw: dict[str, object], *, tenant_id: str, site_id: str | None, drive_id: str
    ) -> DriveObject:
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 1024:
            raise MicrosoftProviderFailure("malformed_provider_response")
        name = raw.get("name", "")
        if not isinstance(name, str):
            raise MicrosoftProviderFailure("malformed_provider_response")
        size = raw.get("size")
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
            raise MicrosoftProviderFailure("malformed_provider_response")
        file = raw.get("file")
        folder = raw.get("folder")
        mime_type = (
            file.get("mimeType")
            if isinstance(file, dict) and isinstance(file.get("mimeType"), str)
            else "application/vnd.microsoft.folder"
            if isinstance(folder, dict)
            else "application/octet-stream"
        )
        raw_permissions = raw.get("permissions", [])
        if not isinstance(raw_permissions, list) or len(raw_permissions) > 1000:
            raise MicrosoftProviderFailure("malformed_provider_response")
        permissions: list[dict[str, str | bool | None]] = []
        for permission in raw_permissions:
            if not isinstance(permission, dict):
                raise MicrosoftProviderFailure("malformed_provider_response")
            permission_id = permission.get("id")
            if not isinstance(permission_id, str) or not permission_id:
                continue
            inherited = permission.get("inheritedFrom") is not None
            link = permission.get("link")
            if isinstance(link, dict):
                scope = link.get("scope")
                if scope not in {"anonymous", "organization"}:
                    normalized_scope = "unknown"
                else:
                    normalized_scope = str(scope)
                permissions.append(
                    {
                        "id": permission_id[:1024],
                        "type": "link",
                        "scope": normalized_scope,
                        "inherited": inherited,
                    }
                )
                continue
            identities = permission.get("grantedToIdentitiesV2")
            if not isinstance(identities, list):
                identities = [permission.get("grantedToV2", permission.get("grantedTo"))]
            emitted = False
            for identity in identities:
                if not isinstance(identity, dict):
                    continue
                target_type = next(
                    (
                        key
                        for key in ("user", "group", "siteGroup")
                        if isinstance(identity.get(key), dict)
                    ),
                    None,
                )
                if target_type is None:
                    continue
                target = identity[target_type]
                principal_id = target.get("id")
                if not isinstance(principal_id, str):
                    continue
                permissions.append(
                    {
                        "id": permission_id[:1024],
                        "type": "group" if target_type in {"group", "siteGroup"} else "user",
                        "principal_id": principal_id[:1024],
                        "inherited": inherited,
                    }
                )
                emitted = True
            if not emitted:
                permissions.append(
                    {
                        "id": permission_id[:1024],
                        "type": "unknown",
                        "inherited": inherited,
                    }
                )
        web_url = raw.get("webUrl")
        if web_url is not None and (
            not isinstance(web_url, str) or urllib.parse.urlparse(web_url).scheme != "https"
        ):
            web_url = None
        modified = raw.get("lastModifiedDateTime")
        if modified is not None and not isinstance(modified, str):
            modified = None
        return DriveObject.model_validate(
            {
                "object_id": identifier,
                "name": name[:1024],
                "mime_type": str(mime_type)[:256],
                "size_bytes": size,
                "modified_at": modified,
                "web_view_link": web_url,
                "tenant_id": tenant_id,
                "site_id": site_id,
                "drive_id": drive_id,
                "removed": isinstance(raw.get("deleted"), dict),
                "permissions": tuple(permissions),
            }
        )

    @staticmethod
    def detect_exposure(obj: DriveObject) -> tuple[Exposure, ...]:
        grouped: dict[ExposureKind, tuple[list[str], list[str], bool]] = {}
        for permission in obj.permissions:
            if permission.get("deleted") is True:
                continue
            permission_id = permission.get("id")
            raw_type, scope = permission.get("type"), permission.get("scope")
            if raw_type == "link" and scope == "anonymous":
                kind = ExposureKind.PUBLIC
            elif raw_type == "link" and scope == "organization":
                kind = ExposureKind.ORGANIZATION
            elif raw_type == "link":
                kind = ExposureKind.UNKNOWN
            elif raw_type == "user":
                kind = ExposureKind.USERS
            elif raw_type == "group":
                kind = ExposureKind.GROUPS
            else:
                kind = ExposureKind.UNKNOWN
            principals, ids, inherited = grouped.setdefault(kind, ([], [], False))
            principal_id = permission.get("principal_id")
            if isinstance(principal_id, str):
                principals.append(principal_id)
            if isinstance(permission_id, str):
                ids.append(permission_id)
            grouped[kind] = (principals, ids, inherited or permission.get("inherited") is True)
        if not grouped:
            return (Exposure(object_id=obj.object_id, kind=ExposureKind.PRIVATE),)
        return tuple(
            Exposure(
                object_id=obj.object_id,
                kind=kind,
                principals=tuple(sorted(set(principals))),
                permission_ids=tuple(sorted(set(ids))),
                inherited=inherited,
            )
            for kind, (principals, ids, inherited) in grouped.items()
        )

    def revoke_share(self, action: ShareRevocation) -> ActionResult:
        if not action.drive_id:
            return ActionResult(succeeded=False, outcome="drive_id_required")
        current = self._request(
            f"/v1.0/drives/{urllib.parse.quote(action.drive_id, safe='')}/items/"
            f"{urllib.parse.quote(action.object_id, safe='')}"
            "/permissions?$select=id"
        )
        values = current.get("value")
        if not isinstance(values, list):
            return ActionResult(succeeded=False, outcome="malformed_provider_response")
        if not any(
            isinstance(item, dict) and item.get("id") == action.permission_id for item in values
        ):
            return ActionResult(succeeded=True, outcome="already_absent")
        path = (
            f"/v1.0/drives/{urllib.parse.quote(action.drive_id, safe='')}/items/"
            f"{urllib.parse.quote(action.object_id, safe='')}/permissions/"
            f"{urllib.parse.quote(action.permission_id, safe='')}"
        )
        result = self._delete(path)
        if not result.succeeded:
            return result
        after = self._request(
            f"/v1.0/drives/{urllib.parse.quote(action.drive_id, safe='')}/items/"
            f"{urllib.parse.quote(action.object_id, safe='')}"
            "/permissions?$select=id"
        ).get("value")
        if isinstance(after, list) and any(
            isinstance(item, dict) and item.get("id") == action.permission_id for item in after
        ):
            return ActionResult(succeeded=False, outcome="verification_failed")
        return ActionResult(succeeded=True, outcome="revoked")

    def _delete(self, path: str) -> ActionResult:
        if not path.startswith("/v1.0/drives/") or ".." in path.split("/"):
            return ActionResult(succeeded=False, outcome="invalid_action_target")
        url = _validate_graph_url(f"{MICROSOFT_GRAPH_BASE}{path[5:]}")
        try:
            self._http.request(
                "DELETE",
                url,
                headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            )
        except MicrosoftProviderFailure as exc:
            if exc.code == "not_found":
                return ActionResult(succeeded=True, outcome="already_absent")
            return ActionResult(succeeded=False, outcome=exc.code)
        return ActionResult(succeeded=True, outcome="revoked")
