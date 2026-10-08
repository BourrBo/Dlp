"""Small server-only client for the Supabase Data API."""

import httpx
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from app.config import get_settings


@dataclass
class _RestResult:
    data: list[dict[str, Any]]


class _RestQuery:
    """Small PostgREST query adapter for the teammate detection/channel services."""

    def __init__(self, table: str, access_token: str | None = None):
        if not re.fullmatch(r"[a-z][a-z0-9_]*", table):
            raise ValueError("Invalid Supabase table name")
        self.table = table
        self.access_token = access_token
        self.params: dict[str, str] = {}
        self.body: dict[str, Any] | list[dict[str, Any]] | None = None
        self.method = "GET"

    def select(self, columns: str = "*") -> "_RestQuery":
        self.params["select"] = columns
        return self

    def eq(self, column: str, value: Any) -> "_RestQuery":
        if not re.fullmatch(r"[a-z][a-z0-9_]*", column):
            raise ValueError("Invalid Supabase column name")
        self.params[column] = f"eq.{value}"
        return self

    def order(self, column: str, *, desc: bool = False) -> "_RestQuery":
        if not re.fullmatch(r"[a-z][a-z0-9_]*", column):
            raise ValueError("Invalid Supabase column name")
        self.params["order"] = f"{column}.{'desc' if desc else 'asc'}"
        return self

    def limit(self, count: int) -> "_RestQuery":
        self.params["limit"] = str(max(0, min(count, 1000)))
        return self

    def insert(self, values: dict[str, Any] | list[dict[str, Any]]) -> "_RestQuery":
        self.body = values
        self.method = "POST"
        return self

    def update(self, values: dict[str, Any]) -> "_RestQuery":
        self.body = values
        self.method = "PATCH"
        return self

    def execute(self) -> _RestResult:
        url = f"{_base_url()}/rest/v1/{self.table}"
        headers = _headers(prefer="return=representation" if self.body is not None else None)
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if self.method == "POST":
            response = httpx.post(
                url,
                params=self.params,
                json=self.body,
                headers=headers,
                timeout=10.0,
            )
        elif self.method == "PATCH":
            response = httpx.patch(
                url,
                params=self.params,
                json=self.body,
                headers=headers,
                timeout=10.0,
            )
        else:
            response = httpx.get(url, params=self.params, headers=headers, timeout=10.0)
        response.raise_for_status()
        rows = response.json() if response.content else []
        return _RestResult(data=rows if isinstance(rows, list) else [rows])


class _RestClient:
    def __init__(self, access_token: str | None = None):
        self.access_token = access_token

    def table(self, table: str) -> _RestQuery:
        return _RestQuery(table, access_token=self.access_token)


@lru_cache(maxsize=1)
def get_supabase() -> _RestClient:
    """Return a server-only PostgREST adapter using the configured service key."""
    _base_url()  # Fail early with the standard missing-configuration message.
    return _RestClient()


def get_authenticated_supabase(access_token: str) -> _RestClient:
    """Return a Data API client that evaluates RLS as the authenticated user."""
    _base_url()
    return _RestClient(access_token=access_token)


def _base_url() -> str:
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_role_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set for the backend")
    return settings.supabase_url.rstrip("/")


def _headers(*, prefer: str | None = None) -> dict[str, str]:
    settings = get_settings()
    key = settings.supabase_service_role_key
    headers = {"apikey": key, "Content-Type": "application/json"}
    # New Supabase secret keys are opaque and belong in apikey only. Legacy
    # service_role keys are JWTs and also serve as the REST bearer token.
    if not key.startswith("sb_secret_"):
        headers["Authorization"] = f"Bearer {key}"
    if prefer:
        headers["Prefer"] = prefer
    return headers


def post_scan_event(event: dict) -> dict:
    url = f"{_base_url()}/rest/v1/dlp_events"
    resp = httpx.post(url, json=event, headers=_headers(prefer="return=representation"), timeout=10.0)
    resp.raise_for_status()
    rows = resp.json()
    return rows[0] if rows else {}


def get_policy(org_id: str, data_type: str, channel: str) -> dict | None:
    url = f"{_base_url()}/rest/v1/dlp_policies"
    resp = httpx.get(
        url,
        params={
            "select": "id,org_id,data_type,channel,condition,action,is_exception,created_at",
            "org_id": f"eq.{org_id}",
            "data_type": f"eq.{data_type}",
            "channel": f"eq.{channel}",
            "limit": "1",
        },
        headers=_headers(),
        timeout=10.0,
    )
    resp.raise_for_status()
    rows = resp.json()
    return rows[0] if rows else None
