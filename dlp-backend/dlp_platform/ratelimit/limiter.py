"""Atomic fixed-window limiters with a local-only and shared Valkey backend."""

import hashlib
import os
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Protocol


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


class RateLimiter(Protocol):
    def check(self, identity: str, organization_id: str) -> LimitResult: ...


class InMemoryRateLimiter:
    """Thread-safe local/test limiter; each process has independent counters."""

    def __init__(
        self,
        per_identity: int,
        per_org: int,
        window_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.per_identity = per_identity
        self.per_org = per_org
        self.window_seconds = window_seconds
        self.clock = clock
        self._lock = Lock()
        self._counts: dict[tuple[str, int], int] = defaultdict(int)
        self._last_window: int | None = None

    def check(self, identity: str, organization_id: str) -> LimitResult:
        now = self.clock()
        window = int(now // self.window_seconds)
        identity_key = ("key:" + identity, window)
        org_key = ("org:" + organization_id, window)
        with self._lock:
            if self._last_window != window:
                self._counts = defaultdict(
                    int, {key: value for key, value in self._counts.items() if key[1] >= window}
                )
                self._last_window = window
            self._counts[identity_key] += 1
            self._counts[org_key] += 1
            key_count, org_count = self._counts[identity_key], self._counts[org_key]
            allowed = key_count <= self.per_identity and org_count <= self.per_org
            remaining = max(0, min(self.per_identity - key_count, self.per_org - org_count))
            return LimitResult(
                allowed,
                self.per_identity,
                remaining,
                max(1, int((window + 1) * self.window_seconds - now)),
            )


_SCRIPT = """
local a = redis.call('INCR', KEYS[1])
if a == 1 then redis.call('EXPIRE', KEYS[1], ARGV[3]) end
local b = redis.call('INCR', KEYS[2])
if b == 1 then redis.call('EXPIRE', KEYS[2], ARGV[3]) end
local rem = math.min(tonumber(ARGV[1])-a, tonumber(ARGV[2])-b)
return {a <= tonumber(ARGV[1]) and b <= tonumber(ARGV[2]) and 1 or 0,
        math.max(0, rem), tonumber(ARGV[4])}
"""


class ValkeyRateLimiter:
    """Shared fixed-window limiter; Lua increments both dimensions atomically."""

    def __init__(
        self, client: object, per_identity: int, per_org: int, window_seconds: int
    ) -> None:
        self.client = client
        self.per_identity = per_identity
        self.per_org = per_org
        self.window_seconds = window_seconds

    def check(self, identity: str, organization_id: str) -> LimitResult:
        now = time.time()
        window = int(now // self.window_seconds)
        identity_hash = hashlib.sha256(identity.encode()).hexdigest()
        org_hash = hashlib.sha256(organization_id.encode()).hexdigest()
        result = self.client.eval(  # type: ignore[attr-defined]
            _SCRIPT,
            2,
            f"dlp:rl:key:{identity_hash}:{window}",
            f"dlp:rl:org:{org_hash}:{window}",
            self.per_identity,
            self.per_org,
            self.window_seconds * 2,
            max(1, int((window + 1) * self.window_seconds - now)),
        )
        return LimitResult(bool(int(result[0])), self.per_identity, int(result[1]), int(result[2]))


def create_limiter() -> RateLimiter:
    per_key = int(os.getenv("RATE_LIMIT_PER_KEY", "30"))
    per_org = int(os.getenv("RATE_LIMIT_PER_ORG", "300"))
    window = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    if min(per_key, per_org, window) < 1:
        raise ValueError("Rate limit values must be positive")
    backend = os.getenv("RATE_LIMIT_BACKEND", "memory")
    if backend == "memory":
        if os.getenv("APP_ENV", "development") == "production":
            raise RuntimeError("Production requires RATE_LIMIT_BACKEND=valkey")
        return InMemoryRateLimiter(per_key, per_org, window)
    if backend == "valkey":
        from valkey import Valkey

        url = os.getenv("VALKEY_URL")
        if not url:
            raise RuntimeError("VALKEY_URL is required for the Valkey rate-limit backend")
        return ValkeyRateLimiter(Valkey.from_url(url), per_key, per_org, window)
    raise ValueError("RATE_LIMIT_BACKEND must be memory or valkey")
