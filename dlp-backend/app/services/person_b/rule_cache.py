"""
Tiny per-org TTL cache shared by the org-scoped rule/EDM/fingerprint loaders.

Avoids a Supabase round trip on every /api/scan call while still picking up
rule changes within ~60s — good enough for a classifications table that
admins edit occasionally, not on every request. Deliberately in-process
(not Redis): if the backend runs as multiple workers, each worker keeps its
own cache, which just means a rule change can take up to TTL to reach every
worker — acceptable for this project's scope, called out here so it isn't
a silent surprise later.
"""

import time
from typing import Callable, TypeVar

T = TypeVar("T")

_TTL_SECONDS = 60
_store: dict[tuple[str, str], tuple[float, object]] = {}


def cached(namespace: str, org_id: str, loader: Callable[[], T]) -> T:
    """Return the cached value for (namespace, org_id) if fresh, else reload."""
    key = (namespace, org_id)
    now = time.monotonic()
    hit = _store.get(key)
    if hit is not None and now - hit[0] < _TTL_SECONDS:
        return hit[1]  # type: ignore[return-value]
    value = loader()
    _store[key] = (now, value)
    return value


def invalidate(namespace: str, org_id: str) -> None:
    """Call after a classification rule is created/updated/deleted for an org."""
    _store.pop((namespace, org_id), None)
