"""Application-scoped rate-limit backend."""

from functools import lru_cache

from dlp_platform.ratelimit.limiter import RateLimiter, create_limiter


@lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    return create_limiter()
