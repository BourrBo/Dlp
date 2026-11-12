"""Deterministic unit and concurrency tests for the local limiter."""

from concurrent.futures import ThreadPoolExecutor

from dlp_platform.ratelimit.limiter import InMemoryRateLimiter


def test_limits_identity_and_organization_and_resets() -> None:
    now = [0.0]
    limiter = InMemoryRateLimiter(2, 3, 10, clock=lambda: now[0])
    assert limiter.check("a", "org-a").allowed
    assert limiter.check("a", "org-a").allowed
    over = limiter.check("a", "org-a")
    assert not over.allowed
    assert over.retry_after == 10
    assert not limiter.check("b", "org-a").allowed  # organization cap reached
    assert limiter.check("b", "org-b").allowed  # distinct key and organization
    now[0] = 10.0
    assert limiter.check("a", "org-a").allowed
    assert limiter.check("other", "org-b").allowed


def test_concurrent_requests_do_not_exceed_limit() -> None:
    limiter = InMemoryRateLimiter(10, 100, 60)
    with ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(lambda _i: limiter.check("same", "org").allowed, range(100)))
    assert sum(results) == 10


def test_distinct_identities_have_separate_buckets_within_one_org() -> None:
    limiter = InMemoryRateLimiter(1, 5, 60)
    assert limiter.check("identity-a", "org").allowed
    assert limiter.check("identity-a", "org").allowed is False
    assert limiter.check("identity-b", "org").allowed
