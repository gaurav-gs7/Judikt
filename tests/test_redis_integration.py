from __future__ import annotations

import os
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor

from judikt.rate_limiter import LocalRateLimiter, RateLimit, RedisRateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@unittest.skipUnless(os.getenv("JUDIKT_TEST_REDIS_URL"), "integration Redis URL is not configured")
class RedisRateLimiterIntegrationTest(unittest.TestCase):
    def test_two_instances_share_an_atomic_limit(self) -> None:
        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        prefix = f"judikt:test:{uuid.uuid4()}"
        first = RedisRateLimiter(url, prefix=prefix)
        second = RedisRateLimiter(url, prefix=prefix)

        self.assertTrue(first.allow("actor:sre-oncall:tool:restart", 2, 60))
        self.assertTrue(second.allow("actor:sre-oncall:tool:restart", 2, 60))
        self.assertFalse(first.allow("actor:sre-oncall:tool:restart", 2, 60))

    def test_concurrent_instances_never_exceed_limit(self) -> None:
        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        prefix = f"judikt:test:{uuid.uuid4()}"
        limiters = [RedisRateLimiter(url, prefix=prefix) for _ in range(4)]
        with ThreadPoolExecutor(max_workers=20) as executor:
            outcomes = list(
                executor.map(
                    lambda index: limiters[index % len(limiters)].allow("shared-actor", 13, 60),
                    range(60),
                )
            )
        self.assertEqual(sum(outcomes), 13)

    def test_gcra_state_expires_and_hashed_key_has_bounded_ttl(self) -> None:
        import redis

        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        prefix = f"judikt:test:{uuid.uuid4()}"
        limiter = RedisRateLimiter(url, prefix=prefix)
        actor = "actor:private-name:tool:restart"
        limit = [RateLimit(actor, 1200, burst=1)]
        self.assertTrue(limiter.allow_all(limit).allowed)
        self.assertFalse(limiter.allow_all(limit).allowed)
        client = redis.Redis.from_url(url, decode_responses=True)
        keys = client.keys(f"{prefix}:*")
        self.assertEqual(len(keys), 1)
        self.assertNotIn("private-name", keys[0])
        ttl = client.pttl(keys[0])
        self.assertGreater(ttl, 0)
        self.assertLessEqual(ttl, 50)
        time.sleep(0.06)
        self.assertTrue(limiter.allow_all(limit).allowed)

    def test_local_and_redis_have_matching_gcra_sequence(self) -> None:
        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        redis_limiter = RedisRateLimiter(url, prefix=f"judikt:test:{uuid.uuid4()}")
        clock = FakeClock()
        local_limiter = LocalRateLimiter(clock=clock)
        limit = [RateLimit("matching-sequence", 1200, burst=2)]

        local = [local_limiter.allow_all(limit).allowed for _ in range(3)]
        redis = [redis_limiter.allow_all(limit).allowed for _ in range(3)]
        clock.advance(0.06)
        time.sleep(0.06)
        local.extend(local_limiter.allow_all(limit).allowed for _ in range(2))
        redis.extend(redis_limiter.allow_all(limit).allowed for _ in range(2))

        self.assertEqual(local, [True, True, False, True, False])
        self.assertEqual(redis, local)

    def test_local_and_redis_match_at_a_steady_rate(self) -> None:
        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        redis_limiter = RedisRateLimiter(url, prefix=f"judikt:test:{uuid.uuid4()}")
        clock = FakeClock()
        local_limiter = LocalRateLimiter(clock=clock)
        limit = [RateLimit("steady-sequence", 1200, burst=1)]
        local: list[bool] = []
        redis: list[bool] = []

        for index in range(3):
            if index:
                clock.advance(0.06)
                time.sleep(0.06)
            local.append(local_limiter.allow_all(limit).allowed)
            redis.append(redis_limiter.allow_all(limit).allowed)

        self.assertEqual(local, [True, True, True])
        self.assertEqual(redis, local)

    def test_multi_key_denial_charges_no_redis_key(self) -> None:
        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        limiter = RedisRateLimiter(url, prefix=f"judikt:test:{uuid.uuid4()}")
        blocked = RateLimit("global", 1200, burst=1)
        untouched = RateLimit("actor:alice", 1200, burst=1)
        self.assertTrue(limiter.allow_all([blocked]).allowed)

        denied = limiter.allow_all([untouched, blocked])

        self.assertFalse(denied.allowed)
        self.assertTrue(limiter.allow_all([untouched]).allowed)


if __name__ == "__main__":
    unittest.main()
