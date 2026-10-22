from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import patch

from judikt.rate_limiter import LocalRateLimiter, RedisRateLimiter, build_rate_limiter


class LocalRateLimiterTest(unittest.TestCase):
    def test_limit_blocks_after_threshold(self) -> None:
        limiter = LocalRateLimiter()

        self.assertTrue(limiter.allow("tool:platform.health", 2, 60))
        self.assertTrue(limiter.allow("tool:platform.health", 2, 60))
        self.assertFalse(limiter.allow("tool:platform.health", 2, 60))

    def test_window_expiry_and_key_isolation(self) -> None:
        limiter = LocalRateLimiter()
        with patch("judikt.rate_limiter.time.monotonic", side_effect=[0.0, 0.0, 10.0]):
            self.assertTrue(limiter.allow("first", 1, 10))
            self.assertTrue(limiter.allow("second", 1, 10))
            self.assertTrue(limiter.allow("first", 1, 10))

    def test_zero_limit_and_invalid_configuration(self) -> None:
        limiter = LocalRateLimiter()
        self.assertFalse(limiter.allow("blocked", 0, 60))
        with self.assertRaisesRegex(ValueError, "zero or greater"):
            limiter.allow("invalid", -1, 60)
        with self.assertRaisesRegex(ValueError, "greater than zero"):
            limiter.allow("invalid", 1, 0)

    def test_unavailable_redis_falls_back_when_not_required(self) -> None:
        with patch.dict(
            os.environ,
            {
                "JUDIKT_REDIS_URL": "redis://unavailable:6379/0",
                "JUDIKT_REDIS_REQUIRED": "false",
            },
            clear=False,
        ), patch("judikt.rate_limiter.RedisRateLimiter", side_effect=RuntimeError("unavailable")):
            limiter = build_rate_limiter()

        self.assertEqual(limiter.mode, "local-fallback")

    def test_unavailable_required_redis_fails_startup(self) -> None:
        with patch.dict(
            os.environ,
            {
                "JUDIKT_REDIS_URL": "redis://unavailable:6379/0",
                "JUDIKT_REDIS_REQUIRED": "true",
            },
            clear=False,
        ), patch("judikt.rate_limiter.RedisRateLimiter", side_effect=RuntimeError("unavailable")):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                build_rate_limiter()

    def test_redis_limiter_checks_backend_during_startup(self) -> None:
        class FakeRedisError(Exception):
            pass

        class FakeClient:
            def ping(self) -> None:
                raise FakeRedisError("connection refused")

        class FakeRedisFactory:
            @staticmethod
            def from_url(url: str, decode_responses: bool) -> FakeClient:
                return FakeClient()

        redis_module = types.SimpleNamespace(Redis=FakeRedisFactory, RedisError=FakeRedisError)
        with patch.dict(sys.modules, {"redis": redis_module}):
            with self.assertRaisesRegex(RuntimeError, "backend is unavailable"):
                RedisRateLimiter("redis://unavailable:6379/0")

    def test_redis_keys_hide_actor_names_and_increment_atomically(self) -> None:
        observed: dict[str, object] = {}

        class FakeClient:
            count = 0

            def ping(self) -> None:
                return None

            def eval(self, script: str, key_count: int, key: str, ttl: int) -> int:
                self.count += 1
                observed.update({"script": script, "key_count": key_count, "key": key, "ttl": ttl})
                return self.count

        client = FakeClient()

        class FakeRedisFactory:
            @staticmethod
            def from_url(url: str, decode_responses: bool) -> FakeClient:
                return client

        redis_module = types.SimpleNamespace(Redis=FakeRedisFactory, RedisError=Exception)
        with patch.dict(sys.modules, {"redis": redis_module}):
            limiter = RedisRateLimiter("redis://shared:6379/0")
            self.assertTrue(limiter.allow("actor:local-operator:tool:restart", 1, 60))
            self.assertFalse(limiter.allow("actor:local-operator:tool:restart", 1, 60))

        self.assertNotIn("local-operator", str(observed["key"]))
        self.assertIn("PEXPIRE", str(observed["script"]))
        self.assertEqual(observed["ttl"], 60_000)

    def test_redis_operation_failure_is_fail_closed(self) -> None:
        class FakeClient:
            def ping(self) -> None:
                return None

            def eval(self, *args: object) -> int:
                raise RuntimeError("backend disappeared")

        class FakeRedisFactory:
            @staticmethod
            def from_url(url: str, decode_responses: bool) -> FakeClient:
                return FakeClient()

        redis_module = types.SimpleNamespace(Redis=FakeRedisFactory, RedisError=Exception)
        with patch.dict(sys.modules, {"redis": redis_module}):
            limiter = RedisRateLimiter("redis://shared:6379/0")
            with self.assertRaisesRegex(RuntimeError, "backend disappeared"):
                limiter.allow("actor", 1, 60)


if __name__ == "__main__":
    unittest.main()
