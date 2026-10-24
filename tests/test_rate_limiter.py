from __future__ import annotations

import io
import os
import sys
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from judikt.gateway import _gateway_result
from judikt.metrics import Metrics
from judikt.models import ToolCallResult
from judikt.policy import PolicyEngine
from judikt.rate_limiter import (
    LocalRateLimiter,
    RateLimit,
    RateLimiterUnavailable,
    RedisRateLimiter,
    ResilientRateLimiter,
    build_rate_limiter,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FailingRateLimiter:
    mode = "redis"

    def allow_all(self, limits: object) -> object:
        raise RateLimiterUnavailable("backend disappeared")

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        raise RateLimiterUnavailable("backend disappeared")


class LocalRateLimiterTest(unittest.TestCase):
    def test_gcra_allows_burst_prevents_boundary_double_burst_and_recovers(self) -> None:
        clock = FakeClock()
        limiter = LocalRateLimiter(clock=clock)
        limit = [RateLimit("tool:health", 60, burst=2)]

        self.assertTrue(limiter.allow_all(limit).allowed)
        self.assertTrue(limiter.allow_all(limit).allowed)
        denied = limiter.allow_all(limit)
        self.assertFalse(denied.allowed)
        self.assertAlmostEqual(denied.retry_after_seconds, 1.0)

        clock.advance(0.999)
        self.assertFalse(limiter.allow_all(limit).allowed)
        clock.advance(0.001)
        self.assertTrue(limiter.allow_all(limit).allowed)
        self.assertFalse(limiter.allow_all(limit).allowed)

    def test_multi_key_denial_charges_no_key(self) -> None:
        clock = FakeClock()
        limiter = LocalRateLimiter(clock=clock)
        blocked = RateLimit("global", 60, burst=1)
        untouched = RateLimit("actor:alice", 60, burst=1)
        self.assertTrue(limiter.allow_all([blocked]).allowed)

        denied = limiter.allow_all([untouched, blocked])

        self.assertFalse(denied.allowed)
        self.assertTrue(limiter.allow_all([untouched]).allowed)

    def test_legacy_allow_uses_same_gcra_contract(self) -> None:
        clock = FakeClock()
        limiter = LocalRateLimiter(clock=clock)

        self.assertTrue(limiter.allow("first", 1, 10))
        self.assertFalse(limiter.allow("first", 1, 10))
        self.assertTrue(limiter.allow("second", 1, 10))
        clock.advance(10)
        self.assertTrue(limiter.allow("first", 1, 10))

    def test_zero_limit_and_invalid_configuration(self) -> None:
        limiter = LocalRateLimiter()
        self.assertFalse(limiter.allow("blocked", 0, 60))
        with self.assertRaisesRegex(ValueError, "zero or greater"):
            limiter.allow("invalid", -1, 60)
        with self.assertRaisesRegex(ValueError, "greater than zero"):
            limiter.allow("invalid", 1, 0)
        with self.assertRaisesRegex(ValueError, "max_keys"):
            LocalRateLimiter(max_keys=0)

    def test_idle_keys_are_evicted_and_map_never_exceeds_cap(self) -> None:
        clock = FakeClock()
        limiter = LocalRateLimiter(clock=clock, max_keys=2)

        def one_per_second(key: str) -> list[RateLimit]:
            return [RateLimit(key, 60, burst=1)]

        self.assertTrue(limiter.allow_all(one_per_second("one")).allowed)
        self.assertTrue(limiter.allow_all(one_per_second("two")).allowed)
        self.assertTrue(limiter.allow_all(one_per_second("three")).allowed)
        self.assertEqual(limiter.key_count, 2)

        clock.advance(1)
        self.assertTrue(limiter.allow_all(one_per_second("four")).allowed)
        self.assertEqual(limiter.key_count, 1)

    def test_updating_existing_key_at_capacity_does_not_evict_another_key(self) -> None:
        clock = FakeClock()
        limiter = LocalRateLimiter(clock=clock, max_keys=2)
        self.assertTrue(
            limiter.allow_all([RateLimit("one", 60, burst=10)]).allowed
        )
        self.assertTrue(
            limiter.allow_all([RateLimit("two", 60, burst=10)]).allowed
        )

        self.assertTrue(
            limiter.allow_all([RateLimit("one", 60, burst=10)]).allowed
        )

        self.assertEqual(limiter.key_count, 2)


class BackendContractTest(unittest.TestCase):
    def test_local_is_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            limiter = build_rate_limiter({})
        self.assertEqual(limiter.mode, "local")

    def test_unavailable_redis_falls_back_when_configured(self) -> None:
        config = {
            "rate_limits": {
                "backend": "redis",
                "on_backend_failure": "local_fallback",
            }
        }
        metrics = Metrics()
        stderr = io.StringIO()
        with redirect_stderr(stderr), patch.dict(
            os.environ,
            {"JUDIKT_REDIS_URL": "redis://unavailable:6379/0"},
            clear=True,
        ), patch(
            "judikt.rate_limiter.RedisRateLimiter",
            side_effect=RuntimeError("unavailable"),
        ):
            limiter = build_rate_limiter(config, metrics=metrics)

        self.assertEqual(limiter.mode, "local-fallback")
        self.assertTrue(limiter.allow_all([RateLimit("tool", 1, burst=1)]).allowed)
        self.assertIn("WARNING:", stderr.getvalue())
        self.assertIn(
            'judikt_rate_limiter_fallback_total{mode="local_fallback"} 1',
            metrics.render(),
        )

    def test_invalid_failure_mode_is_rejected_for_every_backend(self) -> None:
        with self.assertRaisesRegex(ValueError, "on_backend_failure"):
            build_rate_limiter(
                {
                    "rate_limits": {
                        "backend": "local",
                        "on_backend_failure": "allow",
                    }
                }
            )

    def test_redis_required_and_production_fail_startup(self) -> None:
        for config, production in (
            ({"rate_limits": {"backend": "redis_required"}}, False),
            ({"rate_limits": {"backend": "local"}}, True),
        ):
            with self.subTest(config=config, production=production), patch.dict(
                os.environ,
                {},
                clear=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "JUDIKT_REDIS_URL"):
                    build_rate_limiter(config, production=production)

    def test_env_required_with_url_propagates_startup_failure(self) -> None:
        with patch.dict(
            os.environ,
            {
                "JUDIKT_REDIS_URL": "redis://unavailable:6379/0",
                "JUDIKT_REDIS_REQUIRED": "true",
            },
            clear=True,
        ), patch(
            "judikt.rate_limiter.RedisRateLimiter",
            side_effect=RuntimeError("unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                build_rate_limiter({})

    def test_runtime_failure_denies_and_increments_metric(self) -> None:
        metrics = Metrics()
        limiter = ResilientRateLimiter(
            FailingRateLimiter(),
            on_backend_failure="deny",
            fallback=LocalRateLimiter(),
            metrics=metrics,
        )

        result = limiter.allow_all([RateLimit("tool", 1, burst=1)])

        self.assertFalse(result.allowed)
        self.assertTrue(result.unavailable)
        self.assertIn(
            'judikt_rate_limiter_fallback_total{mode="deny"} 1',
            metrics.render(),
        )

    def test_runtime_failure_falls_back_warns_once_and_increments_metric(self) -> None:
        clock = FakeClock()
        metrics = Metrics()
        limiter = ResilientRateLimiter(
            FailingRateLimiter(),
            on_backend_failure="local_fallback",
            fallback=LocalRateLimiter(clock=clock),
            metrics=metrics,
            clock=clock,
        )
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            first = limiter.allow_all([RateLimit("first", 1, burst=1)])
            second = limiter.allow_all([RateLimit("second", 1, burst=1)])

        self.assertTrue(first.allowed)
        self.assertTrue(second.allowed)
        self.assertEqual(stderr.getvalue().count("WARNING:"), 1)
        self.assertIn(
            'judikt_rate_limiter_fallback_total{mode="local_fallback"} 2',
            metrics.render(),
        )


class RedisRateLimiterUnitTest(unittest.TestCase):
    def test_checks_backend_during_startup(self) -> None:
        class FakeRedisError(Exception):
            pass

        class FakeClient:
            def ping(self) -> None:
                raise FakeRedisError("connection refused")

        class FakeRedisFactory:
            @staticmethod
            def from_url(url: str, decode_responses: bool) -> FakeClient:
                return FakeClient()

        redis_module = types.SimpleNamespace(
            Redis=FakeRedisFactory,
            RedisError=FakeRedisError,
        )
        with patch.dict(sys.modules, {"redis": redis_module}):
            with self.assertRaisesRegex(RuntimeError, "backend is unavailable"):
                RedisRateLimiter("redis://unavailable:6379/0")

    def test_hashes_every_key_and_uses_one_atomic_script(self) -> None:
        observed: dict[str, object] = {}

        class FakeClient:
            def ping(self) -> None:
                return None

            def eval(self, script: str, key_count: int, *values: str) -> list[object]:
                observed.update(
                    {"script": script, "key_count": key_count, "values": values}
                )
                return [1, "0"]

        client = FakeClient()

        class FakeRedisFactory:
            @staticmethod
            def from_url(url: str, decode_responses: bool) -> FakeClient:
                return client

        redis_module = types.SimpleNamespace(Redis=FakeRedisFactory, RedisError=Exception)
        with patch.dict(sys.modules, {"redis": redis_module}):
            limiter = RedisRateLimiter("redis://shared:6379/0")
            result = limiter.allow_all(
                [
                    RateLimit("actor:local-operator:tool:restart", 60, burst=1),
                    RateLimit("global", 120, burst=2),
                ]
            )

        self.assertTrue(result.allowed)
        self.assertEqual(observed["key_count"], 2)
        self.assertNotIn("local-operator", str(observed["values"]))
        self.assertIn("redis.call('TIME')", str(observed["script"]))
        self.assertIn("max_retry_ms", str(observed["script"]))

    def test_operation_failure_has_stable_exception(self) -> None:
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
            with self.assertRaisesRegex(
                RateLimiterUnavailable,
                "became unavailable",
            ):
                limiter.allow_all([RateLimit("actor", 1, burst=1)])


class RetryMetadataTest(unittest.TestCase):
    def test_policy_denial_has_accurate_retry_evidence(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        clock = FakeClock()
        policy = PolicyEngine(project_root / "config" / "policies.yaml")
        policy._rate_limiter = LocalRateLimiter(clock=clock)

        for _ in range(10):
            decision = policy.evaluate(
                "platform-ops",
                "platform.health",
                {"service": "payments-api"},
                authenticated_actor="demo-operator",
            )
            self.assertTrue(decision.allowed)
        denied = policy.evaluate(
            "platform-ops",
            "platform.health",
            {"service": "payments-api"},
            authenticated_actor="demo-operator",
        )

        self.assertEqual(denied.rule, "rate_limit")
        retry = next(
            float(value.partition(":")[2])
            for value in denied.evidence
            if value.startswith("retry_after_seconds:")
        )
        self.assertAlmostEqual(retry, 6.0, delta=1.0)

    def test_backend_outage_has_distinct_policy_rule(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        policy = PolicyEngine(project_root / "config" / "policies.yaml")
        policy._rate_limiter = ResilientRateLimiter(
            FailingRateLimiter(),
            on_backend_failure="deny",
            fallback=LocalRateLimiter(),
        )

        decision = policy.evaluate(
            "platform-ops",
            "platform.health",
            {"service": "payments-api"},
            authenticated_actor="demo-operator",
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "rate_limiter_unavailable")

    def test_gateway_meta_contains_retry_after_from_decision_evidence(self) -> None:
        guarded = ToolCallResult(
            correlation_id="corr-1",
            allowed=False,
            server="server",
            tool="tool",
            reason="rate limited",
            rule="rate_limit",
            action="DENY",
            evidence=["retry_after_seconds:5.250"],
        )

        result = _gateway_result(guarded)

        decision = result["_meta"]["io.judikt/decision"]
        self.assertEqual(decision["retry_after_seconds"], 5.25)


if __name__ == "__main__":
    unittest.main()
