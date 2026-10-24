from __future__ import annotations

import dataclasses
import hashlib
import math
import os
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from .metrics import Metrics


Clock = Callable[[], float]


@dataclasses.dataclass(frozen=True)
class RateLimit:
    key: str
    rate_per_minute: float
    burst: int | None = None


@dataclasses.dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after_seconds: float = 0.0
    unavailable: bool = False


class RateLimiterUnavailable(RuntimeError):
    pass


class RateLimiter(Protocol):
    mode: str

    def allow_all(self, limits: Sequence[RateLimit]) -> RateLimitResult:
        ...

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        ...


@dataclasses.dataclass
class _GCRAState:
    theoretical_arrival_time: float
    last_seen: float
    full_refill_period: float


class LocalRateLimiter:
    def __init__(
        self,
        mode: str = "local",
        *,
        clock: Clock = time.monotonic,
        max_keys: int = 100_000,
    ) -> None:
        if max_keys <= 0:
            raise ValueError("local rate-limiter max_keys must be greater than zero")
        self.mode = mode
        self._clock = clock
        self._max_keys = max_keys
        self._states: OrderedDict[str, _GCRAState] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def key_count(self) -> int:
        with self._lock:
            return len(self._states)

    def allow_all(self, limits: Sequence[RateLimit]) -> RateLimitResult:
        normalized = _normalize_limits(limits)
        now = self._clock()
        with self._lock:
            self._evict_idle(now)
            retry_after = 0.0
            candidates: list[tuple[RateLimit, float, float]] = []
            for limit in normalized:
                if limit.rate_per_minute == 0:
                    retry_after = max(retry_after, 60.0)
                    continue
                interval, burst, full_refill = _gcra_parameters(limit)
                state = self._states.get(limit.key)
                tat = state.theoretical_arrival_time if state is not None else now
                allow_at = tat - ((burst - 1) * interval)
                retry_after = max(retry_after, allow_at - now)
                candidates.append((limit, max(tat, now) + interval, full_refill))

            if retry_after > 0:
                return RateLimitResult(False, retry_after)

            protected = {limit.key for limit, _, _ in candidates}
            for limit, new_tat, full_refill in candidates:
                if limit.key not in self._states:
                    self._ensure_capacity(protected)
                self._states[limit.key] = _GCRAState(new_tat, now, full_refill)
                self._states.move_to_end(limit.key)
            return RateLimitResult(True)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        _validate_legacy_limit(limit, window_seconds)
        rate_per_minute = limit * (60.0 / window_seconds)
        burst = limit if limit > 0 else None
        result = self.allow_all([RateLimit(key, rate_per_minute, burst=burst)])
        return result.allowed

    def _evict_idle(self, now: float) -> None:
        expired = [
            key
            for key, state in self._states.items()
            if now - state.last_seen >= state.full_refill_period
        ]
        for key in expired:
            self._states.pop(key, None)

    def _ensure_capacity(self, protected: set[str]) -> None:
        if len(self._states) < self._max_keys:
            return
        for key in list(self._states):
            if key not in protected:
                self._states.pop(key)
                return
        self._states.popitem(last=False)


class RedisRateLimiter:
    mode = "redis"
    _GCRA_SCRIPT = """
local redis_time = redis.call('TIME')
local now_ms = (tonumber(redis_time[1]) * 1000) + math.floor(tonumber(redis_time[2]) / 1000)
local max_retry_ms = 0
local theoretical_arrivals = {}

for index = 1, #KEYS do
  local offset = ((index - 1) * 2) + 1
  local interval_ms = tonumber(ARGV[offset])
  local burst = tonumber(ARGV[offset + 1])
  local stored = redis.call('GET', KEYS[index])
  local tat = stored and tonumber(stored) or now_ms
  theoretical_arrivals[index] = tat
  local allow_at = tat - ((burst - 1) * interval_ms)
  if allow_at > now_ms then
    max_retry_ms = math.max(max_retry_ms, allow_at - now_ms)
  end
end

if max_retry_ms > 0 then
  return {0, tostring(max_retry_ms)}
end

for index = 1, #KEYS do
  local offset = ((index - 1) * 2) + 1
  local interval_ms = tonumber(ARGV[offset])
  local burst = tonumber(ARGV[offset + 1])
  local new_tat = math.max(theoretical_arrivals[index], now_ms) + interval_ms
  local ttl_ms = math.max(1, math.ceil(burst * interval_ms))
  redis.call('SET', KEYS[index], tostring(new_tat), 'PX', ttl_ms)
end

return {1, '0'}
"""

    def __init__(self, redis_url: str, prefix: str = "judikt:rate") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RateLimiterUnavailable("Redis rate limiting requires optional redis dependency") from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix
        try:
            self._client.ping()
        except redis.RedisError as exc:
            raise RateLimiterUnavailable("Redis rate limiting backend is unavailable") from exc

    def allow_all(self, limits: Sequence[RateLimit]) -> RateLimitResult:
        normalized = _normalize_limits(limits)
        if any(limit.rate_per_minute == 0 for limit in normalized):
            return RateLimitResult(False, 60.0)
        if not normalized:
            return RateLimitResult(True)
        keys: list[str] = []
        arguments: list[str] = []
        for limit in normalized:
            interval, burst, _ = _gcra_parameters(limit)
            key_digest = hashlib.sha256(limit.key.encode()).hexdigest()
            keys.append(f"{self._prefix}:{key_digest}")
            arguments.extend((str(interval * 1000.0), str(burst)))
        try:
            response = self._client.eval(
                self._GCRA_SCRIPT,
                len(keys),
                *keys,
                *arguments,
            )
        except Exception as exc:
            raise RateLimiterUnavailable(
                "Redis rate limiting backend became unavailable"
            ) from exc
        allowed = bool(int(response[0]))
        retry_after = float(response[1]) / 1000.0
        return RateLimitResult(allowed, retry_after)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        _validate_legacy_limit(limit, window_seconds)
        rate_per_minute = limit * (60.0 / window_seconds)
        burst = limit if limit > 0 else None
        result = self.allow_all([RateLimit(key, rate_per_minute, burst=burst)])
        return result.allowed


class _UnavailableRateLimiter:
    mode = "redis-unavailable"

    def allow_all(self, limits: Sequence[RateLimit]) -> RateLimitResult:
        raise RateLimiterUnavailable("Redis rate limiting backend is unavailable")

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        raise RateLimiterUnavailable("Redis rate limiting backend is unavailable")


class ResilientRateLimiter:
    def __init__(
        self,
        primary: RateLimiter,
        *,
        on_backend_failure: str,
        fallback: LocalRateLimiter,
        metrics: Metrics | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        if on_backend_failure not in {"deny", "local_fallback"}:
            raise ValueError(
                "rate_limits.on_backend_failure must be 'deny' or 'local_fallback'"
            )
        self._primary = primary
        self._on_backend_failure = on_backend_failure
        self._fallback = fallback
        self._metrics = metrics
        self._clock = clock
        self._last_warning = float("-inf")
        self.mode = primary.mode

    def allow_all(self, limits: Sequence[RateLimit]) -> RateLimitResult:
        try:
            return self._primary.allow_all(limits)
        except RateLimiterUnavailable:
            if self._metrics is not None:
                self._metrics.observe_rate_limiter_fallback(
                    self._on_backend_failure
                )
            if self._on_backend_failure == "deny":
                return RateLimitResult(False, unavailable=True)
            self._warn_once_per_minute()
            return self._fallback.allow_all(limits)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        _validate_legacy_limit(limit, window_seconds)
        rate_per_minute = limit * (60.0 / window_seconds)
        burst = limit if limit > 0 else None
        result = self.allow_all([RateLimit(key, rate_per_minute, burst=burst)])
        return result.allowed

    def _warn_once_per_minute(self) -> None:
        now = self._clock()
        if now - self._last_warning < 60:
            return
        print(
            "WARNING: Redis rate limiter unavailable; using local fallback",
            file=sys.stderr,
        )
        self._last_warning = now


def build_rate_limiter(
    config: dict[str, Any] | None = None,
    *,
    metrics: Metrics | None = None,
    production: bool = False,
) -> RateLimiter:
    settings = (config or {}).get("rate_limits", {})
    if not isinstance(settings, dict):
        raise ValueError("rate_limits must be an object")
    backend = str(settings.get("backend", "local"))
    if backend not in {"local", "redis", "redis_required"}:
        raise ValueError(
            "rate_limits.backend must be 'local', 'redis', or 'redis_required'"
        )
    redis_url = os.getenv("JUDIKT_REDIS_URL", "")
    env_required = _enabled("JUDIKT_REDIS_REQUIRED")
    if production or (redis_url and env_required):
        backend = "redis_required"
    on_failure = str(
        settings.get(
            "on_backend_failure",
            "deny" if production else "local_fallback",
        )
    )
    if on_failure not in {"deny", "local_fallback"}:
        raise ValueError(
            "rate_limits.on_backend_failure must be 'deny' or 'local_fallback'"
        )
    max_keys = int(settings.get("max_local_keys", 100_000))
    fallback = LocalRateLimiter(mode="local-fallback", max_keys=max_keys)
    if backend == "local":
        return LocalRateLimiter(max_keys=max_keys)
    if not redis_url:
        if backend == "redis_required":
            raise RuntimeError(
                "Redis rate limiting backend is required but JUDIKT_REDIS_URL is not set"
            )
        if on_failure == "local_fallback":
            _observe_startup_fallback(metrics)
            return fallback
        primary: RateLimiter = _UnavailableRateLimiter()
    else:
        try:
            primary = RedisRateLimiter(redis_url)
        except RuntimeError:
            if backend == "redis_required":
                raise
            if on_failure == "local_fallback":
                _observe_startup_fallback(metrics)
                return fallback
            primary = _UnavailableRateLimiter()
    return ResilientRateLimiter(
        primary,
        on_backend_failure=on_failure,
        fallback=fallback,
        metrics=metrics,
    )


def _normalize_limits(limits: Sequence[RateLimit]) -> tuple[RateLimit, ...]:
    normalized = tuple(limits)
    seen: set[str] = set()
    for limit in normalized:
        if not limit.key:
            raise ValueError("rate-limit key must not be empty")
        if limit.key in seen:
            raise ValueError("rate-limit keys must be unique within an atomic check")
        seen.add(limit.key)
        if limit.rate_per_minute < 0:
            raise ValueError("rate limit must be zero or greater")
        if limit.burst is not None and limit.burst <= 0:
            raise ValueError("rate-limit burst must be greater than zero")
    return normalized


def _gcra_parameters(limit: RateLimit) -> tuple[float, int, float]:
    burst = (
        limit.burst
        if limit.burst is not None
        else max(1, math.ceil(limit.rate_per_minute))
    )
    interval = 60.0 / limit.rate_per_minute
    return interval, burst, burst * interval


def _validate_legacy_limit(limit: int, window_seconds: int) -> None:
    if limit < 0:
        raise ValueError("rate limit must be zero or greater")
    if window_seconds <= 0:
        raise ValueError("rate-limit window must be greater than zero")


def _observe_startup_fallback(metrics: Metrics | None) -> None:
    if metrics is not None:
        metrics.observe_rate_limiter_fallback("local_fallback")
    print(
        "WARNING: Redis rate limiter unavailable at startup; using local fallback",
        file=sys.stderr,
    )


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}
