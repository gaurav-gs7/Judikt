from __future__ import annotations

import json
import math
import os
import platform
import statistics
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .backends import PlatformOpsBackend
from .ops_runtime import JudiktOpsRuntime


class PerformanceBenchmarkError(ValueError):
    pass


def run_gateway_benchmark(
    policy_path: Path,
    *,
    iterations: int = 200,
    warmup: int = 20,
) -> dict[str, Any]:
    if iterations <= 0:
        raise PerformanceBenchmarkError("iterations must be greater than zero")
    if warmup < 0:
        raise PerformanceBenchmarkError("warmup must not be negative")
    policy = _benchmark_policy(policy_path, iterations + warmup + 100)
    arguments = {"service": "payments-api"}

    with tempfile.TemporaryDirectory(prefix="judikt-performance-") as directory:
        root = Path(directory)
        benchmark_policy = root / "policies.json"
        benchmark_policy.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
        with _isolated_runtime_environment(root):
            baseline = PlatformOpsBackend()
            for _ in range(warmup):
                baseline.call("platform.health", arguments)
            baseline_durations = _measure(
                iterations,
                lambda index: baseline.call("platform.health", arguments),
            )

            runtime = JudiktOpsRuntime(
                benchmark_policy,
                root / "audit.db",
                include_demo_servers=True,
            )
            try:
                for index in range(warmup):
                    result = runtime.call_tool(
                        "platform-ops",
                        "platform.health",
                        arguments,
                        correlation_id=f"warmup-{index}",
                    )
                    if not result.allowed:
                        raise PerformanceBenchmarkError(
                            f"warmup call was denied by rule {result.rule!r}"
                        )
                started = time.perf_counter_ns()
                guarded_durations = _measure(
                    iterations,
                    lambda index: _guarded_call(runtime, arguments, index),
                )
                elapsed_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
                audit_report = runtime.audit_integrity()
                expected_audit_events = warmup + iterations
                if (
                    not audit_report["valid"]
                    or not audit_report["signed"]
                    or audit_report["checked_events"] != expected_audit_events
                ):
                    raise PerformanceBenchmarkError(
                        "benchmark audit evidence is incomplete, unsigned, or invalid"
                    )
            finally:
                runtime.close()

    baseline_summary = _latency_summary(baseline_durations)
    guarded_summary = _latency_summary(guarded_durations)
    throughput = iterations / elapsed_seconds if elapsed_seconds > 0 else 0.0
    return {
        "schema_version": "judikt.performance.v1",
        "benchmark": {
            "name": "in_process_guarded_tool_call",
            "workload": "platform-ops/platform.health",
            "iterations": iterations,
            "warmup_iterations": warmup,
            "rate_limits_raised_for_benchmark": True,
        },
        "scope": {
            "included": [
                "policy and authorization",
                "risk scoring",
                "local rate limiting",
                "tool metadata inspection and pin verification",
                "built-in tool execution",
                "inbound content inspection",
                "redaction",
                "hash-chained HMAC-signed SQLite audit",
                "metrics accounting",
            ],
            "excluded": [
                "HTTP transport and JWT validation",
                "external MCP network latency",
                "Redis, SIEM, Argus, S3, and OTLP exporters",
            ],
            "note": "Local single-process evidence; this is not a production SLA.",
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "operating_system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "baseline_backend_latency_ms": baseline_summary,
        "guarded_latency_ms": guarded_summary,
        "estimated_guard_overhead_ms": {
            "mean": round(max(0.0, guarded_summary["mean"] - baseline_summary["mean"]), 3),
            "p50": round(max(0.0, guarded_summary["p50"] - baseline_summary["p50"]), 3),
            "p99": round(max(0.0, guarded_summary["p99"] - baseline_summary["p99"]), 3),
        },
        "throughput_calls_per_second": round(throughput, 2),
        "results": {
            "allowed": iterations,
            "denied": 0,
            "audit_events_verified": audit_report["checked_events"],
            "audit_chain_valid": audit_report["valid"],
            "audit_signed": audit_report["signed"],
        },
    }


def report_passes(
    report: dict[str, Any],
    *,
    max_p99_ms: float = 0.0,
    min_throughput: float = 0.0,
) -> bool:
    if (
        not math.isfinite(max_p99_ms)
        or not math.isfinite(min_throughput)
        or max_p99_ms < 0
        or min_throughput < 0
    ):
        raise PerformanceBenchmarkError(
            "performance thresholds must be finite and not negative"
        )
    p99 = float(report["guarded_latency_ms"]["p99"])
    throughput = float(report["throughput_calls_per_second"])
    return (not max_p99_ms or p99 <= max_p99_ms) and (
        not min_throughput or throughput >= min_throughput
    )


def _guarded_call(runtime: JudiktOpsRuntime, arguments: dict[str, str], index: int) -> None:
    result = runtime.call_tool(
        "platform-ops",
        "platform.health",
        arguments,
        correlation_id=f"benchmark-{index}",
    )
    if not result.allowed:
        raise PerformanceBenchmarkError(f"measured call was denied by rule {result.rule!r}")


def _measure(iterations: int, operation: Callable[[int], Any]) -> list[float]:
    durations = []
    for index in range(iterations):
        started = time.perf_counter_ns()
        operation(index)
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    return durations


def _latency_summary(durations: list[float]) -> dict[str, float]:
    ordered = sorted(durations)
    return {
        "mean": round(statistics.fmean(ordered), 3),
        "p50": round(_percentile(ordered, 50), 3),
        "p95": round(_percentile(ordered, 95), 3),
        "p99": round(_percentile(ordered, 99), 3),
        "max": round(ordered[-1], 3),
    }


def _percentile(ordered: list[float], percentile: int) -> float:
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile / 100
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _benchmark_policy(policy_path: Path, limit: int) -> dict[str, Any]:
    try:
        policy = json.loads(policy_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise PerformanceBenchmarkError(f"cannot load policy {policy_path}: {exc}") from exc
    if not isinstance(policy, dict):
        raise PerformanceBenchmarkError("policy document must be a JSON object")
    rate_limits = policy.get("rate_limits_per_minute")
    if not isinstance(rate_limits, dict):
        raise PerformanceBenchmarkError("policy must define rate_limits_per_minute")
    policy["rate_limits_per_minute"] = {key: limit for key in rate_limits}
    policy["global_rate_limit_per_minute"] = limit
    return policy


@contextmanager
def _isolated_runtime_environment(root: Path) -> Iterator[None]:
    overrides = {
        "JUDIKT_TELEMETRY": "disabled",
        "JUDIKT_AUDIT_SINK": "none",
        "JUDIKT_AUDIT_HMAC_SECRET": "benchmark-audit-secret-at-least-32-bytes",
        "JUDIKT_AUDIT_HMAC_SECRET_ARN": "",
        "JUDIKT_AUDIT_HMAC_SECRET_VAULT_PATH": "",
        "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
        "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
        "JUDIKT_APPROVAL_SECRET": "benchmark-approval-secret-32-bytes-minimum",
        "JUDIKT_APPROVAL_SECRET_ARN": "",
        "JUDIKT_APPROVAL_SECRET_VAULT_PATH": "",
        "JUDIKT_ARGUS_URL": "",
        "JUDIKT_UPSTREAM_CONFIG": "",
        "JUDIKT_REDIS_URL": "",
        "JUDIKT_REDIS_REQUIRED": "false",
        "JUDIKT_TOOL_PIN_PATH": str(root / "tool-pins.json"),
        "JUDIKT_SLACK_WEBHOOK_URL": "",
        "JUDIKT_SLACK_WEBHOOK_SECRET_ARN": "",
        "JUDIKT_SLACK_WEBHOOK_VAULT_PATH": "",
        "JUDIKT_SLACK_SIGNING_SECRET": "",
        "JUDIKT_SLACK_SIGNING_SECRET_ARN": "",
        "JUDIKT_SLACK_SIGNING_SECRET_VAULT_PATH": "",
    }
    previous = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
