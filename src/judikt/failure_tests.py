from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from .ops_runtime import JudiktOpsRuntime
from .paths import DEFAULT_POLICY_PATH


ROLLBACK_PLAN = "verify health checks and restore previous known-good release if errors increase"


@dataclass(frozen=True)
class FailureCaseResult:
    name: str
    passed: bool
    expected: str
    observed: str


def run_failure_tests(policy_path: Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        runtime = JudiktOpsRuntime(
            policy_path,
            Path(tmp) / "failure-drill.db",
            include_demo_servers=True,
            circuit_failure_threshold=2,
            circuit_cooldown_seconds=60,
        )
        try:
            cases: list[tuple[str, str, Callable[[], tuple[bool, str]]]] = [
                (
                    "approval gate blocks destructive rollback",
                    "blocked by approval_required",
                    lambda: _expect_rule(
                        runtime.call_tool(
                            "platform-ops",
                            "platform.rollback_deployment",
                            {
                                "service": "payments-api",
                                "version": "payments-api@2026.05.2",
                                "actor": "gaurav",
                                "rollback_plan": ROLLBACK_PLAN,
                            },
                        ),
                        "approval token is required",
                    ),
                ),
                (
                    "kill switch blocks a read tool",
                    "blocked by kill_switch",
                    lambda: _kill_switch_case(runtime),
                ),
                (
                    "circuit breaker opens after repeated tool failures",
                    "blocked by circuit_breaker",
                    lambda: _circuit_breaker_case(runtime),
                ),
                (
                    "secret redaction protects config output",
                    "api_key redacted",
                    lambda: _redaction_case(runtime),
                ),
                (
                    "rate limit blocks excessive health checks",
                    "blocked by rate_limit",
                    lambda: _rate_limit_case(runtime),
                ),
            ]
            results = [
                FailureCaseResult(name=name, passed=passed, expected=expected, observed=observed)
                for name, expected, case in cases
                for passed, observed in [case()]
            ]
            return {
                "passed": all(result.passed for result in results),
                "case_count": len(results),
                "passed_count": sum(1 for result in results if result.passed),
                "results": [asdict(result) for result in results],
            }
        finally:
            runtime.close()


def _expect_rule(result: Any, expected_reason_fragment: str) -> tuple[bool, str]:
    observed = f"allowed={result.allowed} reason={result.reason}"
    return (not result.allowed and expected_reason_fragment in result.reason, observed)


def _kill_switch_case(runtime: JudiktOpsRuntime) -> tuple[bool, str]:
    runtime.set_tool_enabled("platform.health", False)
    try:
        result = runtime.call_tool("platform-ops", "platform.health", {"service": "payments-api"})
        observed = f"allowed={result.allowed} reason={result.reason}"
        return (not result.allowed and "kill switch" in result.reason, observed)
    finally:
        runtime.set_tool_enabled("platform.health", True)


def _circuit_breaker_case(runtime: JudiktOpsRuntime) -> tuple[bool, str]:
    args = {"service": "payments-api", "command": "dependency-health"}
    original_call = runtime.platform.call

    def unavailable(tool: str, arguments: dict[str, Any]) -> Any:
        if tool == "platform.run_diagnostic":
            raise RuntimeError("injected upstream outage")
        return original_call(tool, arguments)

    runtime.platform.call = unavailable
    try:
        runtime.call_tool("platform-ops", "platform.run_diagnostic", args)
        runtime.call_tool("platform-ops", "platform.run_diagnostic", args)
        result = runtime.call_tool("platform-ops", "platform.run_diagnostic", args)
        observed = f"allowed={result.allowed} reason={result.reason}"
        return (not result.allowed and "circuit breaker" in result.reason, observed)
    finally:
        runtime.platform.call = original_call


def _redaction_case(runtime: JudiktOpsRuntime) -> tuple[bool, str]:
    result = runtime.call_tool("platform-ops", "platform.read_config", {"service": "payments-api"})
    observed = json.dumps(result.result, sort_keys=True)
    return (result.result.get("api_key") == "[REDACTED]", observed)


def _rate_limit_case(runtime: JudiktOpsRuntime) -> tuple[bool, str]:
    last = None
    for _ in range(11):
        last = runtime.call_tool("platform-ops", "platform.health", {"service": "checkout-worker"})
    assert last is not None
    observed = f"allowed={last.allowed} reason={last.reason}"
    return (not last.allowed and "per-minute limit" in last.reason, observed)


def main() -> int:
    report = run_failure_tests()
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
