from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from judikt.performance import (
    PerformanceBenchmarkError,
    report_passes,
    run_gateway_benchmark,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "config" / "policies.yaml"


class PerformanceBenchmarkTest(unittest.TestCase):
    def test_full_pipeline_report_contains_verifiable_privacy_safe_evidence(self) -> None:
        with patch.dict(os.environ, {"JUDIKT_TELEMETRY": "console"}, clear=False):
            report = run_gateway_benchmark(POLICY, iterations=8, warmup=2)
            self.assertEqual(os.environ["JUDIKT_TELEMETRY"], "console")

        self.assertEqual(report["schema_version"], "judikt.performance.v1")
        self.assertEqual(report["results"]["allowed"], 8)
        self.assertEqual(report["results"]["denied"], 0)
        self.assertEqual(report["results"]["audit_events_verified"], 20)
        self.assertTrue(report["results"]["audit_chain_valid"])
        self.assertTrue(report["results"]["audit_signed"])
        self.assertGreater(report["throughput_calls_per_second"], 0)
        self.assertGreaterEqual(report["guarded_latency_ms"]["p99"], 0)
        rendered = json.dumps(report)
        self.assertNotIn("benchmark-audit-secret", rendered)
        self.assertNotIn("hostname", rendered.lower())
        latency = report["guarded_latency_ms"]
        self.assertLessEqual(latency["p50"], latency["p95"])
        self.assertLessEqual(latency["p95"], latency["p99"])
        self.assertLessEqual(latency["p99"], latency["max"])

    def test_single_iteration_has_stable_percentiles_and_exact_audit_count(self) -> None:
        report = run_gateway_benchmark(POLICY, iterations=1, warmup=0)
        latency = report["guarded_latency_ms"]
        self.assertEqual(latency["p50"], latency["p95"])
        self.assertEqual(latency["p95"], latency["p99"])
        self.assertEqual(latency["p99"], latency["max"])
        self.assertEqual(report["results"]["audit_events_verified"], 2)

    def test_thresholds_pass_and_fail_deterministically(self) -> None:
        report = {
            "guarded_latency_ms": {"p99": 12.5},
            "throughput_calls_per_second": 250.0,
        }
        self.assertTrue(report_passes(report, max_p99_ms=20, min_throughput=200))
        self.assertFalse(report_passes(report, max_p99_ms=10))
        self.assertFalse(report_passes(report, min_throughput=300))
        for max_p99, throughput in (
            (-1, 0),
            (0, -1),
            (float("nan"), 0),
            (float("inf"), 0),
            (0, float("nan")),
            (0, float("inf")),
        ):
            with self.subTest(max_p99=max_p99, throughput=throughput), self.assertRaises(
                PerformanceBenchmarkError
            ):
                report_passes(
                    report,
                    max_p99_ms=max_p99,
                    min_throughput=throughput,
                )

    def test_invalid_workload_parameters_are_rejected(self) -> None:
        for iterations, warmup in ((0, 0), (-1, 0), (1, -1)):
            with self.subTest(iterations=iterations, warmup=warmup), self.assertRaises(
                PerformanceBenchmarkError
            ):
                run_gateway_benchmark(POLICY, iterations=iterations, warmup=warmup)

    def test_malformed_and_missing_policy_documents_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cases = [
                (Path(directory) / "missing.json", "cannot load policy"),
                (Path(directory) / "invalid.json", "cannot load policy"),
                (Path(directory) / "list.json", "must be a JSON object"),
                (Path(directory) / "missing-rates.json", "rate_limits_per_minute"),
            ]
            cases[1][0].write_text("not-json")
            cases[2][0].write_text("[]")
            cases[3][0].write_text("{}")
            for path, message in cases:
                with self.subTest(path=path.name), self.assertRaisesRegex(
                    PerformanceBenchmarkError, message
                ):
                    run_gateway_benchmark(path, iterations=1, warmup=0)

    def test_denied_calls_close_runtime_and_restore_operator_environment(self) -> None:
        class DenyingRuntime:
            def __init__(self) -> None:
                self.closed = False

            def call_tool(self, *args: object, **kwargs: object) -> object:
                return SimpleNamespace(allowed=False, rule="synthetic_deny")

            def close(self) -> None:
                self.closed = True

        for warmup in (0, 1):
            runtime = DenyingRuntime()
            with self.subTest(warmup=warmup), patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_SINK": "operator-siem",
                    "JUDIKT_TOOL_PIN_PATH": "/operator/tool-pins.json",
                },
                clear=False,
            ):
                with patch(
                    "judikt.performance.JudiktOpsRuntime", return_value=runtime
                ), self.assertRaisesRegex(PerformanceBenchmarkError, "denied"):
                    run_gateway_benchmark(POLICY, iterations=1, warmup=warmup)
                self.assertTrue(runtime.closed)
                self.assertEqual(os.environ["JUDIKT_AUDIT_SINK"], "operator-siem")
                self.assertEqual(
                    os.environ["JUDIKT_TOOL_PIN_PATH"],
                    "/operator/tool-pins.json",
                )

    def test_invalid_audit_evidence_fails_benchmark_and_closes_runtime(self) -> None:
        class InvalidAuditRuntime:
            def __init__(self) -> None:
                self.closed = False

            def call_tool(self, *args: object, **kwargs: object) -> object:
                return SimpleNamespace(allowed=True, rule="allow")

            def audit_integrity(self) -> dict[str, object]:
                return {"valid": False, "signed": False, "checked_events": 0}

            def close(self) -> None:
                self.closed = True

        runtime = InvalidAuditRuntime()
        with patch(
            "judikt.performance.JudiktOpsRuntime", return_value=runtime
        ), self.assertRaisesRegex(PerformanceBenchmarkError, "audit evidence"):
            run_gateway_benchmark(POLICY, iterations=2, warmup=1)
        self.assertTrue(runtime.closed)

    def test_cli_threshold_failure_is_nonzero_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "performance.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "performance",
                    "--iterations",
                    "2",
                    "--warmup",
                    "0",
                    "--min-throughput",
                    "1e30",
                    "--output",
                    str(output),
                ],
                cwd=PROJECT_ROOT,
                env={**os.environ, "PYTHONPATH": "src"},
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            report = json.loads(output.read_text())
        self.assertEqual(report["schema_version"], "judikt.performance.v1")
        self.assertEqual(report["results"]["allowed"], 2)


if __name__ == "__main__":
    unittest.main()
