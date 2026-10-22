from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from judikt.ops_runtime import JudiktOpsRuntime
from judikt.real_mcp import register_tools
from judikt.request_context import bind_authenticated_subject, reset_authenticated_subject


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "config" / "policies.yaml"
ROLLBACK_PLAN = "verify rollout health and restore previous release if errors increase"


class JudiktOpsRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def runtime(self) -> JudiktOpsRuntime:
        db = Path(self.temp_dir.name) / "audit.db"
        return JudiktOpsRuntime(
            POLICY,
            db,
            include_demo_servers=True,
            circuit_failure_threshold=2,
            circuit_cooldown_seconds=60,
        )

    def test_demo_adapters_are_not_loaded_by_default(self) -> None:
        runtime = JudiktOpsRuntime(POLICY, Path(self.temp_dir.name) / "neutral.db")
        try:
            self.assertFalse(runtime.demo_servers_enabled)
            self.assertIsNone(runtime.platform)
            self.assertIsNone(runtime.kubernetes)
            self.assertIsNone(runtime.incidents)
            self.assertEqual(runtime.list_tools(), {})
        finally:
            runtime.close()

    def test_real_mcp_registration_omits_demo_tools_by_default(self) -> None:
        class FakeMCP:
            def __init__(self) -> None:
                self.tools: dict[str, object] = {}

            def tool(self, *, name: str, description: str):
                def register(function: object) -> object:
                    self.tools[name] = function
                    return function

                return register

        runtime = JudiktOpsRuntime(POLICY, Path(self.temp_dir.name) / "registration.db")
        mcp = FakeMCP()
        try:
            register_tools(mcp, runtime)
            self.assertIn("judikt.call_upstream", mcp.tools)
            self.assertIn("judikt.runtime_state", mcp.tools)
            self.assertNotIn("platform.health", mcp.tools)
            self.assertNotIn("incident.create", mcp.tools)
            self.assertNotIn("kubernetes.get_pod", mcp.tools)
        finally:
            runtime.close()

    def test_real_runtime_allows_health_and_audits_call(self) -> None:
        runtime = self.runtime()
        try:
            result = runtime.call_tool("platform-ops", "platform.health", {"service": "payments-api"})
            self.assertTrue(result.allowed)
            self.assertEqual(result.result["service"], "payments-api")
            audit = runtime.recent_audit()
            self.assertEqual(len(audit), 1)
            self.assertTrue(audit[0]["allowed"])
        finally:
            runtime.close()

    def test_real_runtime_blocks_unapproved_rollback(self) -> None:
        runtime = self.runtime()
        try:
            result = runtime.call_tool(
                "platform-ops",
                "platform.rollback_deployment",
                {"service": "payments-api", "version": "payments-api@2026.05.2", "actor": "gaurav"},
            )
            self.assertFalse(result.allowed)
            self.assertEqual(result.reason, "approval token is required for this critical-risk action")
            self.assertEqual(result.risk_level, "critical")
        finally:
            runtime.close()

    def test_real_runtime_redacts_config_secret(self) -> None:
        runtime = self.runtime()
        try:
            result = runtime.call_tool("platform-ops", "platform.read_config", {"service": "payments-api"})
            self.assertTrue(result.allowed)
            self.assertEqual(result.result["api_key"], "[REDACTED]")
            self.assertEqual(runtime.recent_audit()[0]["result"]["api_key"], "[REDACTED]")
        finally:
            runtime.close()

    def test_real_runtime_opens_circuit_after_repeated_upstream_failures(self) -> None:
        runtime = self.runtime()
        try:
            args = {"service": "payments-api", "command": "dependency-health"}
            with mock.patch.object(runtime.platform, "call", side_effect=RuntimeError("backend unavailable")):
                first = runtime.call_tool("platform-ops", "platform.run_diagnostic", args)
                second = runtime.call_tool("platform-ops", "platform.run_diagnostic", args)
                third = runtime.call_tool("platform-ops", "platform.run_diagnostic", args)
            self.assertFalse(first.allowed)
            self.assertFalse(second.allowed)
            self.assertFalse(third.allowed)
            self.assertEqual(third.reason, "circuit breaker is open after repeated upstream failures")
            self.assertTrue(runtime.circuit_breakers()["platform-ops/platform.run_diagnostic"]["open"])
        finally:
            runtime.close()

    def test_real_runtime_supports_kubernetes_dry_run_and_requires_actor(self) -> None:
        runtime = self.runtime()
        try:
            missing_actor = runtime.call_tool(
                "kubernetes",
                "kubernetes.restart_pod",
                {"namespace": "prod", "pod": "payment-service-xyz"},
            )
            dry_run = runtime.call_tool(
                "kubernetes",
                "kubernetes.restart_pod",
                {
                    "namespace": "prod",
                    "pod": "payment-service-xyz",
                    "actor": "gaurav",
                    "rollback_plan": ROLLBACK_PLAN,
                    "dry_run": True,
                },
            )

            self.assertFalse(missing_actor.allowed)
            self.assertEqual(missing_actor.rule, "authz")
            self.assertTrue(dry_run.allowed)
            self.assertEqual(dry_run.action, "DRY_RUN_ONLY")
            self.assertFalse(dry_run.result["executed"])
        finally:
            runtime.close()

    def test_real_runtime_supports_shadow_mode_without_execution(self) -> None:
        runtime = self.runtime()
        try:
            result = runtime.call_tool(
                "platform-ops",
                "platform.restart_deployment",
                {
                    "service": "payments-api",
                    "actor": "gaurav",
                    "rollback_plan": ROLLBACK_PLAN,
                    "shadow_mode": True,
                },
            )

            self.assertTrue(result.allowed)
            self.assertEqual(result.action, "SHADOW_MODE")
            self.assertFalse(result.result["executed"])
            self.assertEqual(runtime.recent_audit()[0]["action"], "SHADOW_MODE")
        finally:
            runtime.close()

    def test_authenticated_subject_cannot_spoof_actor(self) -> None:
        runtime = self.runtime()
        context_token = bind_authenticated_subject("readonly")
        try:
            result = runtime.call_tool(
                "platform-ops",
                "platform.restart_deployment",
                {
                    "service": "payments-api",
                    "actor": "sre-oncall",
                    "rollback_plan": ROLLBACK_PLAN,
                },
            )

            self.assertFalse(result.allowed)
            self.assertEqual(result.rule, "identity_mismatch")
        finally:
            reset_authenticated_subject(context_token)
            runtime.close()

    def test_control_plane_state_exposes_rate_limiter_mode(self) -> None:
        class FakeMCP:
            def __init__(self) -> None:
                self.tools: dict[str, object] = {}

            def tool(self, *, name: str, description: str):
                def register(function: object) -> object:
                    self.tools[name] = function
                    return function

                return register

        runtime = self.runtime()
        mcp = FakeMCP()
        try:
            register_tools(mcp, runtime)
            state = mcp.tools["judikt.runtime_state"]()  # type: ignore[operator]
            self.assertEqual(state["rate_limiter"], {"mode": "local"})
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
