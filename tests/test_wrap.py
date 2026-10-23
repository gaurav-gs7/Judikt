from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from judikt.protocol import StdioMCPClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"


class WrapEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.audit_path = root / "audit.db"
        self.client = StdioMCPClient(
            "judikt-wrap",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(self.audit_path),
                "wrap",
                "--name",
                "external-incidents",
                "--",
                sys.executable,
                str(FIXTURE),
                "identity-fields",
            ],
            environment={
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "JUDIKT_APPROVAL_SECRET": "wrap-test-approval",
                "JUDIKT_AUDIT_HMAC_SECRET": "wrap-test-audit",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
                "JUDIKT_UPSTREAM_CONFIG": str(root / "must-not-be-loaded.json"),
            },
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )

    def tearDown(self) -> None:
        self.client.close()
        self.temp_dir.cleanup()

    def test_wrap_discovers_proxies_guards_and_audits_upstream(self) -> None:
        tools = self.client.list_tools()
        self.assertEqual(
            [tool["name"] for tool in tools],
            [
                "external.fetch_issue",
                "external.get_user",
                "external.record_request",
            ],
        )

        user_lookup = self.client.call_tool(
            "external.get_user",
            {"user": "octocat"},
        )
        lookup_with_actor = self.client.call_tool(
            "external.get_user",
            {"user": "octocat", "actor": "gaurav"},
        )
        requested = self.client.call_tool(
            "external.record_request",
            {"requested_by": "release-manager"},
        )
        blocked = self.client.call_tool(
            "external.fetch_issue",
            {"issue_id": "/home/operator/.ssh/id_rsa"},
        )

        self.assertTrue(user_lookup["allowed"])
        self.assertEqual(
            user_lookup["result"]["received_arguments"],
            {"user": "octocat"},
        )
        self.assertTrue(lookup_with_actor["allowed"])
        self.assertEqual(
            lookup_with_actor["result"]["received_arguments"],
            {"user": "octocat", "actor": "gaurav"},
        )
        self.assertTrue(requested["allowed"])
        self.assertEqual(
            requested["result"]["received_arguments"],
            {"requested_by": "release-manager"},
        )
        self.assertTrue(blocked["blocked"])
        self.assertIn("blocked security pattern", blocked["reason"])

        connection = sqlite3.connect(self.audit_path)
        try:
            rows = connection.execute(
                "SELECT allowed, arguments_json FROM audit_events ORDER BY id"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual([row[0] for row in rows], [1, 1, 1, 0])
        self.assertEqual(json.loads(rows[0][1]), {"user": "octocat"})
        self.assertEqual(
            json.loads(rows[1][1]),
            {"actor": "gaurav", "user": "octocat"},
        )
        self.assertEqual(
            json.loads(rows[2][1]),
            {"requested_by": "release-manager"},
        )

    def test_wrap_does_not_load_configured_or_demo_servers(self) -> None:
        names = {tool["name"] for tool in self.client.list_tools()}
        self.assertNotIn("platform.health", names)
        self.assertNotIn("kubernetes.get_pod", names)
        self.assertNotIn("incident.create", names)


class WrapCLITest(unittest.TestCase):
    def test_missing_command_fails_without_traceback(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "judikt.cli", "wrap"],
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("upstream command is required", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
