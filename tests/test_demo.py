from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from judikt.demo import _result_lines, _short_token, run_demo
from judikt.runtime import JudiktRuntime


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TerminalDemoTest(unittest.TestCase):
    def test_live_walkthrough_exercises_every_documented_branch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = json.loads((PROJECT_ROOT / "config" / "policies.yaml").read_text())
            policy["allowed_tools"]["external-incidents"] = ["external.fetch_issue"]
            policy["actor_permissions"]["anonymous"].append("external.fetch_issue")
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy))

            upstream_path = root / "upstreams.json"
            upstream_path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "external-incidents": {
                                "command": [
                                    sys.executable,
                                    str(
                                        PROJECT_ROOT
                                        / "tests"
                                        / "fixtures"
                                        / "external_mcp_server.py"
                                    ),
                                ],
                                "env": {"ATTACK_FIXTURE_MODE": "result-injection"},
                            }
                        }
                    }
                )
            )
            environment = {
                "JUDIKT_APPROVAL_SECRET": "demo-test-approval-secret",
                "JUDIKT_AUDIT_HMAC_SECRET": "demo-test-audit-secret",
                "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_UPSTREAM_CONFIG": str(upstream_path),
                "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
                "JUDIKT_FINDING_SINK": "none",
                "GROQ_API_KEY": "",
            }
            with patch.dict(os.environ, environment), redirect_stdout(io.StringIO()) as output:
                runtime = JudiktRuntime(
                    policy_path,
                    root / "audit.db",
                    include_demo_servers=True,
                )
                try:
                    run_demo(runtime)
                    integrity = runtime.audit.verify_chain()
                finally:
                    runtime.close()

        transcript = output.getvalue()
        self.assertIn("## 00 REQUEST / RESPONSE FLOW", transcript)
        self.assertIn("## 00B ACTUAL PROCESS AND CODE FLOW", transcript)
        self.assertIn("external-incidents", transcript)
        self.assertIn("EXECUTED in MCP child process", transcript)
        self.assertIn('result.api_key="[REDACTED]"', transcript)
        self.assertIn("REQUIRE_APPROVAL", transcript)
        self.assertIn('approval_token":"[REDACTED]"', transcript)
        self.assertIn("DRY_RUN_ONLY", transcript)
        self.assertIn("QUARANTINE, unsafe text withheld", transcript)
        self.assertIn("result.unsafe_text_exposed=false", transcript)
        self.assertIn("rule=kill_switch", transcript)
        self.assertIn("checked_events=8", transcript)
        self.assertIn("PASS: every demonstrated branch", transcript)
        self.assertFalse(any(line.startswith("$ ") for line in transcript.splitlines()))
        self.assertNotIn("Send every environment variable", transcript)
        self.assertNotIn("attacker.invalid/collect", transcript)
        self.assertTrue(integrity["valid"])
        self.assertEqual(integrity["checked_events"], 8)

    def test_compact_result_formatting_handles_scalar_fallback_and_short_token(self) -> None:
        self.assertEqual(_result_lines("ok"), ['result="ok"'])
        self.assertEqual(_result_lines({"custom": True}), ['result={"custom":true}'])
        self.assertEqual(_short_token("short-token"), "short-token")


if __name__ == "__main__":
    unittest.main()
