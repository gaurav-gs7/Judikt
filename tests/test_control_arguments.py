from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from judikt.approval import ApprovalAuthority, arguments_hash
from judikt.catalog import ToolCatalog, gateway_result
from judikt.models import JUDIKT_CONTROL_ARGUMENTS, strip_control_arguments
from judikt.paths import DEFAULT_POLICY_PATH
from judikt.runtime import JudiktRuntime
from judikt.upstreams import UpstreamServer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"
APPROVAL_SECRET = "control-arguments-approval-secret-at-least-32-bytes"


class ControlArgumentTest(unittest.TestCase):
    def _runtime(
        self,
        root: Path,
        mode: str,
        *,
        allowed: list[str],
        demo_boolean: bool = False,
    ) -> tuple[JudiktRuntime, Path]:
        call_log = root / "calls.jsonl"
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        policy["allowed_tools"] = {"profile-tools": allowed}
        policy["actor_permissions"] = {"local-operator": allowed, "anonymous": allowed}
        policy["approval_required"] = ["delete_repo"]
        policy["allow_demo_boolean_approval"] = demo_boolean
        policy["tool_pinning"]["first_use"] = "auto"
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy))
        runtime = JudiktRuntime(
            policy_path,
            root / "audit.db",
            upstream_servers=[
                UpstreamServer(
                    name="profile-tools",
                    command=(sys.executable, str(FIXTURE), mode, str(call_log)),
                )
            ],
            approval_authority=ApprovalAuthority(APPROVAL_SECRET),
        )
        self.addCleanup(runtime.close)
        return runtime, call_log

    @staticmethod
    def _calls(call_log: Path) -> list[dict[str, Any]]:
        if not call_log.exists():
            return []
        return [json.loads(line) for line in call_log.read_text().splitlines()]

    def test_approved_call_reaches_strict_upstream_without_control_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, call_log = self._runtime(
                Path(directory), "strict-profiles", allowed=["delete_repo", "read_file"]
            )
            arguments = {"target": "prod-infra"}
            token = runtime.policy.issue_approval(
                actor="local-operator",
                reason="reviewed",
                server="profile-tools",
                tool="delete_repo",
                arguments=arguments,
            )

            result = runtime.call_tool(
                "profile-tools",
                "delete_repo",
                {**arguments, "approval_token": token},
            )
            audit = runtime.audit.recent()
            calls = self._calls(call_log)
            logged = call_log.read_text()

        self.assertTrue(result.allowed, result.reason)
        self.assertEqual(calls, [{"tool": "delete_repo", "arguments": arguments}])
        self.assertNotIn(token, logged)
        self.assertTrue(audit[0]["control_arguments_stripped"])
        self.assertEqual(audit[0]["arguments"]["approval_token"], "[REDACTED]")

    def test_demo_boolean_approval_is_not_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, call_log = self._runtime(
                Path(directory),
                "strict-profiles",
                allowed=["delete_repo"],
                demo_boolean=True,
            )

            result = runtime.call_tool(
                "profile-tools",
                "delete_repo",
                {"target": "lab", "approved": True},
            )
            calls = self._calls(call_log)

        self.assertTrue(result.allowed, result.reason)
        self.assertEqual(calls, [{"tool": "delete_repo", "arguments": {"target": "lab"}}])

    def test_unapproved_read_call_records_no_stripping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, call_log = self._runtime(
                Path(directory), "strict-profiles", allowed=["read_file"]
            )
            result = runtime.call_tool("profile-tools", "read_file", {"target": "a"})
            audit = runtime.audit.recent()
            calls = self._calls(call_log)

        self.assertTrue(result.allowed, result.reason)
        self.assertFalse(audit[0]["control_arguments_stripped"])
        self.assertEqual(calls, [{"tool": "read_file", "arguments": {"target": "a"}}])

    def test_tool_declaring_control_argument_is_excluded_and_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, call_log = self._runtime(
                Path(directory),
                "control-collision",
                allowed=["collide_tool", "read_file"],
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                catalog = ToolCatalog(runtime, "local-operator")
            names = {tool.name for tool in catalog.tools()}
            denied = runtime.call_tool(
                "profile-tools", "collide_tool", {"target": "x", "approval_token": "t"}
            )
            calls = self._calls(call_log)

        self.assertNotIn("collide_tool", names)
        self.assertIn("read_file", names)
        self.assertIn("collide_tool", stderr.getvalue())
        self.assertIn("control_argument_collision", stderr.getvalue())
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.rule, "control_argument_collision")
        self.assertTrue(gateway_result(denied)["isError"])
        self.assertEqual(calls, [])

    def test_approval_gated_tools_advertise_optional_token_and_pins_hold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._runtime(
                Path(directory),
                "strict-profiles",
                allowed=["delete_repo", "read_file"],
            )
            catalog = ToolCatalog(runtime, "local-operator")
            tools = {tool.name: tool.as_mcp() for tool in catalog.tools()}
            upstream = {
                tool["name"]: tool
                for tool in runtime.upstreams.definitions()["profile-tools"]
            }
            report = runtime.tool_integrity.verify(
                "profile-tools", list(upstream.values())
            )

        gated = tools["delete_repo"]["inputSchema"]
        self.assertEqual(gated["properties"]["approval_token"]["type"], "string")
        self.assertIn(
            "Judikt removes it before the call reaches the upstream",
            gated["properties"]["approval_token"]["description"],
        )
        self.assertNotIn("approval_token", gated["required"])
        self.assertNotIn("approved", gated["properties"])
        self.assertNotIn("approval_token", tools["read_file"]["inputSchema"]["properties"])
        # The upstream's own definition is untouched, so pins still verify.
        self.assertNotIn("approval_token", upstream["delete_repo"]["inputSchema"]["properties"])
        self.assertNotEqual(report.status, "drifted")

    def test_risk_action_approval_also_advertises_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = json.loads(DEFAULT_POLICY_PATH.read_text())
            policy["risk"] = {"risk_actions": {"critical": "require_approval"}, "argument_rules": [
                {"argument": "target", "in": ["prod"], "add": 40, "evidence": "production target"}
            ]}
            path = root / "policy.json"
            path.write_text(json.dumps(policy))
            from judikt.policy import PolicyEngine

            engine = PolicyEngine(path, ApprovalAuthority(APPROVAL_SECRET))
            definition = {"name": "delete_repo", "annotations": {"destructiveHint": True}}

            self.assertTrue(engine.may_require_approval("delete_repo", definition))
            self.assertFalse(
                engine.may_require_approval(
                    "read_file", {"name": "read_file", "annotations": {"readOnlyHint": True}}
                )
            )


class ControlArgumentHelpersTest(unittest.TestCase):
    def test_constant_drives_stripping_and_approval_binding(self) -> None:
        self.assertEqual(JUDIKT_CONTROL_ARGUMENTS, {"approval_token", "approved"})
        arguments = {"target": "x", "approval_token": "token", "approved": True}
        self.assertEqual(strip_control_arguments(arguments), {"target": "x"})
        self.assertEqual(arguments_hash(arguments), arguments_hash({"target": "x"}))

    def test_demo_backends_do_not_declare_control_arguments(self) -> None:
        from judikt.backends import INCIDENT_TOOLS, KUBERNETES_TOOLS, PLATFORM_TOOLS

        for tool in [*PLATFORM_TOOLS, *KUBERNETES_TOOLS, *INCIDENT_TOOLS]:
            with self.subTest(tool=tool.name):
                properties = set(tool.input_schema.get("properties", {}))
                self.assertFalse(properties & JUDIKT_CONTROL_ARGUMENTS)


if __name__ == "__main__":
    unittest.main()
