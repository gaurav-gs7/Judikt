from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from judikt.approval import ApprovalAuthority
from judikt.auth import AuthConfig, Authenticator
from judikt.ops_runtime import JudiktOpsRuntime
from judikt.real_mcp import _static_denial_as_error, register_tools
from judikt.request_context import bind_authenticated_subject, reset_authenticated_subject


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "config" / "policies.yaml"
SECRET = "control-plane-approval-secret-at-least-32-bytes"


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *, name: str, description: str):
        del description

        def register(function: object) -> object:
            self.tools[name] = function
            return function

        return register


class ControlPlaneAuthorizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.runtime = JudiktOpsRuntime(
            POLICY,
            Path(self.temp_dir.name) / "audit.db",
            include_demo_servers=True,
            approval_authority=ApprovalAuthority(SECRET),
        )
        self.mcp = _FakeMCP()
        register_tools(self.mcp, self.runtime)

    def tearDown(self) -> None:
        self.runtime.close()
        self.temp_dir.cleanup()

    def _call(self, name: str, **arguments: object) -> dict[str, object]:
        return self.mcp.tools[name](**arguments)  # type: ignore[operator, no-any-return]

    def test_no_claims_deny_every_admin_tool(self) -> None:
        calls = [
            ("judikt.set_tool_enabled", {"tool": "platform.health", "enabled": False}),
            ("judikt.set_server_enabled", {"server": "platform-ops", "enabled": False}),
            ("judikt.runtime_state", {}),
            (
                "judikt.issue_approval",
                {
                    "actor": "operator",
                    "reason": "must be denied",
                    "server": "platform-ops",
                    "tool": "platform.health",
                    "arguments": {"service": "payments-api"},
                },
            ),
        ]
        for name, arguments in calls:
            with self.subTest(name=name):
                result = self._call(name, **arguments)
                self.assertEqual(result["rule"], "admin_authorization")

    def test_static_bearer_defaults_to_execute_and_cannot_administer(self) -> None:
        auth = Authenticator(AuthConfig(bearer_token="shared")).authenticate("Bearer shared")
        context = bind_authenticated_subject("", auth.claims)
        try:
            health = self._call("platform.health", service="payments-api")
            admin = self._call(
                "judikt.set_tool_enabled",
                tool="platform.health",
                enabled=False,
            )
        finally:
            reset_authenticated_subject(context)

        self.assertTrue(health["allowed"])
        self.assertEqual(admin["rule"], "admin_authorization")

    def test_static_bearer_admin_role_allows_admin_tools(self) -> None:
        auth = Authenticator(
            AuthConfig(bearer_token="shared", bearer_role="admin")
        ).authenticate("Bearer shared")
        context = bind_authenticated_subject("", auth.claims)
        try:
            state = self._call("judikt.runtime_state")
            disabled = self._call(
                "judikt.set_tool_enabled",
                tool="platform.health",
                enabled=False,
            )
            self._call(
                "judikt.set_tool_enabled",
                tool="platform.health",
                enabled=True,
                reason="restore shared test state",
            )
        finally:
            reset_authenticated_subject(context)

        self.assertIn("audit_integrity", state)
        self.assertIn("platform.health", disabled["disabled_tools"])

    def test_jwt_scope_and_group_admin_authorization(self) -> None:
        cases = [
            ({"scope": "mcp:execute"}, False),
            ({"scope": "mcp:admin"}, True),
            ({"groups": ["mcp-admin"]}, True),
            ({"cognito:groups": ["mcp-admin"]}, True),
        ]
        for claims, expected in cases:
            with self.subTest(claims=claims):
                context = bind_authenticated_subject("operator", claims)
                try:
                    result = self._call("judikt.runtime_state")
                finally:
                    reset_authenticated_subject(context)
                self.assertEqual("audit_integrity" in result, expected)
                if not expected:
                    self.assertEqual(result["rule"], "admin_authorization")

    def test_request_approval_requires_execute_role(self) -> None:
        read_context = bind_authenticated_subject("reader", {"scope": "mcp:read"})
        try:
            denied = self._call(
                "judikt.request_approval",
                actor="reader",
                reason="test",
                server="platform-ops",
                tool="platform.health",
                arguments={"service": "payments-api"},
            )
        finally:
            reset_authenticated_subject(read_context)
        execute_context = bind_authenticated_subject("operator", {"scope": "mcp:execute"})
        try:
            passed_auth = self._call(
                "judikt.request_approval",
                actor="operator",
                reason="test",
                server="platform-ops",
                tool="platform.health",
                arguments={"service": "payments-api"},
            )
        finally:
            reset_authenticated_subject(execute_context)

        self.assertEqual(denied["rule"], "execute_authorization")
        self.assertEqual(passed_auth["status"], "ERROR")
        self.assertIn("Slack approvals require", passed_auth["reason"])


class StaticDenialAsErrorTest(unittest.TestCase):
    def setUp(self) -> None:
        from mcp import types

        self.types = types

    def test_refusals_become_mcp_tool_errors(self) -> None:
        refusal = {"allowed": False, "rule": "admin_authorization", "reason": "denied"}
        for result in (refusal, ([], refusal), ([self.types.TextContent(type="text", text="x")], refusal)):
            with self.subTest(result=type(result).__name__):
                converted = _static_denial_as_error(result, self.types)
                self.assertIsInstance(converted, self.types.CallToolResult)
                self.assertTrue(converted.isError)
                self.assertEqual(converted.structuredContent, refusal)
                self.assertTrue(converted.content)
        errored = _static_denial_as_error({"status": "ERROR", "reason": "slack"}, self.types)
        self.assertTrue(errored.isError)

    def test_successful_and_non_dict_results_pass_through_unchanged(self) -> None:
        allowed = {"allowed": True, "result": {}}
        self.assertIs(_static_denial_as_error(allowed, self.types), allowed)
        pair = ([], {"disabled_tools": []})
        self.assertIs(_static_denial_as_error(pair, self.types), pair)
        content = [self.types.TextContent(type="text", text="ok")]
        self.assertIs(_static_denial_as_error(content, self.types), content)


if __name__ == "__main__":
    unittest.main()
