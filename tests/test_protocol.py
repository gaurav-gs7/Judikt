from __future__ import annotations

import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.models import Tool
from judikt.protocol import MCPProtocolError, StdioMCPClient, is_mcp_tool_error, serve_stdio


FIXTURE = Path(__file__).parent / "fixtures" / "external_mcp_server.py"


class StdioMCPClientTest(unittest.TestCase):
    def _client(self, mode: str) -> StdioMCPClient:
        client = StdioMCPClient(
            f"fixture-{mode}",
            command=[sys.executable, str(FIXTURE)],
            environment={"ATTACK_FIXTURE_MODE": mode},
        )
        self.addCleanup(client.close)
        return client

    def test_supports_standard_text_only_tool_results(self) -> None:
        result = self._client("text-only").call_tool(
            "external.fetch_issue", {"issue_id": "INC-100"}
        )

        self.assertIn("content", result)
        self.assertIn("INC-100", result["content"][0]["text"])

    def test_follows_paginated_tool_catalogs(self) -> None:
        tools = self._client("paginated").list_tools()

        self.assertEqual(
            {tool["name"] for tool in tools},
            {"external.fetch_issue", "external.second_tool"},
        )

    def test_answers_server_initiated_roots_request(self) -> None:
        tools = self._client("server-request").list_tools()

        self.assertEqual([tool["name"] for tool in tools], ["external.fetch_issue"])

    def test_answers_server_initiated_ping_request(self) -> None:
        tools = self._client("server-ping").list_tools()

        self.assertEqual([tool["name"] for tool in tools], ["external.fetch_issue"])

    def test_rejects_repeated_pagination_cursor(self) -> None:
        with self.assertRaisesRegex(MCPProtocolError, "repeated a pagination cursor"):
            self._client("repeated-cursor").list_tools()

    def test_rejects_malformed_tool_catalog(self) -> None:
        with self.assertRaisesRegex(MCPProtocolError, "invalid tool catalog"):
            self._client("malformed-catalog").list_tools()

    def test_preserves_mcp_tool_error_for_runtime_scanning(self) -> None:
        result = self._client("tool-error").call_tool(
            "external.fetch_issue", {"issue_id": "INC-ERROR"}
        )

        self.assertTrue(is_mcp_tool_error(result))
        self.assertIn("INC-ERROR", result["content"][0]["text"])

    def test_external_server_receives_only_explicitly_brokered_environment(self) -> None:
        with patch.dict(os.environ, {"UNBROKERED_SECRET": "must-not-leak"}):
            client = StdioMCPClient(
                "fixture-environment",
                command=[sys.executable, str(FIXTURE)],
                environment={
                    "ATTACK_FIXTURE_MODE": "environment",
                    "BROKERED_VALUE": "operator-selected",
                },
                inherit_environment=False,
            )
            self.addCleanup(client.close)
            result = client.call_tool("external.fetch_issue", {"issue_id": "INC-101"})

        payload = result["structuredContent"]
        self.assertFalse(payload["unbrokered_secret_visible"])
        self.assertEqual(payload["brokered_value"], "operator-selected")


class StdioMCPServerTest(unittest.TestCase):
    def test_dispatches_native_and_legacy_results_with_locked_protocol_output(self) -> None:
        requests = [
            "not-json",
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "initialize",
                    "params": {"protocolVersion": "unsupported"},
                }
            ),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {}}),
            json.dumps(
                {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "fixture.echo", "arguments": {"mode": "legacy"}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {"name": "fixture.echo", "arguments": {"mode": "native"}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "missing.tool", "arguments": {}},
                }
            ),
            json.dumps(
                {"jsonrpc": "2.0", "id": 8, "method": "resources/list", "params": {}}
            ),
        ]
        stdin = io.StringIO("\n".join(requests) + "\n")
        stdout = io.StringIO()
        emitted: list[object] = []

        def handler(_tool: str, arguments: dict[str, object]) -> dict[str, object]:
            if arguments["mode"] == "native":
                return {
                    "content": [{"type": "text", "text": "native"}],
                    "structuredContent": {"mode": "native"},
                    "isError": False,
                }
            return {"mode": "legacy"}

        def subscribe(emit: object) -> None:
            emitted.append(emit)
            emit()  # type: ignore[operator]

        tool = Tool(
            "fixture.echo",
            "Echo a fixture value.",
            {"type": "object"},
            title="Echo",
            annotations={"readOnlyHint": True},
            output_schema={"type": "object"},
            meta={"fixture": True},
        )
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            serve_stdio(
                "fixture",
                [],
                handler,
                tools_provider=lambda: [tool],
                accepted_tool_names_provider=lambda: {"fixture.echo"},
                subscribe_list_changed=subscribe,
            )

        messages = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(messages[0]["method"], "notifications/tools/list_changed")
        self.assertEqual(messages[1]["error"]["code"], -32000)
        by_id = {message.get("id"): message for message in messages if "id" in message}
        self.assertEqual(by_id[1]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(by_id[2]["result"]["protocolVersion"], "2025-11-25")
        self.assertTrue(by_id[2]["result"]["capabilities"]["tools"]["listChanged"])
        self.assertEqual(by_id[3]["result"], {})
        listed = by_id[4]["result"]["tools"][0]
        self.assertEqual(listed["title"], "Echo")
        self.assertEqual(listed["outputSchema"], {"type": "object"})
        self.assertEqual(listed["_meta"], {"fixture": True})
        self.assertEqual(by_id[5]["result"]["structuredContent"], {"mode": "legacy"})
        self.assertEqual(by_id[6]["result"]["content"][0]["text"], "native")
        self.assertEqual(by_id[7]["error"]["code"], -32602)
        self.assertEqual(by_id[8]["error"]["code"], -32000)
        self.assertEqual(len(emitted), 1)


if __name__ == "__main__":
    unittest.main()
