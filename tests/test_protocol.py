from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.protocol import MCPProtocolError, StdioMCPClient, is_mcp_tool_error


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


if __name__ == "__main__":
    unittest.main()
