from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from judikt.paths import DEFAULT_POLICY_PATH
from judikt.protocol import MCPProtocolError, STABLE_PROTOCOL_VERSION, StdioMCPClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"
LIST_CHANGED_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "list_changed_mcp_server.py"


class MCPResultSemanticsTest(unittest.TestCase):
    def test_allowed_text_content_is_preserved_exactly(self) -> None:
        with self._wrapped_client("exact-content") as client:
            result = client.call_tool("external.fetch_issue", {"issue_id": "INC-42"})

        self.assertEqual(
            result["content"],
            [
                {
                    "type": "text",
                    "text": "exact upstream text",
                    "annotations": {"audience": ["assistant"]},
                }
            ],
        )
        self.assertFalse(result["isError"])
        self.assertEqual(result["_meta"]["io.judikt/decision"]["rule"], "allow")

    def test_content_structured_content_and_upstream_meta_are_preserved(self) -> None:
        with self._wrapped_client("full-result") as client:
            result = client.call_tool("external.fetch_issue", {"issue_id": "INC-43"})

        self.assertEqual(result["structuredContent"]["issue_id"], "INC-43")
        self.assertIn("INC-43", result["content"][0]["text"])
        self.assertEqual(result["_meta"]["fixture/request-id"], "upstream-42")
        self.assertEqual(
            set(result["_meta"]["io.judikt/decision"]),
            {"correlation_id", "rule", "action", "risk_level"},
        )

    def test_image_block_passes_through_unchanged(self) -> None:
        expected = {
            "type": "image",
            "data": "aW1hZ2UtYnl0ZXM=",
            "mimeType": "image/png",
        }
        with self._wrapped_client("image") as client:
            result = client.call_tool("external.fetch_issue", {"issue_id": "INC-44"})

        self.assertEqual(result["content"], [expected])

    def test_upstream_tool_error_is_mirrored(self) -> None:
        with self._wrapped_client("tool-error") as client:
            result = client.call_tool("external.fetch_issue", {"issue_id": "INC-45"})

        self.assertTrue(result["isError"])
        self.assertIn("INC-45", result["content"][0]["text"])
        self.assertEqual(
            result["_meta"]["io.judikt/decision"]["rule"],
            "upstream_error",
        )

    def test_tool_metadata_is_forwarded_and_approval_annotation_is_tightened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._policy(
                root,
                ["external.fetch_issue"],
                approval_required=["external.fetch_issue"],
                classification={"external.fetch_issue": {"tier": "write"}},
            )
            with self._wrapped_client("metadata", root=root, policy=policy) as client:
                tool = client.list_tools()[0]

        self.assertEqual(tool["title"], "Fetch issue")
        self.assertEqual(tool["outputSchema"]["required"], ["issue_id"])
        self.assertEqual(tool["_meta"], {"fixture/catalog": "preserved"})
        self.assertFalse(tool["annotations"]["readOnlyHint"])
        self.assertTrue(tool["annotations"]["destructiveHint"])

    @contextmanager
    def _wrapped_client(
        self,
        mode: str,
        *,
        root: Path | None = None,
        policy: Path | None = None,
    ) -> Iterator[StdioMCPClient]:
        temporary = tempfile.TemporaryDirectory() if root is None else None
        actual_root = Path(temporary.name) if temporary is not None else root
        assert actual_root is not None
        policy_args = ["--policy", str(policy)] if policy is not None else []
        client = StdioMCPClient(
            "semantics",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(actual_root / "audit.db"),
                "wrap",
                *policy_args,
                "--name",
                "external-incidents",
                "--",
                sys.executable,
                str(EXTERNAL_FIXTURE),
                mode,
            ],
            environment=self._environment(actual_root),
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )
        try:
            yield client
        finally:
            client.close()
            if temporary is not None:
                temporary.cleanup()

    @staticmethod
    def _policy(
        root: Path,
        allowed: list[str],
        *,
        approval_required: list[str] | None = None,
        classification: dict[str, object] | None = None,
        server: str = "external-incidents",
    ) -> Path:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        policy["allowed_tools"] = {server: allowed}
        policy["actor_permissions"] = {"local-operator": allowed, "anonymous": []}
        policy["approval_required"] = approval_required or []
        policy["tool_classification"] = classification or {}
        path = root / "policy.json"
        path.write_text(json.dumps(policy))
        return path

    @staticmethod
    def _environment(root: Path, *, pin_mode: str = "enforce") -> dict[str, str]:
        return {
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_APPROVAL_SECRET": "semantics-approval-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_HMAC_SECRET": "semantics-audit-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
            "JUDIKT_TOOL_PIN_MODE": pin_mode,
            "JUDIKT_UPSTREAM_CONFIG": "",
        }


class MCPListChangedTest(unittest.TestCase):
    def test_added_tool_is_advertised_only_when_policy_allows_it(self) -> None:
        for allowed, expected in (
            (["dynamic.trigger", "dynamic.added"], {"dynamic.trigger", "dynamic.added"}),
            (["dynamic.trigger"], {"dynamic.trigger"}),
        ):
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy = MCPResultSemanticsTest._policy(root, allowed, server="dynamic")
                with self._client(root, policy, "add", pin_mode="disabled") as client:
                    notifications: list[dict[str, object]] = []
                    client.add_notification_handler(
                        "notifications/tools/list_changed",
                        lambda message: notifications.append(message),
                    )
                    self.assertEqual(
                        {tool["name"] for tool in client.list_tools()},
                        {"dynamic.trigger"},
                    )
                    client.call_tool("dynamic.trigger", {})
                    self.assertTrue(self._wait_for(lambda: bool(notifications)))
                    self.assertTrue(
                        self._wait_for(
                            lambda: {tool["name"] for tool in client.list_tools()} == expected
                        )
                    )

    def test_changed_pinned_tool_is_excluded_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = ["dynamic.trigger", "dynamic.stable"]
            policy = MCPResultSemanticsTest._policy(root, allowed, server="dynamic")
            with self._client(root, policy, "change", pin_mode="enforce") as client:
                notifications: list[dict[str, object]] = []
                client.add_notification_handler(
                    "notifications/tools/list_changed",
                    lambda message: notifications.append(message),
                )
                self.assertEqual(
                    {tool["name"] for tool in client.list_tools()},
                    set(allowed),
                )
                client.call_tool("dynamic.trigger", {})
                self.assertTrue(self._wait_for(lambda: bool(notifications)))
                self.assertTrue(
                    self._wait_for(
                        lambda: {tool["name"] for tool in client.list_tools()}
                        == {"dynamic.trigger"}
                    )
                )
                with self.assertRaisesRegex(MCPProtocolError, "unknown tool"):
                    client.call_tool("dynamic.stable", {})

    @contextmanager
    def _client(
        self,
        root: Path,
        policy: Path,
        mode: str,
        *,
        pin_mode: str,
    ) -> Iterator[StdioMCPClient]:
        client = StdioMCPClient(
            "dynamic-gateway",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(root / "audit.db"),
                "wrap",
                "--policy",
                str(policy),
                "--name",
                "dynamic",
                "--",
                sys.executable,
                str(LIST_CHANGED_FIXTURE),
                mode,
            ],
            environment=MCPResultSemanticsTest._environment(root, pin_mode=pin_mode),
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )
        try:
            yield client
        finally:
            client.close()

    @staticmethod
    def _wait_for(condition: object, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():  # type: ignore[operator]
                return True
            time.sleep(0.02)
        return False


class MCPVersionNegotiationTest(unittest.TestCase):
    def test_supported_and_unsupported_protocol_versions(self) -> None:
        self.assertEqual(self._initialize("2025-06-18")["protocolVersion"], "2025-06-18")
        unsupported = self._initialize("2099-01-01")
        self.assertEqual(unsupported["protocolVersion"], STABLE_PROTOCOL_VERSION)
        self.assertTrue(unsupported["capabilities"]["tools"]["listChanged"])

    def test_unknown_tool_uses_invalid_params_error(self) -> None:
        response = self._exchange(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": STABLE_PROTOCOL_VERSION},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "missing.tool", "arguments": {}},
                },
            ]
        )[1]

        self.assertEqual(response["error"]["code"], -32602)

    def _initialize(self, version: str) -> dict[str, object]:
        return self._exchange(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": version},
                }
            ]
        )[0]["result"]

    def _exchange(self, messages: list[dict[str, object]]) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "--audit-db",
                    str(root / "audit.db"),
                    "wrap",
                    "--name",
                    "external-incidents",
                    "--",
                    sys.executable,
                    str(EXTERNAL_FIXTURE),
                    "exact-content",
                ],
                cwd=PROJECT_ROOT,
                env={
                    **os.environ,
                    **MCPResultSemanticsTest._environment(root),
                },
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            try:
                assert process.stdin is not None
                assert process.stdout is not None
                responses = []
                for message in messages:
                    process.stdin.write(json.dumps(message) + "\n")
                    process.stdin.flush()
                    responses.append(json.loads(process.stdout.readline()))
                return responses
            finally:
                process.terminate()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
