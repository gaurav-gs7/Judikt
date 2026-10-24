from __future__ import annotations

import io
import json
import multiprocessing
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from judikt.content_guard import ContentGuard
from judikt.paths import DEFAULT_POLICY_PATH, upstream_state
from judikt.protocol import StdioMCPClient
from judikt.tool_integrity import (
    ToolDriftError,
    ToolIntegrityStore,
    ToolPinMetadata,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUTO_POLICY = {"tool_pinning": {"first_use": "auto"}}


def _concurrent_pin_worker(pin_path: str, prefix: str) -> None:
    for index in range(50):
        server = f"{prefix}-{index}"
        store = ToolIntegrityStore(
            Path(pin_path),
            ContentGuard(),
            policy=AUTO_POLICY,
        )
        store.verify(server, [_tool(f"{server}.read", "read")])


def _tool(name: str, tier: str) -> dict[str, object]:
    annotations = {
        "readOnlyHint": tier == "read",
        "destructiveHint": tier == "destructive",
    }
    if tier == "write":
        annotations["destructiveHint"] = False
    return {
        "name": name,
        "description": f"{tier.title()} fixture tool",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": annotations,
    }


class ToolPinningHardeningTest(unittest.TestCase):
    def test_read_auto_pins_while_destructive_tool_waits_for_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin_path = root / "pins.json"
            store = ToolIntegrityStore(pin_path, ContentGuard())
            tools = [_tool("fixture.read", "read"), _tool("fixture.delete", "destructive")]

            report = store.verify("fixture", tools)

            self.assertEqual(report.status, "pending")
            self.assertEqual(report.pending_count, 1)
            self.assertEqual(store.pending_tools("fixture"), ["fixture.delete"])
            entry = store.entries()["fixture"]
            self.assertEqual(set(entry["tools"]), {"fixture.read"})
            self.assertEqual(set(entry["pending_tools"]), {"fixture.delete"})

    def test_pending_tool_is_hidden_denied_then_callable_after_cli_accept(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = self._write_server(root / "server.py")
            policy_path = self._write_policy(root / "policy.json")
            environment = self._environment(root)
            state = upstream_state(
                "pin-fixture",
                [sys.executable, str(script)],
                cwd=PROJECT_ROOT,
            )

            first = self._client(script, policy_path, environment)
            try:
                self.assertEqual(
                    [tool["name"] for tool in first.list_tools()],
                    ["fixture.read"],
                )
                denied = first.call_tool("fixture.delete", {})
                self.assertTrue(denied["isError"])
                self.assertEqual(
                    denied["_meta"]["io.judikt/decision"]["rule"],
                    "pin_pending",
                )
            finally:
                first.close()

            accepted = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "pins",
                    "accept",
                    state.state_key,
                    "--tool",
                    "fixture.delete",
                    "--yes",
                ],
                cwd=PROJECT_ROOT,
                env={**os.environ, **environment},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            second = self._client(script, policy_path, environment)
            try:
                self.assertEqual(
                    {tool["name"] for tool in second.list_tools()},
                    {"fixture.read", "fixture.delete"},
                )
                result = second.call_tool("fixture.delete", {})
                self.assertFalse(result["isError"], result)
            finally:
                second.close()

    def test_destructive_tool_added_after_first_verify_becomes_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ToolIntegrityStore(Path(directory) / "pins.json", ContentGuard())
            self.assertEqual(
                store.verify("fixture", [_tool("fixture.read", "read")]).status,
                "pinned",
            )

            report = store.verify(
                "fixture",
                [_tool("fixture.read", "read"), _tool("fixture.delete", "destructive")],
            )

            self.assertEqual(report.status, "pending")
            self.assertEqual(store.pending_tools("fixture"), ["fixture.delete"])

    def test_cross_process_updates_do_not_lose_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pin_path = Path(directory) / "pins.json"
            context = multiprocessing.get_context("spawn")
            processes = [
                context.Process(
                    target=_concurrent_pin_worker,
                    args=(str(pin_path), prefix),
                )
                for prefix in ("first", "second")
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(20)
                self.assertEqual(process.exitcode, 0)

            entries = ToolIntegrityStore(pin_path, ContentGuard()).entries()
            self.assertEqual(len(entries), 100)

    def test_world_writable_pin_file_is_refused_with_exit_three(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_key = "fixture-state"
            pin_path = root / "state" / "judikt" / "upstreams" / state_key / "audit.tool-pins.json"
            store = ToolIntegrityStore(
                pin_path,
                ContentGuard(),
                policy=AUTO_POLICY,
                metadata={"fixture": ToolPinMetadata(state_key)},
            )
            store.verify("fixture", [_tool("fixture.read", "read")])
            pin_path.chmod(0o666)

            result = subprocess.run(
                [sys.executable, "-m", "judikt.cli", "pins", "show", state_key],
                cwd=PROJECT_ROOT,
                env={
                    **os.environ,
                    "PYTHONPATH": str(PROJECT_ROOT / "src"),
                    "XDG_STATE_HOME": str(root / "state"),
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 3)
            self.assertIn("group- or world-writable", result.stderr)

    def test_digest_edit_fails_integrity_and_accept_resigns_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pin_path = Path(directory) / "pins.json"
            tools = [_tool("fixture.read", "read")]
            store = ToolIntegrityStore(pin_path, ContentGuard(), policy=AUTO_POLICY)
            store.verify("fixture", tools)
            document = json.loads(pin_path.read_text())
            document["fixture"]["tools"]["fixture.read"]["digest"] = "0" * 64
            pin_path.write_text(json.dumps(document))
            pin_path.chmod(0o600)

            with self.assertRaisesRegex(ToolDriftError, "pin file integrity check failed"):
                store.verify("fixture", tools)

            store.accept("fixture", tools, ["fixture.read"])
            self.assertEqual(store.verify("fixture", tools).status, "verified")

    def test_legacy_unsigned_entry_is_warned_and_signed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pin_path = Path(directory) / "pins.json"
            tools = [_tool("fixture.read", "read")]
            initial = ToolIntegrityStore(pin_path, ContentGuard(), policy=AUTO_POLICY)
            initial.verify("fixture", tools)
            document = json.loads(pin_path.read_text())
            document["fixture"].pop("mac")
            pin_path.write_text(json.dumps(document))
            pin_path.chmod(0o600)
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                report = ToolIntegrityStore(
                    pin_path,
                    ContentGuard(),
                    policy=AUTO_POLICY,
                ).verify("fixture", tools)

            self.assertEqual(report.status, "upgraded")
            self.assertIn("legacy unsigned tool pin", stderr.getvalue())
            self.assertIn("mac", json.loads(pin_path.read_text())["fixture"])
            self.assertEqual(stat.S_IMODE(pin_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(pin_path.parent.stat().st_mode), 0o700)

    @staticmethod
    def _write_server(path: Path) -> Path:
        tools = [_tool("fixture.read", "read"), _tool("fixture.delete", "destructive")]
        path.write_text(
            textwrap.dedent(
                f"""
                import json
                import sys

                TOOLS = {tools!r}
                for line in sys.stdin:
                    request = json.loads(line)
                    if "id" not in request:
                        continue
                    method = request.get("method")
                    if method == "initialize":
                        result = {{
                            "protocolVersion": "2025-11-25",
                            "capabilities": {{"tools": {{"listChanged": False}}}},
                            "serverInfo": {{"name": "pin-fixture", "version": "1"}},
                        }}
                    elif method == "tools/list":
                        result = {{"tools": TOOLS}}
                    elif method == "tools/call":
                        result = {{
                            "content": [{{"type": "text", "text": "executed"}}],
                            "structuredContent": {{"executed": True}},
                            "isError": False,
                        }}
                    else:
                        result = {{}}
                    print(json.dumps({{"jsonrpc": "2.0", "id": request["id"], "result": result}}), flush=True)
                """
            ).lstrip()
        )
        return path

    @staticmethod
    def _write_policy(path: Path) -> Path:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        names = ["fixture.read", "fixture.delete"]
        policy["allowed_tools"] = {"pin-fixture": names}
        policy["actor_permissions"] = {"local-operator": names, "anonymous": []}
        policy["tool_classification"] = {
            "fixture.read": {"tier": "read"},
            "fixture.delete": {"tier": "destructive"},
        }
        path.write_text(json.dumps(policy))
        return path

    @staticmethod
    def _environment(root: Path) -> dict[str, str]:
        return {
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "XDG_STATE_HOME": str(root / "state"),
            "JUDIKT_APPROVAL_SECRET": "pin-test-approval-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_HMAC_SECRET": "pin-test-audit-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_UPSTREAM_CONFIG": "",
        }

    @staticmethod
    def _client(
        script: Path,
        policy_path: Path,
        environment: dict[str, str],
    ) -> StdioMCPClient:
        return StdioMCPClient(
            "pin-fixture",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--policy",
                str(policy_path),
                "wrap",
                "--name",
                "pin-fixture",
                "--",
                sys.executable,
                str(script),
            ],
            environment=environment,
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )


if __name__ == "__main__":
    unittest.main()
