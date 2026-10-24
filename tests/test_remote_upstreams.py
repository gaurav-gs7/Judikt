from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from judikt.approval import ApprovalAuthority
from judikt.paths import DEFAULT_POLICY_PATH
from judikt.metrics import Metrics
from judikt.protocol import StdioMCPClient, UpstreamTimeoutError
from judikt.remote_protocol import StreamableHTTPMCPClient, _http_timeout
from judikt.runtime import JudiktRuntime
from judikt.upstreams import (
    UpstreamConfigError,
    UpstreamServer,
    load_upstream_servers,
    validate_remote_url,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "streamable_http_mcp_server.py"
APPROVAL_SECRET = "remote-upstream-test-approval-secret-at-least-32-bytes"


class RemoteUpstreamEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp_dir.name)
        cls.header_log = cls.root / "headers.jsonl"
        cls.call_log = cls.root / "calls.jsonl"
        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}/mcp"
        cls.process = subprocess.Popen(
            [
                sys.executable,
                str(FIXTURE),
                str(cls.port),
                str(cls.header_log),
                str(cls.call_log),
            ],
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_for_port(cls.process, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.process.poll() is None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
        for stream in (cls.process.stdout, cls.process.stderr):
            if stream is not None:
                stream.close()
        cls.temp_dir.cleanup()

    def setUp(self) -> None:
        self.header_log.write_text("")
        self.call_log.write_text("")

    def test_official_remote_client_lists_calls_and_uses_only_brokered_headers(self) -> None:
        changed = threading.Event()
        client = StreamableHTTPMCPClient(
            "remote",
            url=self.url,
            headers={"Authorization": "Bearer brokered-upstream-token"},
            allow_private_network=True,
        )
        try:
            client.add_notification_handler(
                "notifications/tools/list_changed",
                lambda _message: changed.set(),
            )
            tools = client.list_tools()
            result = client.call_tool("remote.lookup_user", {"user": "octocat"})
            notified = client.call_tool("remote.notify_catalog", {})
            self.assertTrue(changed.wait(2))
        finally:
            client.close()

        definitions = {tool["name"]: tool for tool in tools}
        self.assertIn("remote.lookup_user", definitions)
        self.assertEqual(
            definitions["remote.lookup_user"]["inputSchema"]["properties"]["user"]["type"],
            "string",
        )
        self.assertTrue(
            definitions["remote.lookup_user"]["annotations"]["readOnlyHint"]
        )
        self.assertFalse(result["isError"])
        self.assertFalse(notified["isError"])
        self.assertEqual(result["structuredContent"]["user"], "octocat")
        observed = [json.loads(line) for line in self.header_log.read_text().splitlines()]
        self.assertTrue(observed)
        self.assertEqual(
            {headers.get("authorization") for headers in observed},
            {"Bearer brokered-upstream-token"},
        )

    def test_wrap_url_applies_pins_and_quarantines_injected_response(self) -> None:
        pin_path = self.root / "wrap-pins.json"
        audit_path = self.root / "wrap-audit.db"
        client = StdioMCPClient(
            "wrapped-remote",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(audit_path),
                "wrap",
                "--url",
                self.url,
                "--allow-private-network",
                "--name",
                "remote",
            ],
            environment={
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "JUDIKT_APPROVAL_SECRET": APPROVAL_SECRET,
                "JUDIKT_AUDIT_HMAC_SECRET": "remote-wrap-audit-secret-at-least-32-bytes",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_TOOL_PIN_PATH": str(pin_path),
                "JUDIKT_UPSTREAM_CONFIG": "",
            },
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )
        try:
            tools = client.list_tools()
            safe = client.call_tool("remote.lookup_user", {"user": "octocat"})
            poisoned = client.call_tool("remote.fetch_note", {"note": "poisoned"})
        finally:
            client.close()

        self.assertEqual(
            {tool["name"] for tool in tools},
            {
                "remote.fetch_note",
                "remote.lookup_user",
                "remote.notify_catalog",
                "remote.slow_read",
            },
        )
        self.assertFalse(safe["isError"])
        self.assertEqual(safe["structuredContent"]["user"], "octocat")
        self.assertTrue(poisoned["isError"])
        self.assertEqual(
            poisoned["_meta"]["io.judikt/decision"]["rule"],
            "inbound_prompt_injection",
        )
        self.assertTrue(pin_path.is_file())
        pins = json.loads(pin_path.read_text())
        self.assertEqual(
            set(pins["remote"]["tools"]),
            {
                "remote.fetch_note",
                "remote.lookup_user",
                "remote.notify_catalog",
                "remote.slow_read",
            },
        )

    def test_remote_timeout_becomes_pipeline_upstream_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = _remote_policy(root, actor="anonymous")
            runtime = JudiktRuntime(
                policy_path,
                root / "audit.db",
                upstream_servers=[
                    UpstreamServer(
                        name="remote",
                        url=self.url,
                        allow_private_network=True,
                        timeouts={"initialize": 2, "list": 2, "call": 0.05},
                    )
                ],
                approval_authority=ApprovalAuthority(APPROVAL_SECRET),
            )
            try:
                outcome = runtime.call_tool(
                    "remote",
                    "remote.slow_read",
                    {"delay": 0.5},
                )
            finally:
                runtime.close()

        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.rule, "upstream_timeout")

    def test_remote_liveness_probe_keeps_healthy_session(self) -> None:
        metrics = Metrics()
        client = StreamableHTTPMCPClient(
            "remote",
            url=self.url,
            allow_private_network=True,
            timeouts={"initialize": 2, "list": 2, "call": 0.1},
            liveness_timeout_seconds=1.0,
            metrics=metrics,
        )
        try:
            original = client._connection
            with self.assertRaises(UpstreamTimeoutError):
                client.call_tool("remote.slow_read", {"delay": 0.5})
            self.assertTrue(
                _wait_until(
                    lambda: 'judikt_upstream_liveness_probes_total{server="remote"} 1'
                    in metrics.render()
                )
            )
            time.sleep(0.3)
            result = client.call_tool("remote.lookup_user", {"user": "after"})
        finally:
            client.close()

        self.assertIs(client._connection, original)
        self.assertEqual(client.reconnect_count, 0)
        self.assertFalse(result["isError"])

    def test_remote_session_is_recreated_when_ping_does_not_answer(self) -> None:
        metrics = Metrics()
        restarted: list[object] = []
        client = StreamableHTTPMCPClient(
            "remote",
            url=self.url,
            allow_private_network=True,
            timeouts={"initialize": 2, "list": 2, "call": 0.1},
            liveness_timeout_seconds=0.2,
            metrics=metrics,
        )
        client.add_restart_handler(restarted.append)
        try:
            original = client._connection

            async def never_answers() -> None:
                await asyncio.sleep(3600)

            original.session.send_ping = never_answers  # type: ignore[union-attr]
            with self.assertRaises(UpstreamTimeoutError):
                client.call_tool("remote.slow_read", {"delay": 0.5})
            self.assertTrue(_wait_until(lambda: client.reconnect_count == 1, 5.0))
            result = client.call_tool("remote.lookup_user", {"user": "reconnected"})
        finally:
            client.close()

        self.assertIsNot(client._connection, original)
        self.assertEqual(restarted, [client])
        self.assertFalse(result["isError"])
        rendered = metrics.render()
        self.assertIn('judikt_upstream_liveness_failures_total{server="remote"} 1', rendered)
        self.assertIn('judikt_upstream_restarts_total{server="remote"} 1', rendered)

    def test_authenticated_http_caller_token_is_not_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outer_port = _free_port()
            policy_path = _remote_policy(root, actor="anonymous")
            upstream_path = root / "upstreams.json"
            upstream_path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "remote": {
                                "url": self.url,
                                "allow_private_network": True,
                                "headers": {
                                    "Authorization": {"from_env": "UPSTREAM_AUTHORIZATION"}
                                },
                            }
                        }
                    }
                )
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "--policy",
                    str(policy_path),
                    "--audit-db",
                    str(root / "outer-audit.db"),
                    "serve-real-mcp",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(outer_port),
                    "--log-level",
                    "warning",
                ],
                cwd=PROJECT_ROOT,
                env={
                    **os.environ,
                    "PYTHONPATH": str(PROJECT_ROOT / "src"),
                    "JUDIKT_UPSTREAM_CONFIG": str(upstream_path),
                    "UPSTREAM_AUTHORIZATION": "Bearer brokered-upstream-token",
                    "JUDIKT_HTTP_BEARER_TOKEN": "outer-caller-token",
                    "JUDIKT_APPROVAL_SECRET": APPROVAL_SECRET,
                    "JUDIKT_AUDIT_HMAC_SECRET": "remote-http-audit-secret-at-least-32-bytes",
                    "JUDIKT_AUDIT_SINK": "none",
                    "JUDIKT_TELEMETRY": "disabled",
                    "JUDIKT_TOOL_PIN_PATH": str(root / "outer-pins.json"),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _wait_for_port(process, outer_port)
                result = asyncio.run(
                    _call_outer_http(
                        f"http://127.0.0.1:{outer_port}/mcp",
                        "outer-caller-token",
                    )
                )
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

        self.assertEqual(result["user"], "octocat")
        observed = [json.loads(line) for line in self.header_log.read_text().splitlines()]
        self.assertTrue(observed)
        self.assertNotIn(
            "Bearer outer-caller-token",
            {headers.get("authorization") for headers in observed},
        )
        self.assertEqual(
            {headers.get("authorization") for headers in observed},
            {"Bearer brokered-upstream-token"},
        )


class RemoteUpstreamSecurityTest(unittest.TestCase):
    def test_transport_bounds_connect_write_and_pool_but_not_stream_reads(self) -> None:
        import httpx

        timeout = _http_timeout(
            httpx,
            {"initialize": 2.0, "list": 3.0, "call": 4.0},
        )

        self.assertEqual(timeout.connect, 2.0)
        self.assertIsNone(timeout.read)
        self.assertEqual(timeout.write, 4.0)
        self.assertEqual(timeout.pool, 2.0)

    def test_ssrf_and_transport_rules(self) -> None:
        refused = (
            "https://169.254.169.254/mcp",
            "https://10.0.0.1/mcp",
            "http://[::1]/mcp",
            "http://example.com/mcp",
        )
        for url in refused:
            with self.subTest(url=url), self.assertRaises(UpstreamConfigError):
                validate_remote_url(url, False, resolve_dns=False)
        validate_remote_url("http://[::1]/mcp", True, resolve_dns=False)

    def test_wrap_refuses_private_ipv6_literals_by_address_policy(self) -> None:
        for url, address in (
            ("https://[::1]:9/mcp", "::1"),
            ("https://[fd00::1]:9/mcp", "fd00::1"),
        ):
            with self.subTest(url=url), tempfile.TemporaryDirectory() as directory:
                completed = subprocess.run(
                    [sys.executable, "-m", "judikt.cli", "wrap", "--url", url],
                    cwd=PROJECT_ROOT,
                    env={
                        **os.environ,
                        "PYTHONPATH": str(PROJECT_ROOT / "src"),
                        "XDG_STATE_HOME": directory,
                        "JUDIKT_AUDIT_SINK": "none",
                        "JUDIKT_TELEMETRY": "disabled",
                        "JUDIKT_UPSTREAM_CONFIG": "",
                    },
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    f"remote upstream url resolves to disallowed address {address}",
                    completed.stderr,
                )
                self.assertNotIn("server name must contain only", completed.stderr)
                self.assertEqual(completed.stdout, "")

    def test_remote_server_name_derivation_handles_ipv6_literals(self) -> None:
        from judikt.policy_init import derive_remote_server_name, normalize_server_name

        cases = {
            "https://[2001:4860:4860::8888]/mcp": "2001-4860-4860-8888",
            "https://[::1]:9/mcp": "1",
            "https://mcp.example.com/mcp": "mcp.example.com",
            "https://[::]/mcp": "remote",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                name = derive_remote_server_name(url)
                self.assertEqual(name, expected)
                self.assertEqual(normalize_server_name(name), expected)

    def test_remote_config_resolves_brokered_header_and_rejects_plain_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstreams.json"
            path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "remote": {
                                "url": "https://mcp.example.test/mcp",
                                "headers": {
                                    "Authorization": {"from_env": "UPSTREAM_AUTHORIZATION"}
                                },
                            }
                        }
                    }
                )
            )
            with mock.patch.dict(
                os.environ,
                {"UPSTREAM_AUTHORIZATION": "Bearer operator-token"},
                clear=True,
            ):
                servers = load_upstream_servers(path)
            self.assertEqual(
                servers[0].headers,
                {"Authorization": "Bearer operator-token"},
            )

            document = json.loads(path.read_text())
            document["servers"]["remote"]["headers"]["Authorization"] = "Bearer inline"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(UpstreamConfigError, "must use from_env"):
                load_upstream_servers(path)

    def test_direct_remote_client_refuses_metadata_address(self) -> None:
        with self.assertRaises(UpstreamConfigError):
            StreamableHTTPMCPClient(
                "metadata",
                url="https://169.254.169.254/latest",
            )


async def _call_outer_http(url: str, token: str) -> dict[str, object]:
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    ) as http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            read_stream, write_stream, _ = streams
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                listed = await session.list_tools()
                names = {tool.name for tool in listed.tools}
                if "remote.lookup_user" not in names:
                    raise AssertionError(f"missing native remote tool: {sorted(names)}")
                response = await session.call_tool(
                    "remote.lookup_user",
                    {"user": "octocat"},
                )
                if response.isError or not isinstance(response.structuredContent, dict):
                    raise AssertionError(response)
                return response.structuredContent


def _remote_policy(root: Path, *, actor: str) -> Path:
    policy = json.loads(DEFAULT_POLICY_PATH.read_text())
    tools = [
        "remote.lookup_user",
        "remote.fetch_note",
        "remote.notify_catalog",
        "remote.slow_read",
    ]
    policy["allowed_tools"] = {"remote": tools}
    policy["actor_permissions"] = {actor: tools, "anonymous": tools if actor == "anonymous" else []}
    policy["tool_pinning"]["first_use"] = "auto"
    path = root / "policy.json"
    path.write_text(json.dumps(policy))
    return path


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_until(predicate: object, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():  # type: ignore[operator]
            return True
        time.sleep(0.02)
    return bool(predicate())  # type: ignore[operator]


def _wait_for_port(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.time() + 15
    while time.time() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=3)
            raise RuntimeError(f"MCP server exited:\n{stdout}\n{stderr}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"MCP server did not listen on port {port}")


if __name__ == "__main__":
    unittest.main()
