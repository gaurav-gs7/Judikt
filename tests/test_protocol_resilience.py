from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from judikt.approval import ApprovalAuthority
from judikt.metrics import Metrics
from judikt.ops_runtime import JudiktOpsRuntime
from judikt.protocol import (
    MCPProtocolError,
    StdioMCPClient,
    UpstreamExitedError,
    UpstreamRestartLimitError,
    UpstreamTimeoutError,
)
from judikt.runtime import JudiktRuntime
from judikt.upstream_registry import StdioUpstreamRegistry
from judikt.upstreams import UpstreamConfigError, UpstreamServer, load_upstream_servers


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "resilient_mcp_server.py"
APPROVAL_SECRET = "protocol-resilience-approval-secret-32-bytes"


class StdioMCPResilienceTest(unittest.TestCase):
    def _client(
        self,
        mode: str,
        *,
        environment: dict[str, str] | None = None,
        **options: object,
    ) -> StdioMCPClient:
        configured_timeouts = options.pop(
            "timeouts",
            {"initialize": 0.25, "list": 0.25, "call": 0.25},
        )
        client = StdioMCPClient(
            f"resilient-{mode}",
            command=[sys.executable, str(FIXTURE), mode],
            environment=environment,
            inherit_environment=False,
            timeouts=configured_timeouts,  # type: ignore[arg-type]
            restart_backoff_seconds=0.01,
            **options,
        )
        self.addCleanup(client.close)
        return client

    def test_initialize_timeout_and_wrap_failure_are_bounded_and_readable(self) -> None:
        started = time.monotonic()
        with self.assertRaises(UpstreamTimeoutError):
            StdioMCPClient(
                "hang-initialize",
                command=[sys.executable, str(FIXTURE), "hang-initialize"],
                inherit_environment=False,
                timeouts={"initialize": 0.1},
            )
        self.assertLess(time.monotonic() - started, 1.5)

        environment = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_UPSTREAM_TIMEOUT_SECONDS": "0.1",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "XDG_STATE_HOME": tempfile.gettempdir(),
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "wrap",
                "--",
                sys.executable,
                str(FIXTURE),
                "hang-initialize",
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("timed out", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)
        self.assertEqual(completed.stdout, "")

    def test_call_timeout_sends_cancellation_and_increments_metric(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cancel_log = Path(directory) / "cancel.json"
            metrics = Metrics()
            client = self._client(
                "hang-call",
                environment={"FIXTURE_CANCEL_LOG": str(cancel_log)},
                metrics=metrics,
            )

            with self.assertRaises(UpstreamTimeoutError):
                client.call_tool("resilient.echo", {"value": "slow"})

            self.assertTrue(_wait_for(cancel_log.exists))
            cancellation = json.loads(cancel_log.read_text())
            self.assertEqual(cancellation["method"], "notifications/cancelled")
            self.assertEqual(cancellation["params"]["reason"], "timeout")
            self.assertIsInstance(cancellation["params"]["requestId"], int)
            self.assertIn(
                'judikt_upstream_timeouts_total{server="resilient-hang-call"} 1',
                metrics.render(),
            )

    def test_large_stderr_is_drained_without_deadlock_and_is_bounded(self) -> None:
        client = self._client(
            "stderr-flood",
            stderr_buffer_bytes=65_536,
            timeouts={"initialize": 0.9, "list": 0.9, "call": 0.9},
        )

        result = client.call_tool("resilient.echo", {"value": "received"})

        self.assertEqual(result["structuredContent"]["value"], "received")
        self.assertLessEqual(len(client.stderr_tail), 20)
        self.assertTrue(all(len(line) <= 200 for line in client.stderr_tail))

    def test_exit_mid_call_fails_fast_then_restarts_and_runs_callback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "starts"
            metrics = Metrics()
            client = self._client(
                "crash-once",
                environment={"FIXTURE_STATE_PATH": str(state)},
                metrics=metrics,
            )
            callbacks: list[int] = []
            client.add_restart_handler(lambda restarted: callbacks.append(restarted.restart_count))

            started = time.monotonic()
            with self.assertRaises(UpstreamExitedError):
                client.call_tool("resilient.echo", {"value": "first"})
            self.assertLess(time.monotonic() - started, 1.0)

            result = client.call_tool("resilient.echo", {"value": "second"})

            payload = result["structuredContent"]
            self.assertEqual(payload["value"], "second")
            self.assertEqual(payload["start_count"], 2)
            self.assertEqual(callbacks, [1])
            self.assertIn(
                'judikt_upstream_restarts_total{server="resilient-crash-once"} 1',
                metrics.render(),
            )

    def test_non_json_banner_is_ignored_and_counted(self) -> None:
        metrics = Metrics()
        client = self._client("non-json-banner", metrics=metrics)

        result = client.call_tool("resilient.echo", {"value": "after-banner"})

        self.assertEqual(result["structuredContent"]["value"], "after-banner")
        self.assertEqual(client.non_json_line_count, 1)
        self.assertTrue(any("skipped non-JSON" in line for line in client.stderr_tail))
        self.assertIn(
            'judikt_upstream_protocol_violations_total{server="resilient-non-json-banner"} 1',
            metrics.render(),
        )

    def test_exit_error_contains_only_bounded_control_free_stderr(self) -> None:
        client = self._client("exit-stderr")

        with self.assertRaises(UpstreamExitedError) as raised:
            client.call_tool("resilient.echo", {"value": "failure"})

        # stderr is operator-only: it is in the diagnostic, never in str(exc).
        self.assertNotIn("recent stderr", str(raised.exception))
        rendered = raised.exception.diagnostic
        self.assertIn("recent stderr: failure", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x00", rendered)
        self.assertNotIn("x" * 201, rendered)

    def test_concurrent_calls_are_correlated_by_request_id(self) -> None:
        client = self._client("concurrent", timeouts={"call": 1.0})
        results: dict[int, str] = {}
        failures: list[BaseException] = []

        def invoke(index: int) -> None:
            try:
                result = client.call_tool(
                    "resilient.echo",
                    {"value": f"value-{index}", "delay": (9 - index) / 100},
                )
                results[index] = result["structuredContent"]["value"]
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=invoke, args=(index,)) for index in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)

        self.assertEqual(failures, [])
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(results, {index: f"value-{index}" for index in range(10)})

    def test_oversized_line_fails_request_and_next_call_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metrics = Metrics()
            client = self._client(
                "oversized-once",
                environment={"FIXTURE_STATE_PATH": str(Path(directory) / "starts")},
                max_message_bytes=1024,
                metrics=metrics,
            )

            with self.assertRaisesRegex(MCPProtocolError, "stdout message limit"):
                client.call_tool("resilient.echo", {"value": "too-large"})
            result = client.call_tool("resilient.echo", {"value": "recovered"})

            self.assertEqual(result["structuredContent"]["value"], "recovered")
            self.assertEqual(client.protocol_violation_count, 1)
            self.assertEqual(client.restart_count, 1)

    def test_notification_hook_receives_server_notification(self) -> None:
        client = self._client("notification")
        observed: list[dict[str, object]] = []
        client.add_notification_handler(
            "notifications/tools/list_changed",
            lambda message: observed.append(message),
        )

        client.list_tools()

        self.assertTrue(_wait_for(lambda: bool(observed)))
        self.assertEqual(observed[0]["method"], "notifications/tools/list_changed")

    def test_close_kills_sigterm_ignoring_child_and_joins_readers(self) -> None:
        client = self._client("ignore-term")
        reader = client._reader_thread
        stderr_reader = client._stderr_thread

        started = time.monotonic()
        client.close()

        self.assertLess(time.monotonic() - started, 5.0)
        self.assertIsNotNone(reader)
        self.assertIsNotNone(stderr_reader)
        self.assertFalse(reader.is_alive())
        self.assertFalse(stderr_reader.is_alive())

    def test_restart_budget_exhaustion_stays_failed_until_close(self) -> None:
        client = self._client(
            "restart-loop",
            restart_limit=2,
            restart_window_seconds=60,
        )

        with self.assertRaises(UpstreamExitedError):
            client.call_tool("resilient.echo", {"value": "initial"})
        for _ in range(2):
            with self.assertRaises(UpstreamExitedError):
                client.call_tool("resilient.echo", {"value": "restart"})
        with self.assertRaisesRegex(UpstreamRestartLimitError, "restart budget"):
            client.call_tool("resilient.echo", {"value": "exhausted"})
        with self.assertRaises(UpstreamRestartLimitError):
            client.list_tools()


class RuntimeRecoveryTest(unittest.TestCase):
    def _policy(self, directory: str) -> Path:
        policy = json.loads(
            (PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json").read_text()
        )
        policy["allowed_tools"] = {"resilient": ["resilient.echo"]}
        policy["actor_permissions"]["anonymous"] = ["resilient.echo"]
        path = Path(directory) / "policy.json"
        path.write_text(json.dumps(policy))
        return path

    def test_runtime_timeout_is_denied_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cancel_log = Path(directory) / "cancel.json"
            runtime = JudiktRuntime(
                self._policy(directory),
                Path(directory) / "audit.db",
                upstream_servers=[
                    UpstreamServer(
                        name="resilient",
                        command=(sys.executable, str(FIXTURE), "hang-call"),
                        environment={"FIXTURE_CANCEL_LOG": str(cancel_log)},
                        timeouts={"initialize": 0.25, "list": 0.25, "call": 0.1},
                    )
                ],
                approval_authority=ApprovalAuthority(APPROVAL_SECRET),
            )
            try:
                outcome = runtime.call_tool(
                    "resilient",
                    "resilient.echo",
                    {"value": "slow"},
                )
                audit = runtime.audit.recent()
            finally:
                runtime.close()

        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.rule, "upstream_timeout")
        self.assertEqual(audit[0]["rule"], "upstream_timeout")

    def test_ops_runtime_timeout_is_denied_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            upstream_path = Path(directory) / "upstreams.json"
            upstream_path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "resilient": {
                                "command": [sys.executable, str(FIXTURE), "hang-call"],
                                "timeouts": {"initialize": 0.25, "list": 0.25, "call": 0.1},
                            }
                        }
                    }
                )
            )
            with patch.dict(
                os.environ,
                {
                    "JUDIKT_UPSTREAM_CONFIG": str(upstream_path),
                    "JUDIKT_AUDIT_SINK": "none",
                    "JUDIKT_TELEMETRY": "disabled",
                },
            ):
                runtime = JudiktOpsRuntime(
                    self._policy(directory),
                    Path(directory) / "ops-audit.db",
                    approval_authority=ApprovalAuthority(APPROVAL_SECRET),
                )
                try:
                    outcome = runtime.call_tool(
                        "resilient",
                        "resilient.echo",
                        {"value": "slow"},
                    )
                    audit = runtime.audit.recent()
                finally:
                    runtime.close()

        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.rule, "upstream_timeout")
        self.assertEqual(audit[0]["rule"], "upstream_timeout")

    def test_runtime_reverifies_pins_after_restart_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            list_log = Path(directory) / "lists"
            runtime = JudiktRuntime(
                self._policy(directory),
                Path(directory) / "audit.db",
                upstream_servers=[
                    UpstreamServer(
                        name="resilient",
                        command=(sys.executable, str(FIXTURE), "crash-once"),
                        environment={
                            "FIXTURE_STATE_PATH": str(Path(directory) / "starts"),
                            "FIXTURE_LIST_LOG": str(list_log),
                        },
                        timeouts={"initialize": 0.25, "list": 0.25, "call": 0.25},
                    )
                ],
                approval_authority=ApprovalAuthority(APPROVAL_SECRET),
            )
            runtime.clients["resilient"]._restart_backoff_seconds = 0.01
            try:
                failed = runtime.call_tool("resilient", "resilient.echo", {"value": "first"})
                recovered = runtime.call_tool(
                    "resilient",
                    "resilient.echo",
                    {"value": "second"},
                )
                list_generations = list_log.read_text().splitlines()
            finally:
                runtime.close()

        self.assertFalse(failed.allowed)
        self.assertTrue(recovered.allowed)
        # Generation 1 is listed once at startup and then served from the
        # catalog cache; the restart hook must re-list (and re-verify pins on)
        # generation 2 before the recovered call succeeds.
        self.assertEqual(list_generations, ["1", "2"])


class UpstreamTimeoutConfigurationTest(unittest.TestCase):
    def test_loads_per_upstream_timeouts_and_rejects_invalid_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstreams.json"
            path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "resilient": {
                                "command": ["resilient-server"],
                                "timeouts": {"initialize": 1, "list": 2.5, "call": 3},
                            }
                        }
                    }
                )
            )

            server = load_upstream_servers(path)[0]

            self.assertEqual(server.timeouts, {"initialize": 1.0, "list": 2.5, "call": 3.0})

            path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "resilient": {
                                "command": ["resilient-server"],
                                "timeouts": {"call": 0},
                            }
                        }
                    }
                )
            )
            with self.assertRaisesRegex(UpstreamConfigError, "positive number"):
                load_upstream_servers(path)

    def test_tool_prefix_is_validated_and_applied_at_registry_boundary(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.called: tuple[str, dict[str, object]] | None = None

            def list_tools(self) -> list[dict[str, object]]:
                return [{"name": "search", "inputSchema": {"type": "object"}}]

            def call_tool(
                self, tool: str, arguments: dict[str, object]
            ) -> dict[str, object]:
                self.called = (tool, arguments)
                return {"tool": tool}

            def close(self) -> None:
                return None

        client = Client()
        registry = StdioUpstreamRegistry(  # type: ignore[arg-type]
            {"github": client}, {"github": "github."}
        )

        self.assertEqual(
            registry.definitions()["github"][0]["name"], "github.search"
        )
        registry.execute("github", "github.search", {"query": "judikt"})
        self.assertEqual(client.called, ("search", {"query": "judikt"}))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstreams.json"
            path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "github": {
                                "command": ["github-mcp"],
                                "tool_name_prefix": "bad prefix/",
                            }
                        }
                    }
                )
            )
            with self.assertRaisesRegex(UpstreamConfigError, "MCP tool-name rules"):
                load_upstream_servers(path)


def _wait_for(predicate: Callable[[], bool], timeout: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


if __name__ == "__main__":
    unittest.main()
