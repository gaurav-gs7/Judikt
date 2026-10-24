from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from judikt.approval import ApprovalAuthority
from judikt.catalog import gateway_result
from judikt.metrics import Metrics
from judikt.protocol import (
    StdioMCPClient,
    UpstreamExitedError,
    UpstreamRestartLimitError,
    UpstreamTimeoutError,
)
from judikt.runtime import JudiktRuntime
from judikt.upstream_registry import UpstreamCatalogCache
from judikt.upstreams import UpstreamConfigError, UpstreamServer, load_upstream_servers


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "resilient_mcp_server.py"
APPROVAL_SECRET = "upstream-recovery-approval-secret-32-bytes"
TOOLS = ["resilient.echo", "resilient.hang", "resilient.notify"]


def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class UpstreamRecoveryTest(unittest.TestCase):
    def _runtime(
        self,
        root: Path,
        mode: str,
        *,
        call_timeout: float = 0.4,
        list_timeout: float = 1.0,
        liveness: float = 0.4,
        catalog_ttl: float | None = None,
    ) -> tuple[JudiktRuntime, Path]:
        policy = json.loads(
            (PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json").read_text()
        )
        policy["allowed_tools"] = {"resilient": TOOLS}
        policy["actor_permissions"]["anonymous"] = TOOLS
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy))
        list_log = root / "lists.log"
        runtime = JudiktRuntime(
            policy_path,
            root / "audit.db",
            upstream_servers=[
                UpstreamServer(
                    name="resilient",
                    command=(sys.executable, str(FIXTURE), mode),
                    environment={
                        "FIXTURE_STATE_PATH": str(root / "starts"),
                        "FIXTURE_LIST_LOG": str(list_log),
                    },
                    timeouts={"initialize": 2.0, "list": list_timeout, "call": call_timeout},
                    liveness_timeout_seconds=liveness,
                    catalog_ttl_seconds=catalog_ttl,
                )
            ],
            approval_authority=ApprovalAuthority(APPROVAL_SECRET),
        )
        runtime.clients["resilient"]._restart_backoff_seconds = 0.01
        self.addCleanup(runtime.close)
        return runtime, list_log

    @staticmethod
    def _lists(list_log: Path) -> list[str]:
        return list_log.read_text().splitlines() if list_log.exists() else []

    def test_hung_upstream_that_ignores_ping_is_killed_and_restarted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, list_log = self._runtime(Path(directory), "probe-dead")
            client = runtime.clients["resilient"]
            metrics = Metrics()
            client._metrics = metrics
            original = client._process
            assert original is not None

            first = runtime.call_tool("resilient", "resilient.hang", {"value": "x"})
            self.assertEqual(first.rule, "upstream_timeout")
            self.assertTrue(gateway_result(first)["isError"])

            # Liveness timeout (0.4s) plus the 2s SIGTERM grace period.
            self.assertTrue(_wait_for(lambda: original.poll() is not None, 0.4 + 2.0))

            second = runtime.call_tool("resilient", "resilient.echo", {"value": "after"})
            lists = self._lists(list_log)

        self.assertTrue(second.allowed, second.reason)
        self.assertNotEqual(second.result["pid"], original.pid)
        self.assertEqual(second.result["start_count"], 2)
        # The restart hook re-listed and re-verified pins on the new process.
        self.assertIn("2", lists)
        rendered = metrics.render()
        self.assertIn('judikt_upstream_liveness_failures_total{server="resilient"} 1', rendered)
        self.assertIn('judikt_upstream_restarts_total{server="resilient"} 1', rendered)

    def test_slow_upstream_that_answers_ping_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._runtime(Path(directory), "probe-alive")
            client = runtime.clients["resilient"]
            original = client._process
            assert original is not None

            slow = runtime.call_tool("resilient", "resilient.hang", {"value": "x"})
            time.sleep(0.4 + 1.0)
            alive = original.poll() is None
            echo = runtime.call_tool("resilient", "resilient.echo", {"value": "ok"})

        self.assertEqual(slow.rule, "upstream_timeout")
        self.assertTrue(alive)
        self.assertTrue(echo.allowed, echo.reason)
        self.assertEqual(echo.result["pid"], original.pid)
        self.assertEqual(client.restart_count, 0)

    def test_hung_catalog_refresh_is_an_audited_denial_and_opens_the_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._runtime(
                Path(directory),
                "list-hang-after-first",
                list_timeout=0.3,
                catalog_ttl=0,
            )

            outcomes = [
                runtime.call_tool("resilient", "resilient.echo", {"value": str(index)})
                for index in range(4)
            ]
            audit = runtime.audit.recent(10)

        for outcome in outcomes[:3]:
            self.assertFalse(outcome.allowed)
            self.assertEqual(outcome.rule, "upstream_timeout")
            rendered = gateway_result(outcome)
            self.assertTrue(rendered["isError"])
            self.assertEqual(rendered["_meta"]["io.judikt/decision"]["rule"], "upstream_timeout")
            self.assertIn("timed out during 'tools/list'", rendered["content"][0]["text"])
        self.assertEqual(outcomes[3].rule, "circuit_breaker")
        rules = [event["rule"] for event in audit]
        self.assertEqual(rules.count("upstream_timeout"), 3)
        self.assertIn("circuit_breaker", rules)
        self.assertTrue(all(event["diagnostic"] for event in audit if event["rule"] == "upstream_timeout"))

    def test_catalog_ttl_limits_tools_list_calls(self) -> None:
        for ttl, expected in ((30, 1), (0, 11)):
            with self.subTest(ttl=ttl), tempfile.TemporaryDirectory() as directory:
                runtime, list_log = self._runtime(
                    Path(directory), "probe-alive", catalog_ttl=ttl
                )
                results = [
                    runtime.call_tool("resilient", "resilient.echo", {"value": str(index)})
                    for index in range(10)
                ]
                lists = self._lists(list_log)

                self.assertTrue(all(result.allowed for result in results))
                # One startup listing plus, with TTL 0, one per call.
                self.assertEqual(len(lists), expected)

    def test_list_changed_notification_triggers_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, list_log = self._runtime(
                Path(directory), "notify-on-call", catalog_ttl=30
            )
            runtime.call_tool("resilient", "resilient.echo", {"value": "a"})
            self.assertEqual(len(self._lists(list_log)), 1)

            runtime.call_tool("resilient", "resilient.notify", {"value": "b"})
            entry_marked = _wait_for(
                lambda: runtime.upstreams.catalog._entries["resilient"].stale, 2.0
            )
            runtime.call_tool("resilient", "resilient.echo", {"value": "c"})
            lists = self._lists(list_log)

        self.assertTrue(entry_marked)
        self.assertEqual(len(lists), 2)

    def test_stale_catalog_serves_pinned_allowed_tools_until_twice_the_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._runtime(
                Path(directory), "list-error-after-first", catalog_ttl=0.5
            )
            fresh = runtime.call_tool("resilient", "resilient.echo", {"value": "a"})
            time.sleep(0.6)
            stale = runtime.call_tool("resilient", "resilient.echo", {"value": "b"})
            time.sleep(0.5)
            expired = runtime.call_tool("resilient", "resilient.echo", {"value": "c"})

        self.assertTrue(fresh.allowed, fresh.reason)
        self.assertTrue(stale.allowed, stale.reason)
        self.assertFalse(expired.allowed)
        self.assertEqual(expired.rule, "upstream_error")
        self.assertIn("returned an error", expired.reason)

    def test_catalog_refresh_that_restarts_the_upstream_does_not_deadlock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = json.loads(
                (PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json").read_text()
            )
            policy["allowed_tools"] = {"resilient": ["resilient.echo"]}
            policy["actor_permissions"]["anonymous"] = ["resilient.echo"]
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy))
            runtime = JudiktRuntime(
                policy_path,
                root / "audit.db",
                upstream_servers=[
                    UpstreamServer(
                        name="resilient",
                        command=(sys.executable, str(FIXTURE), "crash-once"),
                        environment={"FIXTURE_STATE_PATH": str(root / "starts")},
                        timeouts={"initialize": 2.0, "list": 2.0, "call": 2.0},
                        catalog_ttl_seconds=0,
                    )
                ],
                approval_authority=ApprovalAuthority(APPROVAL_SECRET),
            )
            runtime.clients["resilient"]._restart_backoff_seconds = 0.01
            self.addCleanup(runtime.close)
            crashed = runtime.call_tool("resilient", "resilient.echo", {"value": "a"})
            outcome: list[Any] = []
            # The next catalog refresh restarts the process, and the restart
            # hook re-lists the same upstream on the same thread.
            worker = threading.Thread(
                target=lambda: outcome.append(
                    runtime.call_tool("resilient", "resilient.echo", {"value": "b"})
                ),
                daemon=True,
            )
            worker.start()
            worker.join(timeout=10)

        self.assertEqual(crashed.rule, "upstream_error")
        self.assertFalse(worker.is_alive(), "catalog refresh deadlocked on restart")
        self.assertTrue(outcome[0].allowed, outcome[0].reason)

    def test_restart_budget_still_applies_when_probes_keep_killing(self) -> None:
        client = StdioMCPClient(
            "resilient-budget",
            command=[sys.executable, str(FIXTURE), "probe-dead"],
            inherit_environment=False,
            timeouts={"initialize": 2.0, "list": 1.0, "call": 0.3},
            restart_limit=2,
            restart_window_seconds=60,
            restart_backoff_seconds=0.01,
            liveness_timeout_seconds=0.3,
        )
        self.addCleanup(client.close)

        def hang_and_wait_for_kill() -> None:
            with self.assertRaises(UpstreamTimeoutError):
                client.call_tool("resilient.hang", {})
            # The process that served (and hung on) this call.
            process = client._process
            assert process is not None
            self.assertTrue(_wait_for(lambda: process.poll() is not None, 3.0))

        hang_and_wait_for_kill()
        for _ in range(2):
            hang_and_wait_for_kill()
        with self.assertRaises(UpstreamRestartLimitError):
            client.call_tool("resilient.echo", {})
        self.assertEqual(client.restart_count, 2)

    def test_probe_failure_fails_pending_requests_of_the_hung_process(self) -> None:
        client = StdioMCPClient(
            "resilient-pending",
            command=[sys.executable, str(FIXTURE), "probe-dead"],
            inherit_environment=False,
            timeouts={"initialize": 2.0, "list": 5.0, "call": 0.3},
            restart_backoff_seconds=0.01,
            liveness_timeout_seconds=0.3,
        )
        self.addCleanup(client.close)
        with self.assertRaises(UpstreamTimeoutError):
            client.call_tool("resilient.hang", {})
        started = time.monotonic()
        # A list request queued behind the hung call is failed by the kill
        # instead of waiting for its own 5s deadline.
        with self.assertRaises((UpstreamExitedError, UpstreamTimeoutError)):
            client.request("tools/list", {})
        self.assertLess(time.monotonic() - started, 4.0)


class CatalogCacheUnitTest(unittest.TestCase):
    def test_stale_window_and_invalidation(self) -> None:
        now = [0.0]

        class Client:
            def __init__(self) -> None:
                self.calls = 0
                self.fail = False

            def list_tools(self) -> list[dict[str, Any]]:
                self.calls += 1
                if self.fail:
                    raise UpstreamTimeoutError("timed out")
                return [{"name": f"tool-{self.calls}"}]

        client = Client()
        cache = UpstreamCatalogCache({"s": client}, {}, {"s": 10}, clock=lambda: now[0])
        self.assertEqual(cache.get("s"), [{"name": "tool-1"}])
        now[0] = 5
        self.assertEqual(cache.get("s"), [{"name": "tool-1"}])
        self.assertEqual(client.calls, 1)
        cache.invalidate("s")
        self.assertEqual(cache.get("s"), [{"name": "tool-2"}])
        client.fail = True
        now[0] = 20
        self.assertEqual(cache.get("s"), [{"name": "tool-2"}])
        now[0] = 25.1
        with self.assertRaises(UpstreamTimeoutError):
            cache.get("s")

    def test_upstream_config_accepts_ttl_and_liveness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstreams.json"
            path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "a": {
                                "command": ["server"],
                                "catalog_ttl_seconds": 0,
                                "liveness_timeout_seconds": 2.5,
                            }
                        }
                    }
                )
            )
            server = load_upstream_servers(path)[0]
            self.assertEqual(server.catalog_ttl_seconds, 0.0)
            self.assertEqual(server.liveness_timeout_seconds, 2.5)
            for key, value in (
                ("catalog_ttl_seconds", -1),
                ("liveness_timeout_seconds", 0),
                ("liveness_timeout_seconds", True),
            ):
                path.write_text(json.dumps({"servers": {"a": {"command": ["s"], key: value}}}))
                with self.subTest(key=key, value=value), self.assertRaises(UpstreamConfigError):
                    load_upstream_servers(path)


if __name__ == "__main__":
    unittest.main()
