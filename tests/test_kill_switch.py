from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from judikt.audit import AuditStore
from judikt.kill_switch import (
    CachedKillSwitchStore,
    KillSwitchStoreError,
    KillSwitchUnavailable,
    RedisKillSwitchStore,
    SQLiteKillSwitchStore,
)
from judikt.metrics import Metrics


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "resilient_mcp_server.py"


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _FailingStore:
    def get_state(self) -> dict[str, object]:
        raise KillSwitchStoreError("synthetic outage")

    def set(
        self,
        scope: str,
        name: str,
        enabled: bool,
        actor: str,
        reason: str,
    ) -> int:
        raise KillSwitchStoreError("synthetic outage")

    def close(self) -> None:
        return


class KillSwitchStoreTest(unittest.TestCase):
    def test_two_instances_observe_changes_within_cache_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            clock = _Clock()
            first = CachedKillSwitchStore(
                SQLiteKillSwitchStore(path),
                ttl_seconds=1,
                clock=clock,
            )
            second = CachedKillSwitchStore(
                SQLiteKillSwitchStore(path),
                ttl_seconds=1,
                clock=clock,
            )
            try:
                self.assertEqual(second.get_state()["tools"], set())
                version = first.set(
                    "tool",
                    "company.restart",
                    False,
                    "operator-a",
                    "incident containment",
                )
                self.assertEqual(second.get_state()["tools"], set())
                clock.now = 1.01
                observed = second.get_state()
            finally:
                first.close()
                second.close()

        self.assertEqual(observed["tools"], {"company.restart"})
        self.assertEqual(observed["version"], version)

    def test_restart_preserves_state_and_versions_are_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            first = SQLiteKillSwitchStore(path)
            version_one = first.set(
                "server", "company", False, "operator-a", "contain incident"
            )
            first.close()
            restarted = SQLiteKillSwitchStore(path)
            try:
                state = restarted.get_state()
                version_two = restarted.set(
                    "server", "company", True, "operator-b", "incident resolved"
                )
            finally:
                restarted.close()

        self.assertEqual(state["servers"], {"company"})
        self.assertGreater(version_two, version_one)

    def test_failure_modes_deny_or_use_last_known_and_increment_metrics(self) -> None:
        metrics = Metrics()
        deny = CachedKillSwitchStore(
            _FailingStore(),
            ttl_seconds=0,
            on_store_failure="deny",
            metrics=metrics,
        )
        fallback = CachedKillSwitchStore(
            _FailingStore(),
            ttl_seconds=0,
            on_store_failure="last_known",
            metrics=metrics,
        )

        with self.assertRaises(KillSwitchUnavailable):
            deny.get_state()
        self.assertEqual(fallback.get_state()["tools"], set())

        rendered = metrics.render()
        self.assertIn('mode="deny"} 1', rendered)
        self.assertIn('mode="last_known"} 1', rendered)

    def test_every_change_is_audited_with_actor_reason_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = AuditStore(root / "audit.db")
            store = CachedKillSwitchStore(
                SQLiteKillSwitchStore(root / "control.db"),
                audit=audit,
            )
            try:
                version = store.set(
                    "tool",
                    "company.restart",
                    False,
                    "oncall@example.com",
                    "active incident",
                )
                event = audit.recent()[0]
            finally:
                store.close()
                audit.close()

        self.assertEqual(event["rule"], "kill_switch_change")
        self.assertEqual(event["arguments"]["actor"], "oncall@example.com")
        self.assertEqual(event["reason"], "active incident")
        self.assertEqual(event["result"]["version"], version)

    @unittest.skipUnless(
        os.getenv("JUDIKT_TEST_REDIS_URL"),
        "JUDIKT_TEST_REDIS_URL is not set; skipping live Redis kill-switch test",
    )
    def test_redis_store_shares_state_and_version(self) -> None:
        prefix = f"judikt:test:kill:{uuid.uuid4()}"
        first = RedisKillSwitchStore(
            os.environ["JUDIKT_TEST_REDIS_URL"],
            prefix=prefix,
        )
        second = RedisKillSwitchStore(
            os.environ["JUDIKT_TEST_REDIS_URL"],
            prefix=prefix,
        )
        try:
            version = first.set(
                "tool", "company.restart", False, "operator", "test"
            )
            state = second.get_state()
        finally:
            first.close()
            second.close()

        self.assertEqual(state["tools"], {"company.restart"})
        self.assertEqual(state["version"], version)


class KillSwitchWrapIntegrationTest(unittest.TestCase):
    def test_cli_kill_blocks_a_running_wrap_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control_path = root / "control.db"
            policy_path = root / "policy.json"
            policy = json.loads(
                (PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json").read_text()
            )
            policy["local_stdio_identity"] = "local-operator"
            policy["allowed_tools"] = {"resilient": ["resilient.echo"]}
            policy["actor_permissions"]["local-operator"] = ["resilient.echo"]
            policy["kill_switches"]["cache_ttl_seconds"] = 0.1
            policy_path.write_text(json.dumps(policy))
            environment = {
                **os.environ,
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "JUDIKT_CONTROL_DB": str(control_path),
                "JUDIKT_AUDIT_HMAC_SECRET": "kill-switch-test-audit-secret-at-least-32-bytes",
            }
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "--policy",
                    str(policy_path),
                    "--audit-db",
                    str(root / "wrap-audit.db"),
                    "wrap",
                    "--name",
                    "resilient",
                    "--",
                    sys.executable,
                    str(FIXTURE),
                    "stable",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=environment,
                cwd=PROJECT_ROOT,
            )
            try:
                self._request(
                    process,
                    "initialize",
                    {"protocolVersion": "2025-11-25", "capabilities": {}},
                )
                allowed = self._request(
                    process,
                    "tools/call",
                    {"name": "resilient.echo", "arguments": {"value": "before"}},
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "judikt.cli",
                        "--policy",
                        str(policy_path),
                        "--audit-db",
                        str(root / "cli-audit.db"),
                        "kill",
                        "tool",
                        "resilient.echo",
                        "--reason",
                        "integration test",
                    ],
                    env=environment,
                    cwd=PROJECT_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                time.sleep(0.15)
                blocked = self._request(
                    process,
                    "tools/call",
                    {"name": "resilient.echo", "arguments": {"value": "after"}},
                )
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

        self.assertFalse(allowed["isError"])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(blocked["isError"])
        self.assertEqual(
            blocked["_meta"]["io.judikt/decision"]["rule"],
            "kill_switch",
        )

    @staticmethod
    def _request(
        process: subprocess.Popen[str],
        method: str,
        params: dict[str, object],
    ) -> dict[str, object]:
        assert process.stdin is not None
        assert process.stdout is not None
        request_id = str(uuid.uuid4())
        process.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }
            )
            + "\n"
        )
        process.stdin.flush()
        response = json.loads(process.stdout.readline())
        if "error" in response:
            raise AssertionError(response["error"])
        return response["result"]


if __name__ == "__main__":
    unittest.main()
