from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
import uuid
from pathlib import Path

from judikt.audit import AuditStore
from judikt.kill_switch import (
    CachedKillSwitchStore,
    DynamoDBKillSwitchStore,
    KillSwitchStoreError,
    KillSwitchUnavailable,
    RedisKillSwitchStore,
    SQLiteKillSwitchStore,
    _validate_change,
    build_kill_switch_store,
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


class _FakeDynamoDBTable:
    """Just enough of the boto3 Table API for DynamoDBKillSwitchStore."""

    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []
        self.version = 0
        self.query_error: Exception | None = None
        self.update_error: Exception | None = None

    def query(self, **kwargs: object) -> dict[str, object]:
        if self.query_error is not None:
            raise self.query_error
        return {"Items": list(self.items)}

    def update_item(self, **kwargs: object) -> dict[str, object]:
        if self.update_error is not None:
            raise self.update_error
        self.version += 1
        self.items = [item for item in self.items if item.get("sk") != "VERSION"]
        self.items.append({"pk": "KILL_SWITCH", "sk": "VERSION", "version": self.version})
        return {"Attributes": {"version": self.version}}

    def put_item(self, Item: dict[str, object]) -> None:
        self.items.append(Item)


class DynamoDBKillSwitchStoreTest(unittest.TestCase):
    def test_unavailable_table_raises_on_get_and_set(self) -> None:
        store = DynamoDBKillSwitchStore(None)

        with self.assertRaises(KillSwitchStoreError):
            store.get_state()
        with self.assertRaises(KillSwitchStoreError):
            store.set("tool", "company.restart", False, "operator", "test")
        store.close()

    def test_query_failure_is_wrapped(self) -> None:
        table = _FakeDynamoDBTable()
        table.query_error = RuntimeError("table not found")
        store = DynamoDBKillSwitchStore(table)

        with self.assertRaisesRegex(KillSwitchStoreError, "unavailable"):
            store.get_state()

    def test_update_failure_is_wrapped(self) -> None:
        table = _FakeDynamoDBTable()
        table.update_error = RuntimeError("throughput exceeded")
        store = DynamoDBKillSwitchStore(table)

        with self.assertRaisesRegex(KillSwitchStoreError, "update failed"):
            store.set("tool", "company.restart", False, "operator", "test")

    def test_set_then_get_reflects_disabled_tools_and_servers_only(self) -> None:
        table = _FakeDynamoDBTable()
        store = DynamoDBKillSwitchStore(table)

        first_version = store.set(
            "tool", "company.restart", False, "operator", "incident"
        )
        second_version = store.set(
            "server", "payments-api", False, "operator", "incident"
        )
        # A tool explicitly re-enabled should not show up as disabled.
        third_version = store.set("tool", "company.read", True, "operator", "resolved")

        state = store.get_state()

        self.assertEqual(second_version, first_version + 1)
        self.assertEqual(third_version, second_version + 1)
        self.assertEqual(state["tools"], {"company.restart"})
        self.assertEqual(state["servers"], {"payments-api"})
        self.assertEqual(state["version"], third_version)


class ValidateChangeTest(unittest.TestCase):
    def test_accepts_a_well_formed_change(self) -> None:
        _validate_change("tool", "company.restart", False, "operator", "incident")

    def test_rejects_an_unknown_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "scope must be"):
            _validate_change("project", "company.restart", False, "operator", "incident")

    def test_rejects_a_blank_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "name must be"):
            _validate_change("tool", "  ", False, "operator", "incident")

    def test_rejects_a_non_boolean_enabled_flag(self) -> None:
        with self.assertRaisesRegex(ValueError, "enabled must be"):
            _validate_change("tool", "company.restart", "false", "operator", "incident")  # type: ignore[arg-type]

    def test_rejects_a_blank_actor(self) -> None:
        with self.assertRaisesRegex(ValueError, "actor must be"):
            _validate_change("tool", "company.restart", False, "", "incident")

    def test_rejects_a_blank_reason(self) -> None:
        with self.assertRaisesRegex(ValueError, "reason must be"):
            _validate_change("tool", "company.restart", False, "operator", "")


class BuildKillSwitchStoreTest(unittest.TestCase):
    def test_rejects_a_non_object_kill_switches_config(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be an object"):
            build_kill_switch_store({"kill_switches": ["not", "an", "object"]})

    def test_rejects_an_unknown_backend(self) -> None:
        with self.assertRaisesRegex(ValueError, "'sqlite' or 'redis'"):
            build_kill_switch_store({"kill_switches": {"backend": "dynamo"}})

    def test_defaults_to_sqlite_with_last_known_on_failure(self) -> None:
        store = build_kill_switch_store({"kill_switches": {}})
        try:
            self.assertIsInstance(store.store, SQLiteKillSwitchStore)
            self.assertEqual(store.on_store_failure, "last_known")
        finally:
            store.close()

    def test_production_defaults_to_deny_on_failure(self) -> None:
        store = build_kill_switch_store({"kill_switches": {}}, production=True)
        try:
            self.assertEqual(store.on_store_failure, "deny")
        finally:
            store.close()

    def test_redis_backend_dispatches_to_the_redis_store(self) -> None:
        # Without JUDIKT_REDIS_URL configured, RedisKillSwitchStore itself
        # raises -- this confirms build_kill_switch_store dispatches "redis"
        # to that class rather than reaching a live server.
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("JUDIKT_REDIS_URL", None)
            with self.assertRaisesRegex(ValueError, "requires a Redis URL"):
                build_kill_switch_store(
                    {"kill_switches": {"backend": "redis", "cache_ttl_seconds": 1}}
                )


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
