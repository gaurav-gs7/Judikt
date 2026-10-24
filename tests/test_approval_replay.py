from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from judikt.approval import ApprovalAuthority, ApprovalTokenError
from judikt.approval_replay import (
    ApprovalReplayConfigurationError,
    ApprovalReplayUnavailable,
    DynamoDBApprovalReplayStore,
    RedisApprovalReplayStore,
    SQLiteApprovalReplayStore,
    approval_jti_digest,
    build_approval_replay_store,
)
from judikt.ops_runtime import JudiktOpsRuntime


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "config" / "policies.yaml"
SECRET = "approval-replay-test-secret-at-least-32-bytes"
ROLLBACK_PLAN = "verify health checks and restore the previous release if errors increase"


def _arguments() -> dict[str, str]:
    return {
        "service": "payments-api",
        "version": "payments-api@2026.05.2",
        "actor": "demo-operator",
        "rollback_plan": ROLLBACK_PLAN,
    }


class ApprovalReplayStoreTest(unittest.TestCase):
    def test_twenty_threads_consume_sqlite_jti_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "replay.db"
            stores = [SQLiteApprovalReplayStore(path) for _ in range(20)]
            barrier = threading.Barrier(len(stores))
            outcomes: list[bool] = []
            lock = threading.Lock()

            def consume(store: SQLiteApprovalReplayStore) -> None:
                barrier.wait()
                outcome = store.consume("shared-jti", int(time.time()) + 300)
                with lock:
                    outcomes.append(outcome)

            threads = [threading.Thread(target=consume, args=(store,)) for store in stores]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            for store in stores:
                store.close()

            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(outcomes.count(True), 1)
            self.assertEqual(outcomes.count(False), 19)

    @unittest.skipUnless(
        os.getenv("JUDIKT_TEST_REDIS_URL"),
        "JUDIKT_TEST_REDIS_URL is not set; skipping live Redis approval replay race",
    )
    def test_twenty_threads_consume_redis_jti_exactly_once(self) -> None:
        stores = [RedisApprovalReplayStore(os.environ["JUDIKT_TEST_REDIS_URL"]) for _ in range(20)]
        jti = f"redis-race-{time.time_ns()}"
        barrier = threading.Barrier(len(stores))
        outcomes: list[bool] = []
        lock = threading.Lock()

        def consume(store: RedisApprovalReplayStore) -> None:
            barrier.wait()
            outcome = store.consume(jti, int(time.time()) + 300)
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=consume, args=(store,)) for store in stores]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        for store in stores:
            store.close()

        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 19)

    def test_expired_rows_are_purged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "replay.db"
            store = SQLiteApprovalReplayStore(path)
            self.assertTrue(store.consume("expired", int(time.time()) - 1))
            self.assertTrue(store.consume("current", int(time.time()) + 300))
            store.close()

            connection = sqlite3.connect(path)
            try:
                rows = connection.execute(
                    "SELECT jti FROM consumed_approvals ORDER BY jti"
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual(rows, [(approval_jti_digest("current"),)])

    def test_unreachable_redis_fails_remote_startup_and_falls_back_locally(self) -> None:
        unreachable = {"JUDIKT_REDIS_URL": "redis://127.0.0.1:1/0", "JUDIKT_SINGLE_INSTANCE": ""}
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, unreachable, clear=False
        ):
            with self.assertRaisesRegex(
                ApprovalReplayConfigurationError, "Redis approval replay backend is unavailable"
            ):
                build_approval_replay_store(Path(directory) / "replay.db", remote_mode=True)
            with mock.patch("sys.stderr") as stderr:
                store = build_approval_replay_store(Path(directory) / "replay.db")
            try:
                self.assertIsInstance(store, SQLiteApprovalReplayStore)
                self.assertTrue(store.consume("local-jti", int(time.time()) + 60))
                self.assertFalse(store.consume("local-jti", int(time.time()) + 60))
            finally:
                store.close()
            warning = "".join(str(call.args[0]) for call in stderr.write.call_args_list)
            self.assertIn("using the local SQLite replay store", warning)

    def test_redis_error_during_consume_is_reported_as_unavailable(self) -> None:
        store = RedisApprovalReplayStore.__new__(RedisApprovalReplayStore)
        import redis

        store._redis_error = redis.RedisError
        store._client = mock.Mock()
        store._client.set.side_effect = redis.ConnectionError("down")
        with self.assertRaises(ApprovalReplayUnavailable):
            store.consume("jti", int(time.time()) + 60)

    def test_remote_sqlite_requires_single_instance_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {"JUDIKT_REDIS_URL": "", "JUDIKT_SINGLE_INSTANCE": ""},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires Redis approval replay protection"):
                build_approval_replay_store(Path(directory) / "replay.db", remote_mode=True)

    def test_remote_runtime_without_redis_or_single_instance_fails_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "JUDIKT_APPROVAL_SECRET": SECRET,
                "JUDIKT_REDIS_URL": "",
                "JUDIKT_SINGLE_INSTANCE": "",
                "JUDIKT_UPSTREAM_CONFIG": "",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires Redis approval replay protection"):
                JudiktOpsRuntime(POLICY, Path(directory) / "audit.db", remote_mode=True)

    def test_dynamodb_store_uses_conditional_put_and_ttl(self) -> None:
        table = mock.Mock()
        store = DynamoDBApprovalReplayStore(table)

        self.assertTrue(store.consume("one-time", 123456))

        table.put_item.assert_called_once_with(
            Item={
                "pk": "APPROVAL_REPLAY",
                "sk": approval_jti_digest("one-time"),
                "expires_at": 123456,
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )


class ApprovalReplayRuntimeTest(unittest.TestCase):
    def _runtime(self, directory: Path, name: str = "audit") -> JudiktOpsRuntime:
        return JudiktOpsRuntime(
            POLICY,
            directory / f"{name}.db",
            include_demo_servers=True,
            approval_authority=ApprovalAuthority(SECRET),
        )

    def test_same_token_executes_once_and_audits_hashed_jti(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            arguments = _arguments()
            token = runtime.policy.issue_approval(
                actor="demo-operator",
                reason="one attempt",
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )
            claims = runtime.policy.approvals.verify(
                token=token,
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )
            with mock.patch.object(runtime.platform, "call", wraps=runtime.platform.call) as call:
                first = runtime.call_tool(
                    "platform-ops",
                    "platform.rollback_deployment",
                    {**arguments, "approval_token": token},
                )
                second = runtime.call_tool(
                    "platform-ops",
                    "platform.rollback_deployment",
                    {**arguments, "approval_token": token},
                )
            events = runtime.recent_audit()
            runtime.close()

            digest_evidence = f"approval_jti_sha256:{approval_jti_digest(claims.jti)}"
            self.assertTrue(first.allowed)
            self.assertFalse(second.allowed)
            self.assertEqual(second.rule, "approval_replay")
            self.assertEqual(second.reason, "approval token has already been used")
            self.assertEqual(call.call_count, 1)
            self.assertIn(digest_evidence, first.evidence)
            self.assertIn(digest_evidence, events[0]["evidence"])
            self.assertNotIn(token, json.dumps(events))

    def test_two_runtime_instances_sharing_store_execute_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self._runtime(root, "first")
            second = self._runtime(root, "second")
            first.approval_replays.close()
            second.approval_replays.close()
            shared_path = root / "shared-replay.db"
            first.approval_replays = SQLiteApprovalReplayStore(shared_path)
            second.approval_replays = SQLiteApprovalReplayStore(shared_path)
            arguments = _arguments()
            token = first.policy.issue_approval(
                actor="demo-operator",
                reason="shared store",
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )

            one = first.call_tool(
                "platform-ops",
                "platform.rollback_deployment",
                {**arguments, "approval_token": token},
            )
            two = second.call_tool(
                "platform-ops",
                "platform.rollback_deployment",
                {**arguments, "approval_token": token},
            )
            first.close()
            second.close()

            self.assertEqual([one.allowed, two.allowed].count(True), 1)
            self.assertEqual([one.rule, two.rule].count("approval_replay"), 1)

    def test_dry_run_does_not_consume_token_before_real_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            arguments = _arguments()
            token = runtime.policy.issue_approval(
                actor="demo-operator",
                reason="dry run then execute",
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )

            dry_run = runtime.call_tool(
                "platform-ops",
                "platform.rollback_deployment",
                {**arguments, "approval_token": token, "dry_run": True},
            )
            executed = runtime.call_tool(
                "platform-ops",
                "platform.rollback_deployment",
                {**arguments, "approval_token": token},
            )
            runtime.close()

            self.assertTrue(dry_run.allowed)
            self.assertEqual(dry_run.action, "DRY_RUN_ONLY")
            self.assertTrue(executed.allowed)

    def test_unavailable_replay_store_fails_closed_without_tripping_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            arguments = _arguments()
            token = runtime.policy.issue_approval(
                actor="demo-operator",
                reason="replay store outage",
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )
            with mock.patch.object(
                runtime.approval_replays,
                "consume",
                side_effect=ApprovalReplayUnavailable("down"),
            ), mock.patch.object(runtime.platform, "call") as upstream:
                result = runtime.call_tool(
                    "platform-ops",
                    "platform.rollback_deployment",
                    {**arguments, "approval_token": token},
                )
                upstream.assert_not_called()
            circuits = runtime.pipeline.circuits.snapshot()
            runtime.close()

            self.assertFalse(result.allowed)
            self.assertEqual(result.rule, "approval_replay_unavailable")
            self.assertNotIn("platform-ops/platform.rollback_deployment", json.dumps(circuits))

    def test_failed_upstream_attempt_still_consumes_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            arguments = _arguments()
            token = runtime.policy.issue_approval(
                actor="demo-operator",
                reason="one failed attempt",
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )
            with mock.patch.object(runtime.platform, "call", side_effect=RuntimeError("failed")):
                failed = runtime.call_tool(
                    "platform-ops",
                    "platform.rollback_deployment",
                    {**arguments, "approval_token": token},
                )
            replay = runtime.call_tool(
                "platform-ops",
                "platform.rollback_deployment",
                {**arguments, "approval_token": token},
            )
            runtime.close()

            self.assertEqual(failed.rule, "upstream_error")
            self.assertEqual(replay.rule, "approval_replay")

    def test_v1_token_is_rejected_with_reissue_message(self) -> None:
        authority = ApprovalAuthority(SECRET)
        arguments = _arguments()
        claims = {
            "version": "judikt-approval-v1",
            "actor": "demo-operator",
            "reason": "old token",
            "server": "platform-ops",
            "tool": "platform.rollback_deployment",
            "arguments_hash": "unused",
            "expires_at": int(time.time()) + 300,
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(
            hmac.new(authority.secret, payload.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")

        with self.assertRaisesRegex(
            ApprovalTokenError,
            "approval token version is unsupported; re-issue",
        ):
            authority.verify(
                token=f"{payload}.{signature}",
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments=arguments,
            )


if __name__ == "__main__":
    unittest.main()
