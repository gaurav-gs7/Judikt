from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.audit import AuditStore


def _record(store: AuditStore) -> None:
    store.record(
        correlation_id="corr-1",
        server="platform-ops",
        tool="platform.health",
        allowed=True,
        rule="allow",
        reason="allowed by policy",
        arguments={"service": "payments-api"},
        result={"status": "healthy"},
        duration_ms=1.25,
    )


def _record_many(path: str, count: int, prefix: str) -> None:
    store = AuditStore(Path(path))
    try:
        for index in range(count):
            store.record(
                correlation_id=f"{prefix}-{index}",
                server="concurrent",
                tool="concurrent.read",
                allowed=True,
                rule="allow",
                reason="allowed by policy",
                arguments={"index": index},
                result={"ok": True},
                duration_ms=1,
            )
    finally:
        store.close()


class AuditHardeningTest(unittest.TestCase):
    def test_signature_required_fails_closed_without_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true", "JUDIKT_AUDIT_HMAC_SECRET": ""},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires JUDIKT_AUDIT_HMAC_SECRET"):
                AuditStore(Path(directory) / "audit.db")

    def test_verify_on_startup_rejects_tampered_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            with patch.dict(
                os.environ,
                {"JUDIKT_AUDIT_HMAC_SECRET": "test-key"},
                clear=False,
            ):
                store = AuditStore(path)
                _record(store)
                store.close()
            connection = sqlite3.connect(path)
            connection.execute("UPDATE audit_events SET rule = 'tampered' WHERE id = 1")
            connection.commit()
            connection.close()

            with patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_HMAC_SECRET": "test-key",
                    "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                    "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "audit integrity verification failed"):
                    AuditStore(path)

    def test_signed_chain_verifies_in_required_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": "test-key",
                "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            },
            clear=False,
        ):
            store = AuditStore(Path(directory) / "audit.db")
            try:
                _record(store)
                report = store.verify_chain()
                self.assertTrue(report["valid"])
                self.assertTrue(report["signed"])
                self.assertTrue(report["signature_required"])
            finally:
                store.close()

    def test_multiple_events_form_one_contiguous_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"JUDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
        ):
            store = AuditStore(Path(directory) / "audit.db")
            try:
                for index in range(4):
                    _record(store)
                events = list(reversed(store.recent()))
                report = store.verify_chain()
                self.assertEqual(report["checked_events"], 4)
                self.assertEqual(report["head_hash"], events[-1]["event_hash"])
                self.assertEqual(events[0]["previous_hash"], "")
                for previous, current in zip(events, events[1:]):
                    self.assertEqual(current["previous_hash"], previous["event_hash"])
            finally:
                store.close()

    def test_wrong_signing_key_is_detected_on_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            with patch.dict(os.environ, {"JUDIKT_AUDIT_HMAC_SECRET": "first-key"}, clear=False):
                store = AuditStore(path)
                _record(store)
                store.close()
            with patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_HMAC_SECRET": "wrong-key",
                    "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                    "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "signature_mismatch"):
                    AuditStore(path)

    def test_signature_and_link_tampering_are_reported_precisely(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"JUDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
        ):
            path = Path(directory) / "audit.db"
            store = AuditStore(path)
            _record(store)
            _record(store)
            connection = sqlite3.connect(path)
            connection.execute("UPDATE audit_events SET signature = 'bad' WHERE id = 1")
            connection.execute("UPDATE audit_events SET previous_hash = 'bad' WHERE id = 2")
            connection.commit()
            connection.close()
            report = store.verify_chain()
            errors = {(item["id"], item["error"]) for item in report["errors"]}
            self.assertIn((1, "signature_mismatch"), errors)
            self.assertIn((2, "previous_hash_mismatch"), errors)
            self.assertIn((2, "event_hash_mismatch"), errors)
            store.close()

    def test_strict_startup_rejects_legacy_unsigned_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            connection = sqlite3.connect(path)
            connection.execute(
                """
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                    correlation_id TEXT NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL,
                    allowed INTEGER NOT NULL, rule TEXT NOT NULL, reason TEXT NOT NULL,
                    arguments_json TEXT NOT NULL, result_json TEXT, duration_ms REAL NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO audit_events (created_at, correlation_id, server, tool, allowed, rule, reason, arguments_json, result_json, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("2026-01-01T00:00:00+00:00", "legacy", "s", "t", 1, "allow", "ok", "{}", None, 1),
            )
            connection.commit()
            connection.close()
            with patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_HMAC_SECRET": "test-key",
                    "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                    "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "legacy_unsigned_event"):
                    AuditStore(path)

    def test_concurrent_writers_preserve_chain_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"JUDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
        ):
            store = AuditStore(Path(directory) / "audit.db")
            threads = [threading.Thread(target=_record, args=(store,)) for _ in range(24)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            report = store.verify_chain()
            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(report["checked_events"], 24)
            store.close()

    def test_two_processes_append_one_gapless_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"JUDIKT_AUDIT_HMAC_SECRET": "concurrent-test-key", "JUDIKT_AUDIT_SINK": "none"},
            clear=False,
        ):
            path = Path(directory) / "audit.db"
            initial = AuditStore(path)
            initial.close()
            processes = [
                multiprocessing.Process(
                    target=_record_many,
                    args=(str(path), 500, prefix),
                )
                for prefix in ("writer-a", "writer-b")
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(30)
                self.assertEqual(process.exitcode, 0)

            store = AuditStore(path)
            try:
                report = store.verify_chain()
                sequences = [row["seq"] for row in store._connection.execute(
                    "SELECT seq FROM audit_events ORDER BY seq"
                )]
                self.assertTrue(report["valid"], report["errors"])
                self.assertEqual(sequences, list(range(1, 1001)))
            finally:
                store.close()

    def test_sequence_gap_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"JUDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
        ):
            store = AuditStore(Path(directory) / "audit.db")
            for _ in range(3):
                _record(store)
            store._connection.execute("DELETE FROM audit_events WHERE seq = 2")
            store._connection.commit()

            report = store.verify_chain()

            self.assertFalse(report["valid"])
            self.assertIn("sequence_gap", {error["error"] for error in report["errors"]})
            store.close()

    def test_previous_hash_format_migrates_without_rewriting_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            secret = "legacy-signing-key"
            payload = {
                "event_version": 2,
                "created_at": "2026-01-01T00:00:00+00:00",
                "correlation_id": "legacy-signed",
                "server": "legacy",
                "tool": "legacy.read",
                "allowed": True,
                "rule": "allow",
                "reason": "allowed",
                "arguments": {},
                "result": {"ok": True},
                "duration_ms": 1.0,
                "action": "ALLOW",
                "evidence": [],
                "instance_id": "local",
                "previous_hash": "",
            }
            event_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            signature = hmac.new(secret.encode(), event_hash.encode(), hashlib.sha256).hexdigest()
            connection = sqlite3.connect(path)
            connection.execute(
                """
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                    correlation_id TEXT NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL,
                    allowed INTEGER NOT NULL, rule TEXT NOT NULL, reason TEXT NOT NULL,
                    arguments_json TEXT NOT NULL, result_json TEXT, duration_ms REAL NOT NULL,
                    action TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
                    signature TEXT NOT NULL, instance_id TEXT NOT NULL,
                    event_version INTEGER NOT NULL, evidence_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO audit_events (
                    created_at, correlation_id, server, tool, allowed, rule, reason,
                    arguments_json, result_json, duration_ms, action, previous_hash,
                    event_hash, signature, instance_id, event_version, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["created_at"], payload["correlation_id"], payload["server"],
                    payload["tool"], 1, payload["rule"], payload["reason"], "{}",
                    '{"ok": true}', 1.0, payload["action"], "", event_hash, signature,
                    "local", 2, "[]",
                ),
            )
            connection.commit()
            connection.close()

            with patch.dict(os.environ, {"JUDIKT_AUDIT_HMAC_SECRET": secret}, clear=False):
                store = AuditStore(path)
                try:
                    row = store._connection.execute("SELECT * FROM audit_events").fetchone()
                    self.assertEqual(row["event_hash"], event_hash)
                    self.assertEqual(row["hash_version"], 1)
                    self.assertEqual(row["seq"], 1)
                    self.assertTrue(store.verify_chain()["valid"])
                finally:
                    store.close()

    def test_malformed_stored_json_is_reported_and_fails_verified_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            with patch.dict(
                os.environ, {"JUDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
            ):
                store = AuditStore(path)
                _record(store)
                store.close()
            connection = sqlite3.connect(path)
            connection.execute("UPDATE audit_events SET arguments_json = '{bad-json' WHERE id = 1")
            connection.commit()
            connection.close()
            with patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_HMAC_SECRET": "test-key",
                    "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "malformed_event_payload"):
                    AuditStore(path)


if __name__ == "__main__":
    unittest.main()
