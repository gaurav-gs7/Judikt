from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from judikt.audit import AuditStore
from judikt.audit_sink import JsonlAuditSink, NullAuditSink, SiemAuditSink, build_audit_sink
from judikt.metrics import Metrics


class _Response:
    def __init__(self, status: int = 202) -> None:
        self.status = status

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _event() -> dict[str, object]:
    return {
        "created_at": "2026-07-22T10:00:00+00:00",
        "correlation_id": "corr-1",
        "server": "platform-ops",
        "tool": "platform.health",
        "allowed": True,
        "rule": "allow",
        "arguments": {"token": "[REDACTED]"},
        "event_hash": "a" * 64,
        "signature": "b" * 64,
    }


class SiemAuditSinkTest(unittest.TestCase):
    def test_null_and_jsonl_sinks_are_stable_under_concurrent_writes(self) -> None:
        NullAuditSink().write(_event())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "audit.jsonl"
            sink = JsonlAuditSink(path)
            threads = [
                threading.Thread(target=sink.write, args=({**_event(), "sequence": index},))
                for index in range(32)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            records = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(len(records), 32)
        self.assertEqual({record["sequence"] for record in records}, set(range(32)))

    def test_builder_selects_none_jsonl_and_rejects_invalid_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            default_path = Path(directory) / "default.jsonl"
            with patch.dict(os.environ, {"JUDIKT_AUDIT_SINK": " disabled "}, clear=True):
                self.assertIsInstance(build_audit_sink(default_path), NullAuditSink)
            custom_path = Path(directory) / "custom.jsonl"
            with patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_SINK": "jsonl",
                    "JUDIKT_AUDIT_JSONL_PATH": str(custom_path),
                },
                clear=True,
            ):
                sink = build_audit_sink(default_path)
                self.assertIsInstance(sink, JsonlAuditSink)
                sink.write(_event())
            self.assertEqual(json.loads(custom_path.read_text()), _event())

            with patch.dict(os.environ, {"JUDIKT_AUDIT_SINK": "unknown"}, clear=True), self.assertRaisesRegex(
                RuntimeError, "unsupported audit sink"
            ):
                build_audit_sink(default_path)

    def test_s3_builder_requires_bucket(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"JUDIKT_AUDIT_SINK": "s3", "JUDIKT_AUDIT_S3_BUCKET": ""},
            clear=True,
        ), self.assertRaisesRegex(RuntimeError, "AUDIT_S3_BUCKET"):
            build_audit_sink(Path(directory) / "audit.jsonl")

    def test_s3_builder_passes_bucket_and_normalized_prefix_to_sink(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_SINK": "s3",
                "JUDIKT_AUDIT_S3_BUCKET": "audit-bucket",
                "JUDIKT_AUDIT_S3_PREFIX": "/security/judikt/",
            },
            clear=True,
        ), patch("judikt.audit_sink.S3AuditSink") as sink_factory:
            sink = build_audit_sink(Path(directory) / "audit.jsonl")

        self.assertIs(sink, sink_factory.return_value)
        sink_factory.assert_called_once_with("audit-bucket", "/security/judikt/")

    def test_generic_json_contract_is_authenticated_hashed_and_signed(self) -> None:
        captured: list[object] = []

        def opener(request: object, timeout: float) -> _Response:
            captured.append((request, timeout))
            return _Response()

        sink = SiemAuditSink(
            "https://siem.example.test/events",
            "operator-token",
            hmac_secret="signing-secret",
            timeout_seconds=1.5,
        )
        with patch("judikt.audit_sink.urllib.request.urlopen", side_effect=opener):
            sink.write(_event())

        request, timeout = captured[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        payload = json.loads(request.data)
        expected_signature = hmac.new(
            b"signing-secret", request.data, hashlib.sha256
        ).hexdigest()
        self.assertEqual(request.full_url, "https://siem.example.test/events")
        self.assertEqual(timeout, 1.5)
        self.assertEqual(headers["authorization"], "Bearer operator-token")
        self.assertEqual(
            headers["x-judikt-event-sha256"], hashlib.sha256(request.data).hexdigest()
        )
        self.assertEqual(headers["x-judikt-signature-256"], f"sha256={expected_signature}")
        self.assertEqual(payload["schema_version"], "judikt.audit.v1")
        self.assertEqual(payload["event"], _event())

    def test_splunk_hec_contract_uses_splunk_auth_and_index_fields(self) -> None:
        captured: list[object] = []
        sink = SiemAuditSink(
            "http://127.0.0.1:8088/services/collector/event",
            "hec-token",
            protocol="splunk_hec",
        )
        with patch(
            "judikt.audit_sink.urllib.request.urlopen",
            side_effect=lambda request, timeout: captured.append(request) or _Response(),
        ):
            sink.write(_event())

        request = captured[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        payload = json.loads(request.data)
        self.assertEqual(headers["authorization"], "Splunk hec-token")
        self.assertEqual(payload["sourcetype"], "judikt:audit:json")
        self.assertEqual(payload["fields"]["tool"], "platform.health")
        self.assertEqual(payload["fields"]["allowed"], "true")
        self.assertNotIn("x-judikt-signature-256", headers)

    def test_builder_supports_siem_and_secret_source_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_SINK": "siem",
                "JUDIKT_SIEM_URL": "https://siem.example.test/events",
                "JUDIKT_SIEM_TOKEN": "token",
                "JUDIKT_SIEM_PROTOCOL": "json",
            },
            clear=True,
        ):
            sink = build_audit_sink(Path(directory) / "audit.jsonl")
        self.assertIsInstance(sink, SiemAuditSink)

    def test_builder_requires_endpoint_and_valid_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with patch.dict(
                os.environ,
                {"JUDIKT_AUDIT_SINK": "siem", "JUDIKT_SIEM_TOKEN": "token"},
                clear=True,
            ), self.assertRaisesRegex(RuntimeError, "JUDIKT_SIEM_URL"):
                build_audit_sink(path)

            for timeout in ("bad", "0", "-1", "nan", "inf"):
                with self.subTest(timeout=timeout), patch.dict(
                    os.environ,
                    {
                        "JUDIKT_AUDIT_SINK": "siem",
                        "JUDIKT_SIEM_URL": "https://siem.example.test/events",
                        "JUDIKT_SIEM_TOKEN": "token",
                        "JUDIKT_SIEM_TIMEOUT_SECONDS": timeout,
                    },
                    clear=True,
                ), self.assertRaisesRegex(RuntimeError, "positive finite"):
                    build_audit_sink(path)

    def test_builder_uses_broker_for_siem_token_and_hmac(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_SINK": "siem",
                "JUDIKT_SIEM_URL": "https://siem.example.test/events",
                "JUDIKT_SIEM_TOKEN_SECRET_ARN": "token-secret",
                "JUDIKT_SIEM_HMAC_SECRET_VAULT_PATH": "secret/data/siem",
            },
            clear=True,
        ), patch(
            "judikt.audit_sink.resolve_configured_secret",
            side_effect=["brokered-token", "brokered-hmac"],
        ) as broker:
            sink = build_audit_sink(Path(directory) / "audit.jsonl")

        self.assertIsInstance(sink, SiemAuditSink)
        self.assertEqual(broker.call_count, 2)

    def test_rejects_unsafe_url_protocol_token_and_timeout(self) -> None:
        cases = [
            ("http://siem.example.test/events", "token", "json", 1),
            ("ftp://siem.example.test/events", "token", "json", 1),
            ("https://user:pass@siem.example.test/events", "token", "json", 1),
            ("https://siem.example.test/events?token=value", "token", "json", 1),
            ("https://siem.example.test/events", "", "json", 1),
            ("https://siem.example.test/events", "token", "unknown", 1),
            ("https://siem.example.test/events", "token", "json", 0),
            ("https://siem.example.test/events", "token", "json", float("nan")),
            ("https://siem.example.test/events", "token", "json", float("inf")),
        ]
        for endpoint, token, protocol, timeout in cases:
            with self.subTest(endpoint=endpoint, protocol=protocol, timeout=timeout), self.assertRaises(
                RuntimeError
            ):
                SiemAuditSink(
                    endpoint,
                    token,
                    protocol=protocol,
                    timeout_seconds=timeout,
                )

        with patch.dict(
            os.environ, {"JUDIKT_SIEM_ALLOW_INSECURE_HTTP": "true"}, clear=True
        ):
            sink = SiemAuditSink("http://siem.example.test/events/", "token")
        self.assertEqual(sink.endpoint, "http://siem.example.test/events")

    def test_network_failures_are_normalized(self) -> None:
        sink = SiemAuditSink("https://siem.example.test/events", "token")
        failures = [
            (urllib.error.HTTPError(sink.endpoint, 503, "private", {}, None), "HTTP 503"),
            (urllib.error.URLError("private network detail"), "unavailable"),
            (TimeoutError("private socket detail"), "unavailable"),
        ]
        for failure, message in failures:
            with self.subTest(failure=failure), patch(
                "judikt.audit_sink.urllib.request.urlopen", side_effect=failure
            ), self.assertRaisesRegex(RuntimeError, message):
                sink.write(_event())

        with patch(
            "judikt.audit_sink.urllib.request.urlopen",
            return_value=_Response(status=500),
        ), self.assertRaisesRegex(RuntimeError, "HTTP 500"):
            sink.write(_event())

    def test_audit_store_best_effort_and_strict_sink_failure_semantics(self) -> None:
        class FailingSink:
            name = "failing-siem"

            def write(self, event: dict[str, object]) -> None:
                raise RuntimeError("private SIEM failure")

        with tempfile.TemporaryDirectory() as directory:
            for strict in (False, True):
                with self.subTest(strict=strict), patch.dict(
                    os.environ,
                    {
                        "JUDIKT_AUDIT_HMAC_SECRET": "audit-secret-with-at-least-32-bytes",
                        "JUDIKT_AUDIT_SINK_STRICT": str(strict).lower(),
                    },
                    clear=True,
                ), patch("judikt.audit.build_audit_sink", return_value=FailingSink()):
                    store = AuditStore(Path(directory) / f"audit-{strict}.db")
                    try:
                        if strict:
                            with self.assertRaisesRegex(RuntimeError, "durable outbox"):
                                store.record(
                                    correlation_id="corr-1",
                                    server="platform-ops",
                                    tool="platform.health",
                                    allowed=True,
                                    rule="allow",
                                    reason="allowed",
                                    arguments={},
                                    result={"ok": True},
                                    duration_ms=1,
                                )
                        else:
                            store.record(
                                correlation_id="corr-1",
                                server="platform-ops",
                                tool="platform.health",
                                allowed=True,
                                rule="allow",
                                reason="allowed",
                                arguments={},
                                result={"ok": True},
                                duration_ms=1,
                            )
                        self.assertEqual(len(store.recent()), 1)
                        self.assertTrue(store.verify_chain()["valid"])
                        self.assertGreaterEqual(store.outbox_status()["pending"], 1)
                    finally:
                        store.close()

    def test_durable_outbox_retries_and_delivers_each_event_once(self) -> None:
        class RecoveringSink:
            name = "recovering-siem"

            def __init__(self) -> None:
                self.available = False
                self.deliveries: dict[tuple[str, int, str], int] = {}

            def write(self, event: dict[str, object]) -> None:
                if not self.available:
                    raise RuntimeError("sink unavailable")
                key = (
                    str(event["chain_id"]),
                    int(event["seq"]),
                    str(event.get("record_type", "event")),
                )
                self.deliveries[key] = self.deliveries.get(key, 0) + 1

        sink = RecoveringSink()
        metrics = Metrics()
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": "outbox-audit-secret-with-at-least-32-bytes",
                "JUDIKT_AUDIT_RETRY_INTERVAL_SECONDS": "60",
            },
            clear=True,
        ), patch("judikt.audit.build_audit_sink", return_value=sink):
            store = AuditStore(Path(directory) / "audit.db", metrics=metrics)
            for index in range(50):
                store.record(
                    correlation_id=f"outbox-{index}",
                    server="test",
                    tool="test.read",
                    allowed=True,
                    rule="allow",
                    reason="allowed",
                    arguments={"index": index},
                    result={"ok": True},
                    duration_ms=1,
                )

            self.assertEqual(store.outbox_status()["pending"], 51)
            sink.available = True
            report = store.reconcile()

            event_deliveries = {
                key: count for key, count in sink.deliveries.items() if key[2] == "event"
            }
            self.assertEqual(len(event_deliveries), 50)
            self.assertEqual(set(event_deliveries.values()), {1})
            self.assertEqual(report["pending"], 0)
            rendered = metrics.render()
            self.assertIn("judikt_audit_outbox_pending 0", rendered)
            self.assertIn("judikt_audit_delivery_failures_total 50", rendered)
            store.close()


if __name__ == "__main__":
    unittest.main()
