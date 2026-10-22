from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import types
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from judikt.findings import (
    ArgusAlertmanagerSink,
    FindingDispatcher,
    build_finding_event,
    should_emit_finding,
)
from judikt.ops_runtime import JudiktOpsRuntime


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "config" / "policies.yaml"


class _RecordingSink:
    name = "recording"

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.events: list[dict[str, object]] = []

    def send(self, event: dict[str, object]) -> None:
        if self.fail:
            raise RuntimeError("synthetic delivery failure with private detail")
        self.events.append(event)


class _FailOnceSink(_RecordingSink):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def send(self, event: dict[str, object]) -> None:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("temporary outage")
        super().send(event)


class _Response:
    status = 202

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _capture_urlopen(captured: list[dict[str, object]]):
    def open_request(request: object, timeout: float) -> _Response:
        captured.append(
            {
                "url": request.full_url,
                "headers": {key.lower(): value for key, value in request.header_items()},
                "body": request.data,
                "timeout": timeout,
            }
        )
        return _Response()

    return open_request


def _event(arguments: object | None = None) -> dict[str, object]:
    return build_finding_event(
        correlation_id="corr-123",
        server="platform-ops",
        tool="platform.run_diagnostic",
        allowed=False,
        rule="blocked_pattern",
        action="DENY",
        reason="arguments matched a blocked security pattern",
        risk_score=75,
        risk_level="high",
        arguments=arguments or {"command": "curl https://private.invalid/secret"},
        result=None,
    )


class FindingDispatcherTest(unittest.TestCase):
    def test_outbox_delivers_once_and_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sink = _RecordingSink()
            dispatcher = FindingDispatcher(Path(directory) / "findings.db", sink)
            try:
                self.assertEqual(dispatcher.dispatch(_event()), "delivered")
                self.assertEqual(dispatcher.dispatch(_event()), "deduplicated")
                self.assertEqual(len(sink.events), 1)
                self.assertEqual(dispatcher.status()["delivered"], 1)
            finally:
                dispatcher.close()

    def test_failed_delivery_stays_in_outbox_without_raw_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sink = _RecordingSink(fail=True)
            dispatcher = FindingDispatcher(Path(directory) / "findings.db", sink)
            try:
                self.assertEqual(dispatcher.dispatch(_event()), "pending")
                status = dispatcher.status()
                self.assertEqual(status["pending"], 1)
                self.assertEqual(status["retrying"], 1)
                row = dispatcher._connection.execute(  # type: ignore[union-attr]
                    "SELECT last_error_hash, payload_json FROM finding_outbox"
                ).fetchone()
                self.assertEqual(len(row["last_error_hash"]), 64)
                self.assertNotIn("private detail", row["payload_json"])
            finally:
                dispatcher.close()

    def test_background_worker_retries_without_another_tool_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_FINDING_RETRY_INTERVAL_SECONDS": "0.01",
                "JUDIKT_FINDING_RETRY_BASE_SECONDS": "0.01",
            },
            clear=False,
        ):
            sink = _FailOnceSink()
            dispatcher = FindingDispatcher(Path(directory) / "findings.db", sink)
            try:
                self.assertEqual(dispatcher.dispatch(_event()), "pending")
                deadline = time.time() + 1
                while dispatcher.status()["delivered"] == 0 and time.time() < deadline:
                    time.sleep(0.01)
                self.assertEqual(dispatcher.status()["delivered"], 1)
                self.assertEqual(sink.calls, 2)
            finally:
                dispatcher.close()

    def test_argus_sink_emits_real_alertmanager_contract_and_signature(self) -> None:
        captured: list[dict[str, object]] = []
        with patch("judikt.findings.urllib.request.urlopen", side_effect=_capture_urlopen(captured)):
            sink = ArgusAlertmanagerSink(
                "http://127.0.0.1:8081",
                "operator-owned-token",
                2,
                "signing-secret",
            )
            sink.send(_event())

        request = captured[0]
        body = request["body"]
        payload = json.loads(body)
        self.assertEqual(request["url"], "http://127.0.0.1:8081/v1/alerts/alertmanager")
        self.assertEqual(request["headers"]["authorization"], "Bearer operator-owned-token")
        expected = "sha256=" + hmac.new(b"signing-secret", body, hashlib.sha256).hexdigest()
        self.assertEqual(request["headers"]["x-judikt-signature-256"], expected)
        self.assertEqual(payload["receiver"], "judikt")
        self.assertEqual(payload["alerts"][0]["labels"]["alertname"], "JudiktMCPSecurityFinding")
        rendered = json.dumps(payload)
        self.assertNotIn("private.invalid", rendered)

    def test_real_runtime_exports_blocked_security_call_to_argus(self) -> None:
        captured: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_ARGUS_URL": "http://127.0.0.1:8081",
                "JUDIKT_ARGUS_API_TOKEN": "argus-service-token",
            },
            clear=False,
        ), patch(
            "judikt.findings.urllib.request.urlopen",
            side_effect=_capture_urlopen(captured),
        ):
            runtime = JudiktOpsRuntime(
                POLICY,
                Path(directory) / "audit.db",
                include_demo_servers=True,
            )
            try:
                result = runtime.call_tool(
                    "platform-ops",
                    "platform.run_diagnostic",
                    {"service": "payments-api", "command": "curl https://private.invalid/export"},
                )
                self.assertFalse(result.allowed)
                self.assertEqual(runtime.finding_delivery()["delivered"], 1)
                self.assertIn(
                    'judikt_findings_total{outcome="delivered"} 1',
                    runtime.render_metrics(),
                )
            finally:
                runtime.close()

        payload = json.loads(captured[0]["body"])
        self.assertEqual(payload["alerts"][0]["labels"]["rule"], "blocked_pattern")
        self.assertNotIn("private.invalid", json.dumps(payload))

    def test_routine_approval_requirement_does_not_page_argus(self) -> None:
        self.assertFalse(should_emit_finding("approval_required", "critical", False))
        self.assertTrue(should_emit_finding("inbound_prompt_injection", "high", False))
        self.assertFalse(should_emit_finding("allow", "critical", True))
        with patch.dict(
            os.environ,
            {"JUDIKT_FINDING_INCLUDE_ALLOWED_CRITICAL": "true"},
            clear=False,
        ):
            self.assertTrue(should_emit_finding("allow", "critical", True))

    def test_finding_sanitizes_caller_controlled_identifiers(self) -> None:
        event = build_finding_event(
            correlation_id="corr\nraw-secret",
            server="bad server name",
            tool="tool/<unsafe>",
            allowed=False,
            rule="allowlist",
            action="DENY",
            reason="not allowed",
            risk_score=50,
            risk_level="high",
            arguments={},
            result=None,
        )

        rendered = json.dumps(event)
        self.assertNotIn("\n", event["correlation_id"])
        self.assertNotIn("<", rendered)
        self.assertEqual(len(event["correlation_id_hash"]), 64)

    def test_repeated_rule_is_deduplicated_within_incident_window(self) -> None:
        with patch("judikt.findings.time.time", return_value=1_800_000_000):
            first = _event({"command": "curl https://one.invalid"})
            second = build_finding_event(
                correlation_id="corr-456",
                server="platform-ops",
                tool="platform.run_diagnostic",
                allowed=False,
                rule="blocked_pattern",
                action="DENY",
                reason="arguments matched a blocked security pattern",
                risk_score=75,
                risk_level="high",
                arguments={"command": "curl https://two.invalid"},
                result=None,
            )

        self.assertEqual(first["dedupe_key"], second["dedupe_key"])
        self.assertNotEqual(first["correlation_id_hash"], second["correlation_id_hash"])

    def test_argus_configuration_requires_operator_owned_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_ARGUS_URL": "http://127.0.0.1:8081",
                "JUDIKT_ARGUS_API_TOKEN": "",
                "JUDIKT_ARGUS_TOKEN_SECRET_ARN": "",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "operator-owned"):
                FindingDispatcher(Path(directory) / "findings.db")

    def test_disabled_dispatcher_has_stable_status_and_idempotent_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"JUDIKT_ARGUS_URL": "", "JUDIKT_FINDING_RETRY_INTERVAL_SECONDS": "bad"},
            clear=False,
        ):
            dispatcher = FindingDispatcher(Path(directory) / "findings.db")
            self.assertEqual(
                dispatcher.status(),
                {
                    "enabled": False,
                    "sink": "none",
                    "pending": 0,
                    "delivered": 0,
                    "retrying": 0,
                },
            )
            self.assertEqual(dispatcher.dispatch(_event()), "disabled")
            dispatcher.close()
            dispatcher.close()

    def test_outbox_survives_restart_and_retries_pending_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "JUDIKT_FINDING_RETRY_INTERVAL_SECONDS": "60",
                "JUDIKT_FINDING_RETRY_BASE_SECONDS": "0.01",
            },
            clear=False,
        ):
            path = Path(directory) / "findings.db"
            first = FindingDispatcher(path, _RecordingSink(fail=True))
            self.assertEqual(first.dispatch(_event()), "pending")
            first.close()

            sink = _RecordingSink()
            second = FindingDispatcher(path, sink)
            try:
                with second._lock:
                    second._connection.execute(  # type: ignore[union-attr]
                        "UPDATE finding_outbox SET next_attempt_at = 0"
                    )
                    second._connection.commit()  # type: ignore[union-attr]
                self.assertEqual(second.flush(), 1)
                self.assertEqual(second.status()["pending"], 0)
                self.assertEqual(len(sink.events), 1)
            finally:
                second.close()

    def test_flush_zero_limit_never_accidentally_drains_everything(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sink = _RecordingSink(fail=True)
            dispatcher = FindingDispatcher(Path(directory) / "findings.db", sink)
            try:
                dispatcher.dispatch(_event())
                attempts_before = dispatcher._connection.execute(  # type: ignore[union-attr]
                    "SELECT attempts FROM finding_outbox"
                ).fetchone()["attempts"]
                self.assertEqual(dispatcher.flush(limit=0), 0)
                attempts_after = dispatcher._connection.execute(  # type: ignore[union-attr]
                    "SELECT attempts FROM finding_outbox"
                ).fetchone()["attempts"]
                self.assertEqual(attempts_after, attempts_before)
            finally:
                dispatcher.close()

    def test_argus_url_security_validation(self) -> None:
        invalid = {
            "ftp://argus.example.com": "absolute HTTP",
            "https://user:pass@argus.example.com": "must not contain",
            "https://argus.example.com/path?token=secret": "must not contain",
            "https://argus.example.com/path#fragment": "must not contain",
            "http://argus.example.com": "requires HTTPS",
        }
        for url, error in invalid.items():
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, error):
                ArgusAlertmanagerSink(url, "token", 1, "")

        with patch.dict(
            os.environ, {"JUDIKT_ARGUS_ALLOW_INSECURE_HTTP": "true"}, clear=False
        ):
            sink = ArgusAlertmanagerSink(
                "http://argus.example.com/v1/alerts/alertmanager/", "token", 1, ""
            )
        self.assertEqual(sink.endpoint, "http://argus.example.com/v1/alerts/alertmanager")

    def test_argus_timeout_and_retry_configuration_reject_invalid_values(self) -> None:
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(
                ValueError, "positive finite"
            ):
                ArgusAlertmanagerSink("http://127.0.0.1:8081", "token", timeout, "")

        with tempfile.TemporaryDirectory() as directory:
            for name, value in (
                ("JUDIKT_FINDING_RETRY_INTERVAL_SECONDS", "bad"),
                ("JUDIKT_FINDING_RETRY_BASE_SECONDS", "0"),
            ):
                with self.subTest(name=name), patch.dict(os.environ, {name: value}, clear=False):
                    with self.assertRaisesRegex(ValueError, name):
                        FindingDispatcher(Path(directory) / f"{name}.db", _RecordingSink())

    def test_invalid_dedupe_window_is_rejected(self) -> None:
        for value in ("bad", "0", "-1"):
            with self.subTest(value=value), patch.dict(
                os.environ, {"JUDIKT_FINDING_DEDUPE_WINDOW_SECONDS": value}, clear=False
            ), self.assertRaisesRegex(ValueError, "DEDUPE_WINDOW"):
                _event()

    def test_argus_http_failures_are_normalized(self) -> None:
        sink = ArgusAlertmanagerSink("http://127.0.0.1:8081", "token", 1, "")
        failures = [
            (
                urllib.error.HTTPError(sink.endpoint, 503, "down", {}, None),
                "HTTP 503",
            ),
            (urllib.error.URLError("refused"), "unavailable"),
        ]
        for failure, message in failures:
            with self.subTest(failure=failure), patch(
                "judikt.findings.urllib.request.urlopen", side_effect=failure
            ), self.assertRaisesRegex(RuntimeError, message):
                sink.send(_event())

        class RejectedResponse(_Response):
            status = 500

        with patch(
            "judikt.findings.urllib.request.urlopen", return_value=RejectedResponse()
        ), self.assertRaisesRegex(RuntimeError, "HTTP 500"):
            sink.send(_event())

    def test_secret_manager_token_is_supported_and_binary_secret_is_rejected(self) -> None:
        calls: list[str] = []

        class Client:
            def get_secret_value(self, SecretId: str) -> dict[str, object]:
                calls.append(SecretId)
                return {"SecretString": "operator-token"}

        boto3 = types.SimpleNamespace(client=lambda service: Client())
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            sys.modules, {"boto3": boto3}
        ), patch.dict(
            os.environ,
            {
                "JUDIKT_ARGUS_URL": "http://127.0.0.1:8081",
                "JUDIKT_ARGUS_API_TOKEN": "",
                "JUDIKT_ARGUS_TOKEN_SECRET_ARN": "arn:aws:secretsmanager:test:argus",
            },
            clear=False,
        ):
            dispatcher = FindingDispatcher(Path(directory) / "findings.db")
            dispatcher.close()
        self.assertEqual(calls, ["arn:aws:secretsmanager:test:argus"])

        class BinaryClient:
            def get_secret_value(self, SecretId: str) -> dict[str, object]:
                return {"SecretBinary": b"not-supported"}

        with patch.dict(
            sys.modules, {"boto3": types.SimpleNamespace(client=lambda service: BinaryClient())}
        ), patch.dict(
            os.environ,
            {
                "JUDIKT_ARGUS_URL": "http://127.0.0.1:8081",
                "JUDIKT_ARGUS_API_TOKEN": "",
                "JUDIKT_ARGUS_TOKEN_SECRET_ARN": "binary-secret",
            },
            clear=False,
        ), self.assertRaisesRegex(RuntimeError, "has no SecretString"):
            FindingDispatcher(Path("unused.db"))

    def test_finding_rule_override_and_dedupe_bucket_rollover(self) -> None:
        with patch.dict(os.environ, {"JUDIKT_FINDING_RULES": "custom_rule"}, clear=False):
            self.assertTrue(should_emit_finding("custom_rule", "low", False))
            self.assertFalse(should_emit_finding("blocked_pattern", "critical", False))

        with patch.dict(
            os.environ, {"JUDIKT_FINDING_DEDUPE_WINDOW_SECONDS": "60"}, clear=False
        ):
            with patch("judikt.findings.time.time", return_value=120):
                first = _event()
            with patch("judikt.findings.time.time", return_value=180):
                second = _event()
        self.assertNotEqual(first["dedupe_key"], second["dedupe_key"])


if __name__ == "__main__":
    unittest.main()
