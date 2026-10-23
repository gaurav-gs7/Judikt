from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from judikt.approval import ApprovalAuthority
from judikt.slack_approval import SlackApprovalError, SlackApprovalWorkflow


class _Response:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class SlackApprovalWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            "os.environ",
            {
                "JUDIKT_SLACK_WEBHOOK_URL": "https://hooks.slack.test/services/example",
                "JUDIKT_SLACK_SIGNING_SECRET": "slack-signing-secret",
                "JUDIKT_SLACK_APPROVER_IDS": "U-ONCALL",
            },
            clear=True,
        )
        self.environment.start()
        self.authority = ApprovalAuthority("approval-secret-at-least-32-bytes")
        self.workflow = SlackApprovalWorkflow(
            Path(self.temp_dir.name) / "approvals.db",
            self.authority,
        )
        self.notify = patch.object(self.workflow, "_notify")
        self.notify.start()

    def tearDown(self) -> None:
        self.notify.stop()
        self.workflow.close()
        self.environment.stop()
        self.temp_dir.cleanup()

    def test_approved_token_is_returned_only_to_requester_and_bound_to_arguments(self) -> None:
        arguments = {
            "service": "payments-api",
            "actor": "sre-oncall",
            "rollback_plan": "restore the previous release when health checks fail",
        }
        requested = self.workflow.request(
            requester="sre-oncall",
            reason="elevated 5xx",
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments=arguments,
            safe_arguments=arguments,
        )
        body, headers = self._signed_action(requested["request_id"], "approve", "U-ONCALL")

        response = self.workflow.handle_action(headers, body)
        status = self.workflow.status(requested["request_id"], "sre-oncall")

        self.assertIn("approved", response["text"])
        self.assertEqual(status["status"], "APPROVED")
        self.authority.verify(
            token=status["approval_token"],
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments=arguments,
        )
        with self.assertRaisesRegex(SlackApprovalError, "different authenticated subject"):
            self.workflow.status(requested["request_id"], "readonly")

    def test_rejects_invalid_signature_and_unapproved_slack_user(self) -> None:
        requested = self.workflow.request(
            requester="sre-oncall",
            reason="restart",
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments={"actor": "sre-oncall"},
            safe_arguments={"actor": "sre-oncall"},
        )
        body, headers = self._signed_action(requested["request_id"], "approve", "U-NOT-ALLOWED")

        with self.assertRaisesRegex(SlackApprovalError, "not an authorized approver"):
            self.workflow.handle_action(headers, body)

        headers["x-slack-signature"] = "v0=invalid"
        with self.assertRaisesRegex(SlackApprovalError, "signature is invalid"):
            self.workflow.handle_action(headers, body)

    def test_deduplicates_identical_pending_requests(self) -> None:
        request = {
            "requester": "sre-oncall",
            "reason": "restart",
            "server": "platform-ops",
            "tool": "platform.restart_deployment",
            "arguments": {"actor": "sre-oncall"},
            "safe_arguments": {"actor": "sre-oncall"},
        }

        first = self.workflow.request(**request)
        second = self.workflow.request(**request)

        self.assertEqual(second["request_id"], first["request_id"])
        self.assertTrue(second["deduplicated"])

    def test_denial_returns_no_token_and_callback_replay_is_rejected(self) -> None:
        requested = self._request(arguments={"actor": "sre-oncall"})
        body, headers = self._signed_action(requested["request_id"], "deny", "U-ONCALL")

        response = self.workflow.handle_action(headers, body)
        status = self.workflow.status(requested["request_id"], "sre-oncall")

        self.assertIn("denied", response["text"])
        self.assertEqual(status["status"], "DENIED")
        self.assertNotIn("approval_token", status)
        with self.assertRaisesRegex(SlackApprovalError, "already DENIED"):
            self.workflow.handle_action(headers, body)

    def test_status_and_callback_expire_pending_requests(self) -> None:
        status_request = self._request(arguments={"sequence": 1})
        self.workflow._connection.execute(
            "UPDATE approval_requests SET expires_at = 0 WHERE request_id = ?",
            (status_request["request_id"],),
        )
        self.workflow._connection.commit()
        self.assertEqual(
            self.workflow.status(status_request["request_id"], "sre-oncall")["status"],
            "EXPIRED",
        )

        action_request = self._request(arguments={"sequence": 2})
        self.workflow._connection.execute(
            "UPDATE approval_requests SET expires_at = 0 WHERE request_id = ?",
            (action_request["request_id"],),
        )
        self.workflow._connection.commit()
        body, headers = self._signed_action(
            action_request["request_id"], "approve", "U-ONCALL"
        )
        with self.assertRaisesRegex(SlackApprovalError, "has expired"):
            self.workflow.handle_action(headers, body)
        self.assertEqual(
            self.workflow.status(action_request["request_id"], "sre-oncall")["status"],
            "EXPIRED",
        )

    def test_request_validates_identity_context_and_ttl(self) -> None:
        invalid = [
            ({"requester": " "}, "requester"),
            ({"reason": ""}, "reason"),
            ({"server": "\t"}, "server"),
            ({"tool": ""}, "tool"),
            ({"ttl_seconds": 59}, "TTL"),
            ({"ttl_seconds": 3601}, "TTL"),
        ]
        for overrides, message in invalid:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                SlackApprovalError, message
            ):
                self._request(**overrides)
        count = self.workflow._connection.execute(
            "SELECT COUNT(*) FROM approval_requests"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_pending_limit_is_per_requester(self) -> None:
        self.workflow.max_pending_per_requester = 1
        self._request(arguments={"sequence": 1})
        with self.assertRaisesRegex(SlackApprovalError, "pending Slack approval limit"):
            self._request(arguments={"sequence": 2})

        other = self._request(requester="other-user", arguments={"sequence": 3})
        self.assertEqual(other["status"], "PENDING")

    def test_concurrent_identical_requests_are_deduplicated_atomically(self) -> None:
        results: list[dict[str, object]] = []
        failures: list[Exception] = []

        def request() -> None:
            try:
                results.append(self._request(arguments={"same": True}))
            except Exception as exc:  # pragma: no cover - assertion captures failures
                failures.append(exc)

        threads = [threading.Thread(target=request) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(failures, [])
        self.assertEqual(len(results), 16)
        self.assertEqual({result["request_id"] for result in results}, {results[0]["request_id"]})
        self.assertEqual(self.workflow._notify.call_count, 1)

    def test_missing_malformed_stale_and_unknown_callbacks_fail_closed(self) -> None:
        requested = self._request()
        now = int(time.time())
        malformed_cases = [
            (
                "",
                {"x-slack-request-timestamp": "", "x-slack-signature": ""},
                "timestamp is invalid",
            ),
            ("payload=not-json", None, "payload is invalid"),
            (
                urllib.parse.urlencode(
                    {
                        "payload": json.dumps(
                            {
                                "user": {"id": "U-ONCALL"},
                                "actions": [{"value": "not-json"}],
                            }
                        )
                    }
                ),
                None,
                "payload is invalid",
            ),
        ]
        for body, explicit_headers, message in malformed_cases:
            headers = (
                explicit_headers
                if explicit_headers is not None
                else self._signed_headers(body, now)
            )
            with self.subTest(message=message), self.assertRaisesRegex(
                SlackApprovalError, message
            ):
                self.workflow.handle_action(headers, body)

        for timestamp in (now - 301, now + 301):
            body, _ = self._signed_action(
                requested["request_id"], "approve", "U-ONCALL", timestamp=timestamp
            )
            with self.assertRaisesRegex(SlackApprovalError, "outside the replay window"):
                self.workflow.handle_action(self._signed_headers(body, timestamp), body)

        invalid_decision, invalid_headers = self._signed_action(
            requested["request_id"], "maybe", "U-ONCALL"
        )
        with self.assertRaisesRegex(SlackApprovalError, "decision is invalid"):
            self.workflow.handle_action(invalid_headers, invalid_decision)

        unknown, unknown_headers = self._signed_action(
            "00000000-0000-0000-0000-000000000000", "approve", "U-ONCALL"
        )
        with self.assertRaisesRegex(SlackApprovalError, "was not found"):
            self.workflow.handle_action(unknown_headers, unknown)
        with self.assertRaisesRegex(SlackApprovalError, "was not found"):
            self.workflow.status("missing", "sre-oncall")

    def test_notification_failure_rolls_back_pending_row(self) -> None:
        self.workflow._notify.side_effect = SlackApprovalError("synthetic delivery failure")
        with self.assertRaisesRegex(SlackApprovalError, "synthetic delivery failure"):
            self._request()
        count = self.workflow._connection.execute(
            "SELECT COUNT(*) FROM approval_requests"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_webhook_payload_is_escaped_bounded_and_uses_configured_timeout(self) -> None:
        captured: list[tuple[object, float]] = []
        self.workflow._timeout_seconds = 1.25
        with patch(
            "judikt.slack_approval.urllib.request.urlopen",
            side_effect=lambda request, timeout: captured.append((request, timeout))
            or _Response(),
        ):
            SlackApprovalWorkflow._notify(
                self.workflow,
                "request-id",
                "user<&>",
                "reason<&>",
                "server<&>",
                "tool<&>",
                {"a_secret": "[REDACTED]", "payload": "<script>" + "x" * 3000},
            )

        request, timeout = captured[0]
        payload = json.loads(request.data)
        rendered = json.dumps(payload)
        self.assertEqual(timeout, 1.25)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.headers["Content-type"], "application/json")
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertLess(len(payload["blocks"][0]["text"]["text"]), 2200)

    def test_webhook_failures_are_normalized_without_leaking_secret_url(self) -> None:
        failures = [
            (_Response(500), "HTTP 500"),
            (
                urllib.error.HTTPError(
                    self.workflow.webhook_url,
                    503,
                    "private",
                    {},
                    None,
                ),
                "HTTP 503",
            ),
            (urllib.error.URLError("private network detail"), "unavailable"),
        ]
        for failure, message in failures:
            with self.subTest(message=message), patch(
                "judikt.slack_approval.urllib.request.urlopen",
                side_effect=failure if isinstance(failure, Exception) else None,
                return_value=failure if not isinstance(failure, Exception) else None,
            ), self.assertRaisesRegex(SlackApprovalError, message) as raised:
                SlackApprovalWorkflow._notify(
                    self.workflow,
                    "request-id",
                    "user",
                    "reason",
                    "server",
                    "tool",
                    {},
                )
            self.assertNotIn("hooks.slack.test", str(raised.exception))

    def test_configuration_rejects_unsafe_urls_and_invalid_limits(self) -> None:
        cases = [
            ({"JUDIKT_SLACK_WEBHOOK_URL": "http://hooks.slack.test/path"}, "HTTPS"),
            ({"JUDIKT_SLACK_WEBHOOK_URL": "ftp://hooks.slack.test/path"}, "absolute HTTP"),
            (
                {"JUDIKT_SLACK_WEBHOOK_URL": "https://user:pass@hooks.slack.test/path"},
                "must not contain",
            ),
            (
                {"JUDIKT_SLACK_WEBHOOK_URL": "https://hooks.slack.test/path?token=x"},
                "must not contain",
            ),
            ({"JUDIKT_SLACK_MAX_PENDING_PER_REQUESTER": "bad"}, "integer between"),
            ({"JUDIKT_SLACK_MAX_PENDING_PER_REQUESTER": "0"}, "integer between"),
            ({"JUDIKT_SLACK_MAX_PENDING_PER_REQUESTER": "101"}, "integer between"),
            ({"JUDIKT_SLACK_TIMEOUT_SECONDS": "0"}, "positive finite"),
            ({"JUDIKT_SLACK_TIMEOUT_SECONDS": "bad"}, "positive finite"),
            ({"JUDIKT_SLACK_TIMEOUT_SECONDS": "nan"}, "positive finite"),
        ]
        base = {
            "JUDIKT_SLACK_WEBHOOK_URL": "https://hooks.slack.test/services/example",
            "JUDIKT_SLACK_SIGNING_SECRET": "secret",
            "JUDIKT_SLACK_APPROVER_IDS": "U-ONCALL",
        }
        for index, (override, message) in enumerate(cases):
            with self.subTest(override=override), patch.dict(
                os.environ, {**base, **override}, clear=True
            ), self.assertRaisesRegex(SlackApprovalError, message):
                SlackApprovalWorkflow(
                    Path(self.temp_dir.name) / f"invalid-{index}.db",
                    self.authority,
                )

        with patch.dict(
            os.environ,
            {
                **base,
                "JUDIKT_SLACK_WEBHOOK_URL": "http://hooks.slack.test/path",
                "JUDIKT_SLACK_ALLOW_INSECURE_HTTP": "true",
            },
            clear=True,
        ):
            workflow = SlackApprovalWorkflow(
                Path(self.temp_dir.name) / "allowed-http.db", self.authority
            )
            workflow.close()

    def test_database_permission_hardening_is_best_effort(self) -> None:
        with patch("pathlib.Path.chmod", side_effect=OSError("unsupported filesystem")):
            workflow = SlackApprovalWorkflow(
                Path(self.temp_dir.name) / "chmod-fallback.db", self.authority
            )
        try:
            self.assertTrue(workflow.enabled)
        finally:
            workflow.close()

    def test_incomplete_configuration_disables_requests(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            workflow = SlackApprovalWorkflow(
                Path(self.temp_dir.name) / "disabled.db", self.authority
            )
            try:
                self.assertFalse(workflow.enabled)
                with self.assertRaisesRegex(SlackApprovalError, "Slack approvals require"):
                    workflow.request(
                        requester="user",
                        reason="reason",
                        server="server",
                        tool="tool",
                        arguments={},
                        safe_arguments={},
                    )
                with self.assertRaisesRegex(SlackApprovalError, "Slack approvals require"):
                    workflow.handle_action(
                        {
                            "x-slack-request-timestamp": str(int(time.time())),
                            "x-slack-signature": "v0=forged-with-empty-secret",
                        },
                        "payload={}",
                    )
            finally:
                workflow.close()

    def _request(self, **overrides: object) -> dict[str, object]:
        request: dict[str, object] = {
            "requester": "sre-oncall",
            "reason": "restart",
            "server": "platform-ops",
            "tool": "platform.restart_deployment",
            "arguments": {"actor": "sre-oncall"},
            "safe_arguments": {"actor": "sre-oncall"},
        }
        request.update(overrides)
        return self.workflow.request(**request)  # type: ignore[arg-type]

    @staticmethod
    def _signed_action(
        request_id: str,
        decision: str,
        user_id: str,
        *,
        timestamp: int | None = None,
    ) -> tuple[str, dict[str, str]]:
        payload = {
            "user": {"id": user_id},
            "actions": [
                {
                    "value": json.dumps({"request_id": request_id, "decision": decision}),
                }
            ],
        }
        body = urllib.parse.urlencode({"payload": json.dumps(payload)})
        observed_timestamp = int(time.time()) if timestamp is None else timestamp
        return body, SlackApprovalWorkflowTest._signed_headers(body, observed_timestamp)

    @staticmethod
    def _signed_headers(body: str, timestamp: int) -> dict[str, str]:
        rendered_timestamp = str(timestamp)
        base = f"v0:{rendered_timestamp}:{body}".encode()
        signature = "v0=" + hmac.new(
            b"slack-signing-secret", base, hashlib.sha256
        ).hexdigest()
        return {
            "x-slack-request-timestamp": rendered_timestamp,
            "x-slack-signature": signature,
        }


if __name__ == "__main__":
    unittest.main()
