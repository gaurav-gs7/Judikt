from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

from judikt.approval import ApprovalAuthority
from judikt.audit import AuditStore
from judikt.ops_runtime import JudiktOpsRuntime
from judikt.secrets import read_vault_secret
from judikt.slack_approval import SlackApprovalWorkflow


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "config" / "policies.yaml"


class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def _http_server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class Tier3HTTPIntegrationTest(unittest.TestCase):
    def test_vault_kv_v2_contract_over_real_http(self) -> None:
        observed: list[dict[str, object]] = []

        class VaultHandler(_QuietHandler):
            def do_GET(self) -> None:
                observed.append(
                    {
                        "path": self.path,
                        "token": self.headers.get("X-Vault-Token"),
                        "namespace": self.headers.get("X-Vault-Namespace"),
                        "accept": self.headers.get("Accept"),
                    }
                )
                body = json.dumps(
                    {"data": {"data": {"api_token": "real-http-vault-secret"}}}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with _http_server(VaultHandler) as address, patch.dict(
            os.environ,
            {
                "JUDIKT_VAULT_ADDR": address,
                "JUDIKT_VAULT_TOKEN": "vault-client-token",
                "JUDIKT_VAULT_NAMESPACE": "platform-team",
                "JUDIKT_SECRET_TIMEOUT_SECONDS": "1",
            },
            clear=True,
        ):
            value = read_vault_secret("secret/data/judikt/service", "api_token")

        self.assertEqual(value, "real-http-vault-secret")
        self.assertEqual(observed[0]["path"], "/v1/secret/data/judikt/service")
        self.assertEqual(observed[0]["token"], "vault-client-token")
        self.assertEqual(observed[0]["namespace"], "platform-team")
        self.assertEqual(observed[0]["accept"], "application/json")

    def test_real_runtime_redacts_and_signs_siem_event_over_http(self) -> None:
        observed: list[dict[str, object]] = []

        class SiemHandler(_QuietHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                observed.append(
                    {
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "event_hash": self.headers.get("X-Judikt-Event-SHA256"),
                        "signature": self.headers.get("X-Judikt-Signature-256"),
                        "body": body,
                    }
                )
                self.send_response(202)
                self.end_headers()

        with tempfile.TemporaryDirectory() as directory, _http_server(
            SiemHandler
        ) as address, patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": "audit-chain-secret-with-at-least-32-bytes",
                "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                "JUDIKT_AUDIT_SINK": "siem",
                "JUDIKT_AUDIT_SINK_STRICT": "true",
                "JUDIKT_SIEM_URL": f"{address}/events",
                "JUDIKT_SIEM_TOKEN": "siem-token",
                "JUDIKT_SIEM_HMAC_SECRET": "siem-body-secret",
                "JUDIKT_SIEM_TIMEOUT_SECONDS": "1",
            },
            clear=True,
        ):
            runtime = JudiktOpsRuntime(
                POLICY,
                Path(directory) / "audit.db",
                include_demo_servers=True,
            )
            try:
                result = runtime.call_tool(
                    "platform-ops",
                    "platform.read_config",
                    {"service": "payments-api"},
                )
                integrity = runtime.audit_integrity()
            finally:
                runtime.close()

        self.assertTrue(result.allowed)
        self.assertEqual(result.result["api_key"], "[REDACTED]")
        self.assertEqual(integrity["sink"], "siem")
        self.assertTrue(integrity["valid"])
        self.assertTrue(integrity["signed"])
        request = observed[0]
        body = request["body"]
        payload = json.loads(body)
        self.assertEqual(request["path"], "/events")
        self.assertEqual(request["authorization"], "Bearer siem-token")
        self.assertEqual(request["event_hash"], hashlib.sha256(body).hexdigest())
        expected_signature = hmac.new(
            b"siem-body-secret", body, hashlib.sha256
        ).hexdigest()
        self.assertEqual(request["signature"], f"sha256={expected_signature}")
        self.assertEqual(payload["event"]["result"]["api_key"], "[REDACTED]")
        self.assertNotIn("sk-demo-sensitive-value", body.decode())
        self.assertEqual(len(payload["event"]["event_hash"]), 64)
        self.assertEqual(len(payload["event"]["signature"]), 64)

    def test_concurrent_audit_writers_deliver_one_valid_chained_event_each(self) -> None:
        observed: list[dict[str, object]] = []
        observed_lock = threading.Lock()

        class SiemHandler(_QuietHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with observed_lock:
                    observed.append(json.loads(body)["event"])
                self.send_response(200)
                self.end_headers()

        with tempfile.TemporaryDirectory() as directory, _http_server(
            SiemHandler
        ) as address, patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": "audit-chain-secret-with-at-least-32-bytes",
                "JUDIKT_AUDIT_SINK": "siem",
                "JUDIKT_AUDIT_SINK_STRICT": "true",
                "JUDIKT_SIEM_URL": f"{address}/events",
                "JUDIKT_SIEM_TOKEN": "siem-token",
            },
            clear=True,
        ):
            store = AuditStore(Path(directory) / "audit.db")
            failures: list[Exception] = []

            def record(index: int) -> None:
                try:
                    store.record(
                        correlation_id=f"corr-{index}",
                        server="platform-ops",
                        tool="platform.health",
                        allowed=True,
                        rule="allow",
                        reason="allowed",
                        arguments={"sequence": index},
                        result={"ok": True},
                        duration_ms=index,
                    )
                except Exception as exc:  # pragma: no cover - assertion captures failures
                    failures.append(exc)

            threads = [threading.Thread(target=record, args=(index,)) for index in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            integrity = store.verify_chain()
            store.close()

        self.assertEqual(failures, [])
        self.assertEqual(len(observed), 16)
        self.assertEqual({event["correlation_id"] for event in observed}, {f"corr-{i}" for i in range(16)})
        self.assertEqual(len({event["event_hash"] for event in observed}), 16)
        self.assertTrue(integrity["valid"], integrity["errors"])
        self.assertEqual(integrity["checked_events"], 16)

    def test_slack_notification_and_signed_callback_over_real_http(self) -> None:
        observed: list[dict[str, object]] = []

        class SlackHandler(_QuietHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                observed.append(
                    {
                        "path": self.path,
                        "content_type": self.headers.get("Content-Type"),
                        "payload": json.loads(body),
                    }
                )
                self.send_response(200)
                self.end_headers()

        with tempfile.TemporaryDirectory() as directory, _http_server(
            SlackHandler
        ) as address, patch.dict(
            os.environ,
            {
                "JUDIKT_SLACK_WEBHOOK_URL": f"{address}/slack-webhook",
                "JUDIKT_SLACK_SIGNING_SECRET": "slack-signing-secret",
                "JUDIKT_SLACK_APPROVER_IDS": "U-ONCALL",
                "JUDIKT_SLACK_TIMEOUT_SECONDS": "1",
            },
            clear=True,
        ):
            authority = ApprovalAuthority("approval-secret-at-least-32-bytes")
            workflow = SlackApprovalWorkflow(
                Path(directory) / "approvals.db", authority
            )
            try:
                arguments = {"service": "payments-api", "actor": "sre-oncall"}
                requested = workflow.request(
                    requester="sre-oncall",
                    reason="error rate <script>",
                    server="platform-ops",
                    tool="platform.restart_deployment",
                    arguments=arguments,
                    safe_arguments=arguments,
                )
                body = urllib.parse.urlencode(
                    {
                        "payload": json.dumps(
                            {
                                "user": {"id": "U-ONCALL"},
                                "actions": [
                                    {
                                        "value": json.dumps(
                                            {
                                                "request_id": requested["request_id"],
                                                "decision": "approve",
                                            }
                                        )
                                    }
                                ],
                            }
                        )
                    }
                )
                timestamp = str(int(time.time()))
                signature = "v0=" + hmac.new(
                    b"slack-signing-secret",
                    f"v0:{timestamp}:{body}".encode(),
                    hashlib.sha256,
                ).hexdigest()
                workflow.handle_action(
                    {
                        "x-slack-request-timestamp": timestamp,
                        "x-slack-signature": signature,
                    },
                    body,
                )
                status = workflow.status(requested["request_id"], "sre-oncall")
            finally:
                workflow.close()

        self.assertEqual(status["status"], "APPROVED")
        authority.verify(
            token=status["approval_token"],
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments=arguments,
        )
        self.assertEqual(observed[0]["path"], "/slack-webhook")
        self.assertEqual(observed[0]["content_type"], "application/json")
        rendered = json.dumps(observed[0]["payload"])
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
