from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from judikt.http_app import DashboardServer


class _Audit:
    def recent(self) -> list[dict[str, object]]:
        return []


class _Runtime:
    audit = _Audit()

    def evaluate_tool(self, server: str, tool: str, arguments: dict[str, object]):
        del server, tool, arguments
        return _Result()


class _Result:
    allowed = True

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": True,
            "action": "PROPOSE_ONLY",
            "result": {"executed": False, "mode": "proposal_only"},
        }


class DashboardAuthenticationTest(unittest.TestCase):
    def test_non_loopback_binding_requires_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "JUDIKT_API_TOKEN"):
            DashboardServer(("0.0.0.0", 0), _Runtime())  # type: ignore[arg-type]

    def test_health_is_public_but_api_requires_bearer_token(self) -> None:
        server = DashboardServer(
            ("127.0.0.1", 0),
            _Runtime(),  # type: ignore[arg-type]
            api_token="integration-secret",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(f"{base_url}/healthz", timeout=3) as response:
                self.assertEqual(json.load(response), {"status": "ok"})

            with self.assertRaises(urllib.error.HTTPError) as unauthorized:
                urllib.request.urlopen(f"{base_url}/api/events", timeout=3)
            self.assertEqual(unauthorized.exception.code, 401)
            self.assertEqual(
                unauthorized.exception.headers["WWW-Authenticate"],
                "Bearer",
            )
            unauthorized.exception.close()

            request = urllib.request.Request(
                f"{base_url}/api/events",
                headers={"Authorization": "Bearer integration-secret"},
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(json.load(response), [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_evaluate_endpoint_is_policy_only(self) -> None:
        server = DashboardServer(
            ("127.0.0.1", 0),
            _Runtime(),  # type: ignore[arg-type]
            api_token="integration-secret",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/api/evaluate",
            data=json.dumps(
                {
                    "server": "argus-ai",
                    "tool": "argus.propose_remediation",
                    "arguments": {"action_type": "collect_diagnostics"},
                }
            ).encode(),
            headers={
                "Authorization": "Bearer integration-secret",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                payload = json.load(response)
            self.assertEqual(payload["action"], "PROPOSE_ONLY")
            self.assertFalse(payload["result"]["executed"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_privileged_posts_require_configured_token_even_on_loopback(self) -> None:
        server = DashboardServer(("127.0.0.1", 0), _Runtime())  # type: ignore[arg-type]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path in ("/api/approval", "/api/kill-switch"):
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}{path}",
                    data=b"{}",
                    method="POST",
                )
                with self.subTest(path=path), self.assertRaises(
                    urllib.error.HTTPError
                ) as raised:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(raised.exception.code, 503)
                self.assertIn("JUDIKT_API_TOKEN is not configured", raised.exception.read().decode())
                raised.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_privileged_posts_reject_missing_or_wrong_token(self) -> None:
        server = DashboardServer(
            ("127.0.0.1", 0),
            _Runtime(),  # type: ignore[arg-type]
            api_token="dashboard-secret",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for authorization in ("", "Bearer wrong"):
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/approval",
                    data=b"{}",
                    headers={"Authorization": authorization},
                    method="POST",
                )
                with self.subTest(authorization=authorization), self.assertRaises(
                    urllib.error.HTTPError
                ) as raised:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(raised.exception.code, 401)
                raised.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
