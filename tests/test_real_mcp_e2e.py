from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import judikt
from judikt.auth import create_hs256_jwt
from judikt.paths import DEFAULT_POLICY_PATH


PROJECT_ROOT = Path(__file__).resolve().parents[1]
IDENTITY_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"
LIST_CHANGED_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "list_changed_mcp_server.py"


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class RealMCPStreamableHTTPEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        root = Path(cls.temp_dir.name)
        cls.port = _free_port()
        environment = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_HTTP_BEARER_TOKEN": "mcp-e2e-token",
            "JUDIKT_HTTP_BEARER_ROLE": "admin",
            "JUDIKT_APPROVAL_SECRET": "mcp-e2e-approval-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_HMAC_SECRET": "mcp-e2e-audit-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
            "JUDIKT_UPSTREAM_CONFIG": "",
            "JUDIKT_DEMO_MODE": "true",
            "JUDIKT_ALLOW_DIRECT_APPROVAL": "true",
            "GROQ_API_KEY": "",
        }
        cls.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(root / "audit.db"),
                "serve-real-mcp",
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
                "--log-level",
                "warning",
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.process.poll() is not None:
                stdout, stderr = cls.process.communicate(timeout=3)
                raise RuntimeError(f"real MCP server exited:\n{stdout}\n{stderr}")
            try:
                with urllib.request.urlopen(f"{cls.base_url}/healthz", timeout=1) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise RuntimeError("real MCP server did not become healthy")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.process.poll() is None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
        for stream in (cls.process.stdout, cls.process.stderr):
            if stream is not None:
                stream.close()
        cls.temp_dir.cleanup()

    def test_public_protected_authentication_origin_and_slack_boundaries(self) -> None:
        with urllib.request.urlopen(f"{self.base_url}/healthz", timeout=3) as response:
            health = json.load(response)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["auth"], "bearer")

        with urllib.request.urlopen(
            f"{self.base_url}/.well-known/oauth-protected-resource", timeout=3
        ) as response:
            metadata = json.load(response)
        self.assertEqual(metadata["resource"], f"{self.base_url}/mcp")
        self.assertEqual(
            metadata["scopes_supported"],
            ["mcp:read", "mcp:execute", "mcp:approve", "mcp:admin"],
        )

        for token in ("", "wrong-token"):
            request = urllib.request.Request(
                f"{self.base_url}/metrics",
                headers={"Authorization": f"Bearer {token}"} if token else {},
            )
            with self.subTest(token=token), self.assertRaises(
                urllib.error.HTTPError
            ) as raised:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(raised.exception.code, 401)
            self.assertIn("resource_metadata", raised.exception.headers["WWW-Authenticate"])
            raised.exception.close()

        invalid_origin = urllib.request.Request(
            f"{self.base_url}/metrics",
            headers={
                "Authorization": "Bearer mcp-e2e-token",
                "Origin": "https://attacker.invalid",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(invalid_origin, timeout=3)
        self.assertEqual(raised.exception.code, 403)
        raised.exception.close()

        metrics = urllib.request.Request(
            f"{self.base_url}/metrics",
            headers={"Authorization": "Bearer mcp-e2e-token"},
        )
        with urllib.request.urlopen(metrics, timeout=3) as response:
            self.assertIn("judikt_tool_calls_total", response.read().decode())

        callback = urllib.request.Request(
            f"{self.base_url}/integrations/slack/actions",
            data=urllib.parse.urlencode({"payload": "{}"}).encode(),
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(callback, timeout=3)
        self.assertEqual(raised.exception.code, 400)
        self.assertIn("Slack approvals require", raised.exception.read().decode())
        raised.exception.close()

    def test_every_published_mcp_tool_through_official_client(self) -> None:
        results = asyncio.run(self._exercise_every_tool())
        self.assertEqual(results["health"]["result"]["service"], "payments-api")
        self.assertEqual(results["config"]["result"]["api_key"], "[REDACTED]")
        self.assertEqual(len(results["logs"]["result"]["logs"]), 1)
        self.assertEqual(results["diagnostic"]["result"]["command"], "dependency-health")
        self.assertEqual(results["restart_dry_run"]["action"], "DRY_RUN_ONLY")
        self.assertFalse(results["restart_dry_run"]["result"]["executed"])
        self.assertEqual(results["rollback_shadow"]["action"], "SHADOW_MODE")
        self.assertEqual(results["pod"]["result"]["status"], "Running")
        self.assertEqual(results["pod_restart_dry_run"]["action"], "DRY_RUN_ONLY")
        self.assertEqual(results["rollout"]["result"]["status"], "healthy")
        self.assertEqual(results["incident_timeline"]["result"]["id"], results["incident_id"])
        self.assertEqual(len(results["incident_timeline"]["result"]["timeline"]), 2)
        self.assertEqual(results["unknown_upstream"]["rule"], "unknown_external_server")
        self.assertEqual(results["approval_request"]["status"], "ERROR")
        self.assertEqual(results["approval_status"]["status"], "ERROR")
        self.assertTrue(
            results["approved_restart"]["allowed"], results["approved_restart"]
        )
        self.assertEqual(results["approved_restart"]["result"]["status"], "completed")
        self.assertEqual(results["killed_health"]["rule"], "kill_switch")
        self.assertIn("platform.health", results["disabled_tool"]["disabled_tools"])
        self.assertIn("incident", results["disabled_server"]["disabled_servers"])
        self.assertTrue(results["runtime_state"]["audit_integrity"]["valid"])
        self.assertEqual(results["runtime_state"]["rate_limiter"]["mode"], "local")

    async def _exercise_every_tool(self) -> dict[str, object]:
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        results: dict[str, object] = {}
        async with httpx.AsyncClient(
            headers={"Authorization": "Bearer mcp-e2e-token"}, timeout=10
        ) as http_client:
            async with streamable_http_client(
                f"{self.base_url}/mcp", http_client=http_client
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    self.assertTrue(initialized.protocolVersion)
                    self.assertEqual(initialized.serverInfo.version, judikt.__version__)
                    listed = await session.list_tools()
                    names = {tool.name for tool in listed.tools}
                    expected = {
                        "platform.health",
                        "platform.read_config",
                        "platform.read_logs",
                        "platform.run_diagnostic",
                        "platform.restart_deployment",
                        "platform.rollback_deployment",
                        "kubernetes.get_pod",
                        "kubernetes.restart_pod",
                        "kubernetes.rollout_status",
                        "incident.create",
                        "incident.attach_evidence",
                        "incident.timeline",
                        "judikt.issue_approval",
                        "judikt.request_approval",
                        "judikt.approval_status",
                        "judikt.call_upstream",
                        "judikt.set_tool_enabled",
                        "judikt.set_server_enabled",
                        "judikt.runtime_state",
                    }
                    self.assertEqual(names, expected)

                    async def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
                        response = await session.call_tool(name, arguments)
                        payload = response.structuredContent
                        self.assertIsInstance(payload, dict, f"{name}: {response}")
                        refused = payload.get("allowed") is False or payload.get("status") == "ERROR"
                        # A refusal must reach MCP clients as a tool error.
                        self.assertEqual(response.isError, refused, f"{name}: {response}")
                        return payload

                    results["health"] = await call("platform.health", {"service": "payments-api"})
                    results["config"] = await call("platform.read_config", {"service": "payments-api"})
                    results["logs"] = await call(
                        "platform.read_logs",
                        {"service": "payments-api", "query": "status=503", "limit": 1},
                    )
                    results["diagnostic"] = await call(
                        "platform.run_diagnostic",
                        {"service": "payments-api", "command": "dependency-health"},
                    )
                    results["restart_dry_run"] = await call(
                        "platform.restart_deployment",
                        {
                            "service": "payments-api",
                            "actor": "sre-oncall",
                            "rollback_plan": "verify health then restore the previous deployment",
                            "dry_run": True,
                        },
                    )
                    results["rollback_shadow"] = await call(
                        "platform.rollback_deployment",
                        {
                            "service": "payments-api",
                            "version": "payments-api@stable",
                            "actor": "sre-oncall",
                            "rollback_plan": "verify health then restore the previous deployment",
                            "shadow_mode": True,
                        },
                    )
                    results["pod"] = await call(
                        "kubernetes.get_pod",
                        {"namespace": "prod", "pod": "payment-service-xyz"},
                    )
                    results["pod_restart_dry_run"] = await call(
                        "kubernetes.restart_pod",
                        {
                            "namespace": "prod",
                            "pod": "payment-service-xyz",
                            "idempotency_key": "real-mcp-e2e-dry-run",
                            "actor": "sre-oncall",
                            "rollback_plan": "wait for replacement and restore workload if readiness fails",
                            "dry_run": True,
                        },
                    )
                    results["rollout"] = await call(
                        "kubernetes.rollout_status",
                        {"namespace": "prod", "deployment": "payment-service"},
                    )
                    created = await call(
                        "incident.create", {"title": "MCP E2E", "severity": "SEV-3"}
                    )
                    incident_id = str(created["result"]["id"])
                    results["incident_id"] = incident_id
                    await call(
                        "incident.attach_evidence",
                        {"incident_id": incident_id, "evidence": {"correlation_id": "e2e"}},
                    )
                    results["incident_timeline"] = await call(
                        "incident.timeline", {"incident_id": incident_id}
                    )
                    results["unknown_upstream"] = await call(
                        "judikt.call_upstream",
                        {"server": "missing", "tool": "missing.tool", "arguments": {}},
                    )
                    results["approval_request"] = await call(
                        "judikt.request_approval",
                        {
                            "actor": "sre-oncall",
                            "reason": "test disabled Slack flow",
                            "server": "platform-ops",
                            "tool": "platform.restart_deployment",
                            "arguments": {},
                        },
                    )
                    results["approval_status"] = await call(
                        "judikt.approval_status",
                        {"request_id": "missing", "actor": "sre-oncall"},
                    )

                    restart_arguments = {
                        "service": "payments-api",
                        "actor": "sre-oncall",
                        "environment": "production",
                        "rollback_plan": "verify health then restore the previous deployment",
                    }
                    approval = await call(
                        "judikt.issue_approval",
                        {
                            "actor": "sre-oncall",
                            "reason": "approved E2E restart",
                            "server": "platform-ops",
                            "tool": "platform.restart_deployment",
                            "arguments": restart_arguments,
                        },
                    )
                    results["approved_restart"] = await call(
                        "platform.restart_deployment",
                        {**restart_arguments, "approval_token": approval["approval_token"]},
                    )

                    results["disabled_tool"] = await call(
                        "judikt.set_tool_enabled",
                        {"tool": "platform.health", "enabled": False},
                    )
                    results["killed_health"] = await call(
                        "platform.health", {"service": "payments-api"}
                    )
                    await call(
                        "judikt.set_tool_enabled",
                        {"tool": "platform.health", "enabled": True},
                    )
                    results["disabled_server"] = await call(
                        "judikt.set_server_enabled",
                        {"server": "incident", "enabled": False},
                    )
                    await call(
                        "judikt.set_server_enabled",
                        {"server": "incident", "enabled": True},
                    )
                    results["runtime_state"] = await call(
                        "judikt.runtime_state", {"limit": 100}
                    )
        return results


class RealMCPJWTAuthorizationEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        root = Path(cls.temp_dir.name)
        cls.port = _free_port()
        cls.issuer = "https://issuer.judikt.test"
        cls.audience = "judikt-e2e"
        cls.jwt_secret = "jwt-e2e-signing-secret"
        environment = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_JWT_HS256_SECRET": cls.jwt_secret,
            "JUDIKT_JWT_ISSUER": cls.issuer,
            "JUDIKT_JWT_AUDIENCE": cls.audience,
            "JUDIKT_AUTHORIZATION_SERVER": cls.issuer,
            "JUDIKT_RESOURCE_URI": f"http://127.0.0.1:{cls.port}/mcp",
            "JUDIKT_REQUIRED_SCOPES": "mcp:tools",
            "JUDIKT_ADMIN_SCOPE": "mcp:admin",
            "JUDIKT_APPROVAL_SECRET": "jwt-e2e-approval-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_HMAC_SECRET": "jwt-e2e-audit-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
            "JUDIKT_UPSTREAM_CONFIG": "",
            "JUDIKT_DEMO_MODE": "true",
            "JUDIKT_ALLOW_DIRECT_APPROVAL": "false",
        }
        cls.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(root / "audit.db"),
                "serve-real-mcp",
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
                "--log-level",
                "warning",
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.process.poll() is not None:
                stdout, stderr = cls.process.communicate(timeout=3)
                raise RuntimeError(f"JWT MCP server exited:\n{stdout}\n{stderr}")
            try:
                with urllib.request.urlopen(f"{cls.base_url}/healthz", timeout=1):
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise RuntimeError("JWT MCP server did not become healthy")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.process.poll() is None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
        for stream in (cls.process.stdout, cls.process.stderr):
            if stream is not None:
                stream.close()
        cls.temp_dir.cleanup()

    def test_jwt_subject_binding_scope_and_admin_authorization(self) -> None:
        now = int(time.time())
        operator = create_hs256_jwt(
            {
                "sub": "readonly",
                "iss": self.issuer,
                "aud": self.audience,
                "exp": now + 300,
                "scope": "mcp:tools",
            },
            self.jwt_secret,
        )
        admin = create_hs256_jwt(
            {
                "sub": "platform-admin",
                "iss": self.issuer,
                "aud": self.audience,
                "exp": now + 300,
                "scope": "mcp:tools mcp:admin",
            },
            self.jwt_secret,
        )
        wrong_audience = create_hs256_jwt(
            {
                "sub": "platform-admin",
                "iss": self.issuer,
                "aud": "wrong-resource",
                "exp": now + 300,
                "scope": "mcp:tools mcp:admin",
            },
            self.jwt_secret,
        )

        denied_request = urllib.request.Request(
            f"{self.base_url}/metrics",
            headers={"Authorization": f"Bearer {wrong_audience}"},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(denied_request, timeout=3)
        self.assertEqual(raised.exception.code, 401)
        raised.exception.close()

        operator_results = asyncio.run(self._operator_calls(operator))
        self.assertTrue(operator_results["health"]["allowed"])
        self.assertEqual(operator_results["spoofed_restart"]["rule"], "identity_mismatch")
        self.assertEqual(operator_results["admin_action"]["rule"], "admin_authorization")
        self.assertEqual(operator_results["runtime_state"]["rule"], "admin_authorization")

        admin_results = asyncio.run(self._admin_calls(admin))
        self.assertEqual(admin_results["direct_approval"]["rule"], "human_approval_required")
        self.assertIn("platform.health", admin_results["disabled"]["disabled_tools"])
        self.assertEqual(admin_results["killed_health"]["rule"], "kill_switch")
        self.assertNotIn("platform.health", admin_results["enabled"]["disabled_tools"])
        self.assertTrue(admin_results["runtime_state"]["audit_integrity"]["valid"])

    async def _operator_calls(self, token: str) -> dict[str, dict[str, object]]:
        return await self._jwt_calls(
            token,
            [
                ("health", "platform.health", {"service": "payments-api"}),
                (
                    "spoofed_restart",
                    "platform.restart_deployment",
                    {
                        "service": "payments-api",
                        "actor": "sre-oncall",
                        "rollback_plan": "restore prior release",
                        "dry_run": True,
                    },
                ),
                (
                    "admin_action",
                    "judikt.set_tool_enabled",
                    {"tool": "platform.health", "enabled": False},
                ),
                ("runtime_state", "judikt.runtime_state", {}),
            ],
        )

    async def _admin_calls(self, token: str) -> dict[str, dict[str, object]]:
        return await self._jwt_calls(
            token,
            [
                (
                    "direct_approval",
                    "judikt.issue_approval",
                    {
                        "actor": "platform-admin",
                        "reason": "should require human approval",
                        "server": "platform-ops",
                        "tool": "platform.restart_deployment",
                        "arguments": {},
                    },
                ),
                (
                    "disabled",
                    "judikt.set_tool_enabled",
                    {"tool": "platform.health", "enabled": False},
                ),
                ("killed_health", "platform.health", {"service": "payments-api"}),
                (
                    "enabled",
                    "judikt.set_tool_enabled",
                    {"tool": "platform.health", "enabled": True},
                ),
                ("runtime_state", "judikt.runtime_state", {}),
            ],
        )

    async def _jwt_calls(
        self,
        token: str,
        calls: list[tuple[str, str, dict[str, object]]],
    ) -> dict[str, dict[str, object]]:
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        results: dict[str, dict[str, object]] = {}
        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=10
        ) as http_client:
            async with streamable_http_client(
                f"{self.base_url}/mcp", http_client=http_client
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    for key, name, arguments in calls:
                        response = await session.call_tool(name, arguments)
                        self.assertIsInstance(response.structuredContent, dict)
                        refused = (
                            response.structuredContent.get("allowed") is False
                            or response.structuredContent.get("status") == "ERROR"
                        )
                        # A refusal must reach MCP clients as a tool error.
                        self.assertEqual(response.isError, refused, f"{name}: {response}")
                        results[key] = response.structuredContent
        return results


class RealMCPDefaultPolicyIdentityEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        root = Path(cls.temp_dir.name)
        cls.port = _free_port()
        cls.issuer = "https://issuer.judikt.default-policy.test"
        cls.audience = "judikt-default-policy-e2e"
        cls.jwt_secret = "default-policy-jwt-secret"

        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        policy["allowed_tools"] = {"external-identities": ["external.get_user"]}
        policy["actor_permissions"] = {
            "alice": ["external.get_user"],
            "local-operator": [],
            "anonymous": [],
        }
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy))

        upstream_path = root / "upstreams.json"
        upstream_path.write_text(
            json.dumps(
                {
                    "servers": {
                        "external-identities": {
                            "command": [
                                sys.executable,
                                str(IDENTITY_FIXTURE),
                                "identity-fields",
                            ]
                        }
                    }
                }
            )
        )
        environment = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_HTTP_BEARER_TOKEN": "",
            "JUDIKT_JWT_HS256_SECRET": cls.jwt_secret,
            "JUDIKT_JWT_ISSUER": cls.issuer,
            "JUDIKT_JWT_AUDIENCE": cls.audience,
            "JUDIKT_AUTHORIZATION_SERVER": cls.issuer,
            "JUDIKT_RESOURCE_URI": f"http://127.0.0.1:{cls.port}/mcp",
            "JUDIKT_REQUIRED_SCOPES": "mcp:tools",
            "JUDIKT_APPROVAL_SECRET": "default-policy-approval-secret-32-bytes-minimum",
            "JUDIKT_AUDIT_HMAC_SECRET": "default-policy-audit-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
            "JUDIKT_UPSTREAM_CONFIG": str(upstream_path),
            "JUDIKT_DEMO_MODE": "",
        }
        cls.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "--policy",
                str(policy_path),
                "--audit-db",
                str(root / "audit.db"),
                "serve-real-mcp",
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
                "--log-level",
                "warning",
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.process.poll() is not None:
                stdout, stderr = cls.process.communicate(timeout=3)
                raise RuntimeError(f"default-policy MCP server exited:\n{stdout}\n{stderr}")
            try:
                with urllib.request.urlopen(f"{cls.base_url}/healthz", timeout=1):
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise RuntimeError("default-policy MCP server did not become healthy")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.process.poll() is None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
        for stream in (cls.process.stdout, cls.process.stderr):
            if stream is not None:
                stream.close()
        cls.temp_dir.cleanup()

    def test_authenticated_subject_does_not_conflict_with_user_business_argument(self) -> None:
        token = create_hs256_jwt(
            {
                "sub": "alice",
                "iss": self.issuer,
                "aud": self.audience,
                "exp": int(time.time()) + 300,
                "scope": "mcp:tools",
            },
            self.jwt_secret,
        )

        result = asyncio.run(self._call_native_tools(token))

        self.assertEqual(
            result["allowed"]["received_arguments"],
            {"user": "octocat"},
        )
        self.assertEqual(result["allowed_rule"], "allow")
        self.assertTrue(result["denied_is_error"])
        self.assertEqual(result["denied_rule"], "allowlist")

    async def _call_native_tools(self, token: str) -> dict[str, object]:
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=10
        ) as http_client:
            async with streamable_http_client(
                f"{self.base_url}/mcp", http_client=http_client
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    native = {tool.name: tool for tool in listed.tools}
                    self.assertIn("external.get_user", native)
                    self.assertNotIn("judikt.call_upstream", native)
                    self.assertEqual(
                        native["external.get_user"].inputSchema["required"],
                        ["user"],
                    )
                    allowed = await session.call_tool(
                        "external.get_user", {"user": "octocat"}
                    )
                    denied = await session.call_tool(
                        "external.fetch_issue", {"issue_id": "INC-1"}
                    )
                    self.assertFalse(allowed.isError, allowed)
                    self.assertIsInstance(allowed.structuredContent, dict)
                    return {
                        "allowed": allowed.structuredContent,
                        "allowed_rule": allowed.meta["io.judikt/decision"]["rule"],
                        "denied_is_error": denied.isError,
                        "denied_rule": denied.meta["io.judikt/decision"]["rule"],
                    }


class RealMCPNativeListChangedEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        root = Path(cls.temp_dir.name)
        cls.port = _free_port()
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        tools = ["dynamic.trigger", "dynamic.added"]
        policy["allowed_tools"] = {"dynamic": tools}
        policy["actor_permissions"] = {"anonymous": tools, "local-operator": []}
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy))
        upstream_path = root / "upstreams.json"
        upstream_path.write_text(
            json.dumps(
                {
                    "servers": {
                        "dynamic": {
                            "command": [
                                sys.executable,
                                str(LIST_CHANGED_FIXTURE),
                                "add",
                            ]
                        }
                    }
                }
            )
        )
        environment = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_HTTP_BEARER_TOKEN": "native-catalog-token",
            "JUDIKT_APPROVAL_SECRET": "native-catalog-approval-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_HMAC_SECRET": "native-catalog-audit-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
            "JUDIKT_UPSTREAM_CONFIG": str(upstream_path),
            "JUDIKT_DEMO_MODE": "",
        }
        cls.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "--policy",
                str(policy_path),
                "--audit-db",
                str(root / "audit.db"),
                "serve-real-mcp",
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
                "--log-level",
                "warning",
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.process.poll() is not None:
                stdout, stderr = cls.process.communicate(timeout=3)
                raise RuntimeError(f"native MCP server exited:\n{stdout}\n{stderr}")
            try:
                with urllib.request.urlopen(f"{cls.base_url}/healthz", timeout=1):
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise RuntimeError("native MCP server did not become healthy")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.process.poll() is None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
        for stream in (cls.process.stdout, cls.process.stderr):
            if stream is not None:
                stream.close()
        cls.temp_dir.cleanup()

    def test_native_catalog_refreshes_and_notifies_official_client(self) -> None:
        asyncio.run(self._exercise_list_changed())

    async def _exercise_list_changed(self) -> None:
        import httpx
        from mcp import ClientSession, types
        from mcp.client.streamable_http import streamable_http_client

        changed = asyncio.Event()

        async def handle(message: object) -> None:
            if isinstance(message, types.ServerNotification) and isinstance(
                message.root, types.ToolListChangedNotification
            ):
                changed.set()

        async with httpx.AsyncClient(
            headers={"Authorization": "Bearer native-catalog-token"}, timeout=10
        ) as http_client:
            async with streamable_http_client(
                f"{self.base_url}/mcp", http_client=http_client
            ) as (read_stream, write_stream, _):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    message_handler=handle,
                ) as session:
                    initialized = await session.initialize()
                    self.assertTrue(initialized.capabilities.tools.listChanged)
                    initial = await session.list_tools()
                    self.assertIn(
                        "dynamic.trigger", {tool.name for tool in initial.tools}
                    )
                    self.assertNotIn(
                        "dynamic.added", {tool.name for tool in initial.tools}
                    )
                    triggered = await session.call_tool("dynamic.trigger", {})
                    self.assertFalse(triggered.isError, triggered)
                    await asyncio.wait_for(changed.wait(), timeout=3)
                    refreshed = await session.list_tools()
                    self.assertIn(
                        "dynamic.added", {tool.name for tool in refreshed.tools}
                    )
                    added = await session.call_tool("dynamic.added", {})
                    self.assertFalse(added.isError, added)
                    self.assertEqual(
                        added.structuredContent, {"tool": "dynamic.added"}
                    )


if __name__ == "__main__":
    unittest.main()
