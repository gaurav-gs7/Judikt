from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from judikt.paths import DEFAULT_POLICY_PATH
from judikt.protocol import StdioMCPClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"


class WrapEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.audit_path = root / "audit.db"
        self.client = StdioMCPClient(
            "judikt-wrap",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(self.audit_path),
                "wrap",
                "--name",
                "external-incidents",
                "--",
                sys.executable,
                str(FIXTURE),
                "identity-fields",
            ],
            environment={
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "JUDIKT_APPROVAL_SECRET": "wrap-test-approval-secret-at-least-32-bytes",
                "JUDIKT_AUDIT_HMAC_SECRET": "wrap-test-audit",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
                "JUDIKT_UPSTREAM_CONFIG": str(root / "must-not-be-loaded.json"),
            },
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )

    def tearDown(self) -> None:
        self.client.close()
        self.temp_dir.cleanup()

    def test_wrap_discovers_proxies_guards_and_audits_upstream(self) -> None:
        tools = self.client.list_tools()
        self.assertEqual(
            [tool["name"] for tool in tools],
            [
                "external.fetch_issue",
                "external.get_user",
                "external.record_request",
            ],
        )

        user_lookup = self.client.call_tool(
            "external.get_user",
            {"user": "octocat"},
        )
        lookup_with_actor = self.client.call_tool(
            "external.get_user",
            {"user": "octocat", "actor": "gaurav"},
        )
        requested = self.client.call_tool(
            "external.record_request",
            {"requested_by": "release-manager"},
        )
        blocked = self.client.call_tool(
            "external.fetch_issue",
            {"issue_id": "/home/operator/.ssh/id_rsa"},
        )

        self.assertTrue(user_lookup["allowed"])
        self.assertEqual(
            user_lookup["result"]["received_arguments"],
            {"user": "octocat"},
        )
        self.assertTrue(lookup_with_actor["allowed"])
        self.assertEqual(
            lookup_with_actor["result"]["received_arguments"],
            {"user": "octocat", "actor": "gaurav"},
        )
        self.assertTrue(requested["allowed"])
        self.assertEqual(
            requested["result"]["received_arguments"],
            {"requested_by": "release-manager"},
        )
        self.assertTrue(blocked["blocked"])
        self.assertIn("blocked security pattern", blocked["reason"])

        connection = sqlite3.connect(self.audit_path)
        try:
            rows = connection.execute(
                "SELECT allowed, arguments_json FROM audit_events ORDER BY id"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual([row[0] for row in rows], [1, 1, 1, 0])
        self.assertEqual(json.loads(rows[0][1]), {"user": "octocat"})
        self.assertEqual(
            json.loads(rows[1][1]),
            {"actor": "gaurav", "user": "octocat"},
        )
        self.assertEqual(
            json.loads(rows[2][1]),
            {"requested_by": "release-manager"},
        )

    def test_wrap_does_not_load_configured_or_demo_servers(self) -> None:
        names = {tool["name"] for tool in self.client.list_tools()}
        self.assertNotIn("platform.health", names)
        self.assertNotIn("kubernetes.get_pod", names)
        self.assertNotIn("incident.create", names)


class WrapCLITest(unittest.TestCase):
    def test_missing_command_fails_without_traceback(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "judikt.cli", "wrap"],
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("upstream command is required", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class WrapProfileEndToEndTest(unittest.TestCase):
    def test_read_only_allows_reads_and_denies_before_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            call_log = root / "calls.jsonl"
            process = self._start_wrap(root, call_log, "read-only")
            try:
                self._request(process, "initialize", {})
                tools = self._request(process, "tools/list", {})["tools"]
                allowed = self._request(
                    process,
                    "tools/call",
                    {"name": "read_file", "arguments": {"target": "README.md"}},
                )["structuredContent"]
                denied = self._request(
                    process,
                    "tools/call",
                    {"name": "delete_repo", "arguments": {"target": "prod-infra"}},
                )["structuredContent"]
            finally:
                stderr = self._stop(process)

            self.assertEqual([tool["name"] for tool in tools], ["read_file"])
            self.assertTrue(allowed["allowed"])
            self.assertTrue(denied["blocked"])
            self.assertEqual(denied["rule"], "allowlist")
            calls = [json.loads(line) for line in call_log.read_text().splitlines()]
            self.assertEqual([call["tool"] for call in calls], ["read_file"])
            self.assertIn(
                "Judikt starter policy (read-only): read=1 write=1 destructive=3",
                stderr,
            )
            self.assertIn(
                "Excluded tools: update_issue, delete_repo, list_things, delete_cache",
                stderr,
            )
            self.assertIn("Annotation/name conflicts: delete_cache", stderr)

    def test_approve_writes_requires_cli_issued_token_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            call_log = root / "calls.jsonl"
            policy_path = root / "policy.json"
            environment = self._environment(root)
            initialized = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "init",
                    "--profile",
                    "approve-writes",
                    "--name",
                    "profile-tools",
                    "--output",
                    str(policy_path),
                    "--",
                    sys.executable,
                    str(FIXTURE),
                    "policy-profiles",
                    str(call_log),
                ],
                cwd=PROJECT_ROOT,
                env={**os.environ, **environment},
                capture_output=True,
                text=True,
                check=False,
            )
            arguments = {"target": "INC-42"}
            approval = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "issue-approval",
                    "--audit-db",
                    str(root / "approval-audit.db"),
                    "--policy",
                    str(policy_path),
                    "--actor",
                    "local-operator",
                    "--reason",
                    "approved fixture update",
                    "--server",
                    "profile-tools",
                    "--tool",
                    "update_issue",
                    "--arguments",
                    json.dumps(arguments),
                ],
                cwd=PROJECT_ROOT,
                env={**os.environ, **environment},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            self.assertEqual(approval.returncode, 0, approval.stderr)

            client = self._explicit_policy_client(root, call_log, policy_path)
            try:
                denied = client.call_tool("update_issue", arguments)
                allowed = client.call_tool(
                    "update_issue",
                    {**arguments, "approval_token": approval.stdout.strip()},
                )
            finally:
                client.close()

            self.assertTrue(denied["blocked"])
            self.assertEqual(denied["rule"], "approval_required")
            self.assertTrue(allowed["allowed"])
            calls = [json.loads(line) for line in call_log.read_text().splitlines()]
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["tool"], "update_issue")
            self.assertIn("Approval-gated tools: update_issue, delete_repo, list_things, delete_cache", initialized.stderr)

    def test_permissive_warns_and_all_tools_execute(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            call_log = root / "calls.jsonl"
            process = self._start_wrap(root, call_log, "permissive")
            try:
                self._request(process, "initialize", {})
                tools = self._request(process, "tools/list", {})["tools"]
                results = [
                    self._request(
                        process,
                        "tools/call",
                        {"name": tool["name"], "arguments": {"target": "fixture"}},
                    )["structuredContent"]
                    for tool in tools
                ]
            finally:
                stderr = self._stop(process)

            self.assertEqual(
                [tool["name"] for tool in tools],
                ["read_file", "update_issue", "delete_repo", "list_things", "delete_cache"],
            )
            self.assertTrue(all(result["allowed"] for result in results))
            self.assertEqual(len(call_log.read_text().splitlines()), 5)
            self.assertIn(
                "WARNING: permissive profile allows every discovered tool without generated approval gates.",
                stderr,
            )

    def test_explicit_policy_bypasses_profile_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            call_log = root / "calls.jsonl"
            policy = json.loads(DEFAULT_POLICY_PATH.read_text())
            policy["allowed_tools"] = {"profile-tools": ["delete_repo"]}
            policy["actor_permissions"] = {
                "local-operator": ["delete_repo"],
                "anonymous": [],
            }
            policy_path = root / "explicit-policy.json"
            policy_path.write_text(json.dumps(policy))

            client = self._explicit_policy_client(
                root,
                call_log,
                policy_path,
                profile="read-only",
            )
            try:
                tools = client.list_tools()
                result = client.call_tool("delete_repo", {"target": "reviewed-repo"})
            finally:
                client.close()

            self.assertEqual([tool["name"] for tool in tools], ["delete_repo"])
            self.assertTrue(result["allowed"])
            self.assertEqual(len(call_log.read_text().splitlines()), 1)

    @classmethod
    def _start_wrap(
        cls,
        root: Path,
        call_log: Path,
        profile: str,
    ) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(root / "audit.db"),
                "wrap",
                "--profile",
                profile,
                "--name",
                "profile-tools",
                "--",
                sys.executable,
                str(FIXTURE),
                "policy-profiles",
                str(call_log),
            ],
            cwd=PROJECT_ROOT,
            env=cls._environment(root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    @classmethod
    def _explicit_policy_client(
        cls,
        root: Path,
        call_log: Path,
        policy_path: Path,
        *,
        profile: str | None = None,
    ) -> StdioMCPClient:
        profile_arguments = ["--profile", profile] if profile else []
        return StdioMCPClient(
            "profile-tools",
            command=[
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(root / "audit.db"),
                "wrap",
                "--policy",
                str(policy_path),
                *profile_arguments,
                "--name",
                "profile-tools",
                "--",
                sys.executable,
                str(FIXTURE),
                "policy-profiles",
                str(call_log),
            ],
            environment=cls._environment(root),
            cwd=str(PROJECT_ROOT),
            inherit_environment=False,
        )

    @staticmethod
    def _environment(root: Path) -> dict[str, str]:
        return {
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "JUDIKT_APPROVAL_SECRET": "profile-test-approval-secret-at-least-32-bytes",
            "JUDIKT_AUDIT_HMAC_SECRET": "profile-test-audit",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_TOOL_PIN_PATH": str(root / "pins.json"),
            "JUDIKT_UPSTREAM_CONFIG": "",
        }

    @staticmethod
    def _request(
        process: subprocess.Popen[str],
        method: str,
        params: dict[str, object],
    ) -> dict[str, object]:
        assert process.stdin is not None
        assert process.stdout is not None
        request_id = f"{method}-{params}"
        process.stdin.write(
            json.dumps(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            )
            + "\n"
        )
        process.stdin.flush()
        response = json.loads(process.stdout.readline())
        if "error" in response:
            raise AssertionError(response["error"])
        return response["result"]

    @staticmethod
    def _stop(process: subprocess.Popen[str]) -> str:
        if process.poll() is None:
            process.terminate()
        _, stderr = process.communicate(timeout=5)
        return stderr


if __name__ == "__main__":
    unittest.main()
