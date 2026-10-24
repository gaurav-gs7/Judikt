from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import judikt

from judikt.audit import AuditStore
from judikt.ops_runtime import JudiktOpsRuntime
from judikt.protocol import StdioMCPClient
from judikt.real_mcp import register_tools
from judikt.request_context import bind_authenticated_subject, reset_authenticated_subject


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = Path(judikt.__file__).resolve().parent.parent
SKILL_ROOT = PROJECT_ROOT / "skills" / "judikt-mcp-security"
ACTIVATION_CASES = PROJECT_ROOT / "tests" / "fixtures" / "skill_activation_cases.json"
UPSTREAM_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"


def _should_activate(prompt: str) -> bool:
    normalized = prompt.casefold()
    targets = ("judikt", "mcp server", "mcp client", "mcp gateway", "mcp tool")
    actions = (
        "assess",
        "audit",
        "configure",
        "connect",
        "protect",
        "secure",
        "smoke test",
        "troubleshoot",
        "wrap",
    )
    return any(term in normalized for term in targets) and any(
        term in normalized for term in actions
    )


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *, name: str, description: str):
        del description

        def register(function: object) -> object:
            self.tools[name] = function
            return function

        return register


class SkillAcceptanceTest(unittest.TestCase):
    def test_positive_and_negative_activation_contract(self) -> None:
        cases = json.loads(ACTIVATION_CASES.read_text())
        skill = (SKILL_ROOT / "SKILL.md").read_text()
        description = skill.split("---", 2)[1]

        self.assertIn("wrap an stdio MCP upstream", description)
        self.assertIn("add Judikt to an MCP client", description)
        for prompt in cases["positive"]:
            with self.subTest(prompt=prompt):
                self.assertTrue(_should_activate(prompt))
        for prompt in cases["negative"]:
            with self.subTest(prompt=prompt):
                self.assertFalse(_should_activate(prompt))

    @unittest.skipUnless(
        os.getenv("JUDIKT_ACCEPTANCE_FRESH_INSTALL") == "1",
        "only meaningful when run by scripts/run_skill_acceptance.sh",
    )
    def test_runtime_under_test_is_the_installed_wheel(self) -> None:
        self.assertTrue(
            Path(judikt.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()),
            f"judikt imported from {judikt.__file__}, not from the fresh wheel in {sys.prefix}",
        )

    def test_diagnostic_is_clean_on_an_empty_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            before = list(home.iterdir())
            process = subprocess.run(
                [
                    sys.executable,
                    str(SKILL_ROOT / "scripts" / "diagnose.py"),
                    "--compact",
                ],
                env={"HOME": str(home), "PATH": os.environ.get("PATH", "")},
                capture_output=True,
                text=True,
                check=False,
            )
            after = list(home.iterdir())

        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(before, after)
        self.assertTrue(report["python"]["supported"])
        if os.getenv("JUDIKT_ACCEPTANCE_FRESH_INSTALL") == "1":
            self.assertTrue(report["judikt"]["installed"])
            self.assertIsNotNone(report["judikt"]["executable"])

    def test_claude_code_and_cursor_configs_launch_the_guarded_catalog(self) -> None:
        for client in ("claude-code", "cursor"):
            with self.subTest(client=client), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                definition = self._client_definition(root, client)
                config = {"mcpServers": {"judikt-acceptance": definition}}
                config_path = root / (".mcp.json" if client == "claude-code" else ".cursor/mcp.json")
                config_path.parent.mkdir(parents=True, exist_ok=True)
                config_path.write_text(json.dumps(config, indent=2) + "\n")

                loaded = json.loads(config_path.read_text())["mcpServers"]["judikt-acceptance"]
                client_process = StdioMCPClient(
                    "judikt-acceptance",
                    command=[loaded["command"], *loaded["args"]],
                    environment=loaded["env"],
                    cwd=str(PROJECT_ROOT),
                    inherit_environment=False,
                )
                try:
                    self.assertEqual(
                        [tool["name"] for tool in client_process.list_tools()],
                        ["external.fetch_issue"],
                    )
                finally:
                    client_process.close()

    def test_allowed_blocked_and_tamper_evident_audit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definition = self._client_definition(root, "runtime")
            client = StdioMCPClient(
                "judikt-acceptance",
                command=[definition["command"], *definition["args"]],
                environment=definition["env"],
                cwd=str(PROJECT_ROOT),
                inherit_environment=False,
            )
            try:
                allowed = client.call_tool(
                    "external.fetch_issue",
                    {"issue_id": "INC-42", "actor": "forged-caller"},
                )
                blocked = client.call_tool(
                    "external.fetch_issue",
                    {"issue_id": "/home/operator/.ssh/id_rsa"},
                )
            finally:
                client.close()

            self.assertFalse(allowed["isError"])
            self.assertEqual(allowed["structuredContent"]["issue_id"], "INC-42")
            self.assertTrue(blocked["isError"])
            self.assertIn("blocked security pattern", blocked["content"][0]["text"])

            with mock.patch.dict(
                os.environ,
                {
                    "JUDIKT_AUDIT_HMAC_SECRET": "skill-acceptance-audit-secret-at-least-32-bytes",
                    "JUDIKT_AUDIT_SINK": "none",
                },
                clear=False,
            ):
                audit = AuditStore(root / "audit.db")
                try:
                    events = list(reversed(audit.recent()))
                    integrity = audit.verify_chain()
                finally:
                    audit.close()

            self.assertEqual([event["allowed"] for event in events], [True, False])
            self.assertEqual([event["tool"] for event in events], ["external.fetch_issue"] * 2)
            self.assertEqual(events[0]["arguments"]["actor"], "forged-caller")
            self.assertEqual(
                allowed["_meta"]["io.judikt/decision"]["rule"],
                "allow",
            )
            self.assertTrue(integrity["valid"])
            self.assertTrue(integrity["signed"])
            self.assertEqual(integrity["checked_events"], 3)
            self.assertEqual(integrity["legacy_unsealed_events"], 0)

    def test_privileged_approval_is_refused_without_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = JudiktOpsRuntime(
                PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json",
                Path(directory) / "approval-audit.db",
            )
            mcp = _FakeMCP()
            context_token = bind_authenticated_subject("unprivileged-operator", {"scope": "mcp:tools"})
            try:
                register_tools(mcp, runtime)
                result = mcp.tools["judikt.issue_approval"](  # type: ignore[operator]
                    actor="local-operator",
                    reason="acceptance test must not mint a token",
                    server="external-incidents",
                    tool="external.fetch_issue",
                    arguments={"issue_id": "INC-42"},
                )
            finally:
                reset_authenticated_subject(context_token)
                runtime.close()

        self.assertEqual(
            result,
            {
                "allowed": False,
                "rule": "admin_authorization",
                "reason": "control-plane administrator scope or group is required",
            },
        )
        self.assertNotIn("approval_token", result)

    @staticmethod
    def _client_definition(root: Path, client: str) -> dict[str, object]:
        return {
            "command": sys.executable,
            "args": [
                "-m",
                "judikt.cli",
                "--audit-db",
                str(root / "audit.db"),
                "wrap",
                "--name",
                "external-incidents",
                "--",
                sys.executable,
                str(UPSTREAM_FIXTURE),
            ],
            "env": {
                "PYTHONPATH": str(PACKAGE_ROOT),
                "JUDIKT_APPROVAL_SECRET": "skill-acceptance-approval-secret-32-bytes",
                "JUDIKT_AUDIT_HMAC_SECRET": "skill-acceptance-audit-secret-at-least-32-bytes",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_TOOL_PIN_PATH": str(root / f"{client}-pins.json"),
            },
        }


if __name__ == "__main__":
    unittest.main(verbosity=2)
