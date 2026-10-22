from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from judikt.paths import DEFAULT_POLICY_PATH
from judikt.policy_init import (
    PolicyInitializationError,
    derive_server_name,
    starter_policy,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"


class PolicyInitializationTest(unittest.TestCase):
    def test_packaged_default_is_neutral_and_fail_closed(self) -> None:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())

        self.assertEqual(policy["local_stdio_identity"], "local-operator")
        self.assertEqual(policy["allowed_tools"], {})
        self.assertEqual(policy["actor_permissions"], {"local-operator": [], "anonymous": []})
        permissions = policy["actor_permissions"]
        self.assertNotIn("*", permissions["local-operator"])
        self.assertEqual(set(permissions), {"local-operator", "anonymous"})

    def test_starter_policy_uses_exact_discovered_tool_names(self) -> None:
        policy = starter_policy(
            "company-tools",
            [
                {"name": "issues.read"},
                {"name": "deployments.restart"},
            ],
        )

        expected = ["issues.read", "deployments.restart"]
        self.assertEqual(policy["allowed_tools"], {"company-tools": expected})
        self.assertEqual(policy["actor_permissions"]["local-operator"], expected)
        self.assertEqual(policy["actor_permissions"]["anonymous"], [])

    def test_starter_policy_rejects_empty_duplicate_and_malformed_catalogs(self) -> None:
        cases = [
            ([], "no tools"),
            ([{"name": "same"}, {"name": "same"}], "duplicate tool name"),
            ([{"description": "missing name"}], "valid name"),
        ]
        for tools, message in cases:
            with self.subTest(tools=tools):
                with self.assertRaisesRegex(PolicyInitializationError, message):
                    starter_policy("upstream", tools)

    def test_server_name_is_derived_without_machine_specific_paths(self) -> None:
        self.assertEqual(derive_server_name([sys.executable, str(FIXTURE)]), "external_mcp_server")
        self.assertEqual(derive_server_name(["npx", "-y", "server-package"]), "server-package")
        self.assertEqual(derive_server_name([sys.executable, "-m", "company.mcp"]), "mcp")

    def test_cli_discovers_tools_and_refuses_accidental_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            command = [
                sys.executable,
                "-m",
                "judikt.cli",
                "init",
                "--name",
                "external-incidents",
                "--output",
                str(output),
                "--",
                sys.executable,
                str(FIXTURE),
            ]
            environment = {
                **os.environ,
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
            }
            created = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            repeated = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(created.returncode, 0, created.stderr)
            report = json.loads(created.stdout)
            policy = json.loads(output.read_text())
            self.assertEqual(report["tool_count"], 1)
            self.assertEqual(
                policy["allowed_tools"],
                {"external-incidents": ["external.fetch_issue"]},
            )
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("refusing to overwrite", repeated.stderr)
            self.assertNotIn("Traceback", repeated.stderr)


if __name__ == "__main__":
    unittest.main()
