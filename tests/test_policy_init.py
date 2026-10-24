from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from judikt.paths import DEFAULT_POLICY_PATH
from judikt.policy_init import (
    PolicyInitializationError,
    derive_server_name,
    initialize_policy,
    normalize_command,
    normalize_server_name,
    starter_policy,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "external_mcp_server.py"
PROFILE_TOOLS = [
    {"name": "read_file", "annotations": {"readOnlyHint": True}},
    {
        "name": "update_issue",
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {"name": "delete_repo", "annotations": {"destructiveHint": True}},
    {"name": "list_things"},
    {"name": "delete_cache", "annotations": {"readOnlyHint": True}},
]


class PolicyInitializationTest(unittest.TestCase):
    def test_packaged_default_is_neutral_and_fail_closed(self) -> None:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())

        self.assertEqual(policy["local_stdio_identity"], "local-operator")
        self.assertEqual(policy["identity_argument_fields"], [])
        self.assertEqual(policy["allowed_tools"], {})
        self.assertEqual(policy["actor_permissions"], {"local-operator": [], "anonymous": []})
        permissions = policy["actor_permissions"]
        self.assertNotIn("*", permissions["local-operator"])
        self.assertEqual(set(permissions), {"local-operator", "anonymous"})

    def test_starter_policy_defaults_to_annotated_read_tools(self) -> None:
        policy = starter_policy(
            "company-tools",
            [
                {"name": "issues.read", "annotations": {"readOnlyHint": True}},
                {
                    "name": "deployments.restart",
                    "annotations": {"readOnlyHint": True},
                },
            ],
        )

        expected = ["issues.read"]
        self.assertEqual(policy["allowed_tools"], {"company-tools": expected})
        self.assertEqual(policy["actor_permissions"]["local-operator"], expected)
        self.assertEqual(policy["actor_permissions"]["anonymous"], [])
        self.assertTrue(policy["tool_classification"]["deployments.restart"]["conflict"])

    def test_classifies_spec_defaults_name_conflicts_and_profiles(self) -> None:
        read_only = starter_policy("profile-tools", PROFILE_TOOLS)

        self.assertEqual(
            read_only["tool_classification"],
            {
                "read_file": {
                    "tier": "read",
                    "annotations": {"readOnlyHint": True},
                    "conflict": False,
                },
                "update_issue": {
                    "tier": "write",
                    "annotations": {
                        "readOnlyHint": False,
                        "destructiveHint": False,
                    },
                    "conflict": False,
                },
                "delete_repo": {
                    "tier": "destructive",
                    "annotations": {"destructiveHint": True},
                    "conflict": False,
                },
                "list_things": {
                    "tier": "destructive",
                    "annotations": {},
                    "conflict": False,
                },
                "delete_cache": {
                    "tier": "destructive",
                    "annotations": {"readOnlyHint": True},
                    "conflict": True,
                },
            },
        )
        self.assertEqual(read_only["allowed_tools"]["profile-tools"], ["read_file"])

        approve_writes = starter_policy(
            "profile-tools", PROFILE_TOOLS, profile="approve-writes"
        )
        self.assertEqual(
            approve_writes["allowed_tools"]["profile-tools"],
            [tool["name"] for tool in PROFILE_TOOLS],
        )
        self.assertEqual(
            approve_writes["approval_required"],
            ["update_issue", "delete_repo", "list_things", "delete_cache"],
        )

        permissive = starter_policy("profile-tools", PROFILE_TOOLS, profile="permissive")
        self.assertEqual(
            permissive["allowed_tools"]["profile-tools"],
            [tool["name"] for tool in PROFILE_TOOLS],
        )
        self.assertEqual(permissive["approval_required"], [])

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
            self.assertEqual(report["classification_summary"]["counts"]["read"], 1)
            self.assertIn("Judikt starter policy (read-only)", created.stderr)
            self.assertEqual(
                policy["allowed_tools"],
                {"external-incidents": ["external.fetch_issue"]},
            )
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("refusing to overwrite", repeated.stderr)
            self.assertNotIn("Traceback", repeated.stderr)

    def test_initialize_policy_closes_client_and_writes_discovered_catalog(self) -> None:
        client = mock.Mock()
        client.list_tools.return_value = [
            {"name": "issues.read", "annotations": {"readOnlyHint": True}}
        ]
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "judikt.policy_init.StdioMCPClient", return_value=client
        ) as client_type:
            output = Path(directory) / "nested" / "policy.json"
            report = initialize_policy(
                ["--", "company-mcp", "--stdio"],
                server_name="company-tools",
                output_path=output,
                identity="operator",
            )

            policy = json.loads(output.read_text())
            self.assertEqual(report["tools"], ["issues.read"])
            self.assertEqual(policy["local_stdio_identity"], "operator")
            self.assertEqual(report["classification_summary"]["excluded_tools"], [])
            client_type.assert_called_once_with(
                "company-tools",
                command=("company-mcp", "--stdio"),
                environment={},
                inherit_environment=False,
            )
            client.close.assert_called_once_with()

    def test_initialize_policy_validates_identity_and_overwrite_before_starting_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            output.write_text("existing")
            with mock.patch("judikt.policy_init.StdioMCPClient") as client_type:
                with self.assertRaisesRegex(PolicyInitializationError, "must not be empty"):
                    initialize_policy(
                        ["server"],
                        server_name="upstream",
                        output_path=output,
                        identity=" ",
                    )
                with self.assertRaisesRegex(PolicyInitializationError, "refusing to overwrite"):
                    initialize_policy(
                        ["server"],
                        server_name="upstream",
                        output_path=output,
                    )
                client_type.assert_not_called()

    def test_rejects_unknown_profile_before_starting_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "judikt.policy_init.StdioMCPClient"
        ) as client_type:
            with self.assertRaisesRegex(PolicyInitializationError, "profile must be one of"):
                initialize_policy(
                    ["server"],
                    server_name="upstream",
                    output_path=Path(directory) / "policy.json",
                    profile="unsafe",
                )
            client_type.assert_not_called()

    def test_command_and_server_name_validation_is_fail_closed(self) -> None:
        for command in ([], [""], ["server", ""]):
            with self.subTest(command=command), self.assertRaisesRegex(
                PolicyInitializationError, "upstream command is required"
            ):
                normalize_command(command)
        for name in ("", "has spaces", "invalid/slash"):
            with self.subTest(name=name), self.assertRaisesRegex(
                PolicyInitializationError, "server name must contain"
            ):
                normalize_server_name(name)


if __name__ == "__main__":
    unittest.main()
