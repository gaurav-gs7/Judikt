from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_skill_release import SkillReleaseError, build_skill_release, project_version


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = PROJECT_ROOT / "skills" / "judikt-mcp-security"
DIAGNOSTIC = SKILL_ROOT / "scripts" / "diagnose.py"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


class SkillPackageTest(unittest.TestCase):
    def test_skill_has_minimal_distributable_layout(self) -> None:
        files = {
            path.relative_to(SKILL_ROOT).as_posix()
            for path in SKILL_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(
            files,
            {
                "SKILL.md",
                "references/mcp-configuration.md",
                "references/security.md",
                "references/setup.md",
                "references/troubleshooting.md",
                "scripts/diagnose.py",
            },
        )

    def test_metadata_workflow_safety_and_network_disclosure_are_explicit(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text()
        security = (SKILL_ROOT / "references" / "security.md").read_text()

        self.assertTrue(skill.startswith("---\nname: judikt-mcp-security\ndescription:"))
        self.assertIn("Requires a separately installed Judikt runtime", skill)
        for step in (
            "Detect the environment",
            "Plan setup",
            "Configure the upstream",
            "Connect the client",
            "Run a smoke test",
            "Produce an assessment",
        ):
            self.assertIn(step, skill)
        for rule in (
            "Operate read-only by default",
            "explicit user authorization before destructive",
            "Never invent, replay, expose, or bypass approval tokens",
            "Never print secrets",
            "Separate verified controls",
        ):
            self.assertIn(rule, skill)
        for integration in ("Groq", "Slack", "AWS", "SIEM"):
            self.assertIn(integration, skill)
            self.assertIn(integration, security)

    def test_diagnostic_source_has_no_network_or_mutation_capabilities(self) -> None:
        tree = ast.parse(DIAGNOSTIC.read_text())
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imported_roots.isdisjoint(
                {
                    "boto3",
                    "http",
                    "httpx",
                    "requests",
                    "socket",
                    "subprocess",
                    "urllib",
                }
            )
        )
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(
            called_attributes.isdisjoint(
                {
                    "chmod",
                    "mkdir",
                    "open",
                    "rename",
                    "replace",
                    "rmdir",
                    "touch",
                    "unlink",
                    "write_bytes",
                    "write_text",
                }
            )
        )

    def test_diagnostic_executes_read_only_with_an_empty_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            before = list(home.iterdir())
            process = subprocess.run(
                [sys.executable, str(DIAGNOSTIC), "--compact"],
                env={**os.environ, "HOME": str(home)},
                capture_output=True,
                text=True,
                check=False,
            )
            after = list(home.iterdir())

        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(before, after)
        self.assertEqual(
            report["diagnostic_contract"],
            {
                "config_contents_read": False,
                "environment_values_read": False,
                "network_calls": False,
                "read_only": True,
            },
        )

    def test_versioned_distribution_contains_one_current_skill_folder(self) -> None:
        expected_files = {
            "judikt-mcp-security/SKILL.md",
            "judikt-mcp-security/references/mcp-configuration.md",
            "judikt-mcp-security/references/security.md",
            "judikt-mcp-security/references/setup.md",
            "judikt-mcp-security/references/troubleshooting.md",
            "judikt-mcp-security/scripts/diagnose.py",
        }
        with tempfile.TemporaryDirectory() as directory:
            artifact = build_skill_release(
                skill_root=SKILL_ROOT,
                pyproject=PYPROJECT,
                output_dir=Path(directory),
                release_tag=f"v{project_version(PYPROJECT)}",
            )
            self.assertEqual(
                artifact.name,
                f"judikt-mcp-security-v{project_version(PYPROJECT)}.zip",
            )
            with zipfile.ZipFile(artifact) as archive:
                archived_files = {
                    name for name in archive.namelist() if not name.endswith("/")
                }
                self.assertEqual(archived_files, expected_files)
                self.assertTrue(
                    all(
                        not Path(name).is_absolute() and ".." not in Path(name).parts
                        for name in archived_files
                    )
                )
                for archived_name in archived_files:
                    relative = Path(archived_name).relative_to("judikt-mcp-security")
                    source = SKILL_ROOT / relative
                    self.assertEqual(
                        hashlib.sha256(archive.read(archived_name)).digest(),
                        hashlib.sha256(source.read_bytes()).digest(),
                    )

    def test_skill_archive_is_reproducible_and_rejects_version_drift(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_artifact = build_skill_release(
                skill_root=SKILL_ROOT,
                pyproject=PYPROJECT,
                output_dir=Path(first),
            )
            second_artifact = build_skill_release(
                skill_root=SKILL_ROOT,
                pyproject=PYPROJECT,
                output_dir=Path(second),
            )
            self.assertEqual(
                hashlib.sha256(first_artifact.read_bytes()).digest(),
                hashlib.sha256(second_artifact.read_bytes()).digest(),
            )
            with self.assertRaisesRegex(SkillReleaseError, "does not match runtime version"):
                build_skill_release(
                    skill_root=SKILL_ROOT,
                    pyproject=PYPROJECT,
                    output_dir=Path(first),
                    release_tag="v999.0.0",
                )


if __name__ == "__main__":
    unittest.main()
