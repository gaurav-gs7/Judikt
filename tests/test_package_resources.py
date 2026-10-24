from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.paths import (
    DEFAULT_INTEROP_PROFILES_PATH,
    DEFAULT_MCP38_COVERAGE_PATH,
    DEFAULT_POLICY_PATH,
    DEMO_POLICY_PATH,
    default_audit_path,
)


class PackageResourcesTest(unittest.TestCase):
    def test_runtime_resources_are_shipped_inside_the_package(self) -> None:
        self.assertEqual(DEFAULT_POLICY_PATH.parent.name, "resources")
        self.assertIn("allowed_tools", json.loads(DEFAULT_POLICY_PATH.read_text()))
        self.assertIn("platform-ops", json.loads(DEMO_POLICY_PATH.read_text())["allowed_tools"])
        self.assertIn("profiles", json.loads(DEFAULT_INTEROP_PROFILES_PATH.read_text()))
        self.assertEqual(len(json.loads(DEFAULT_MCP38_COVERAGE_PATH.read_text())["threats"]), 38)

    def test_default_audit_database_uses_user_state_not_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"XDG_STATE_HOME": directory}, clear=True):
                self.assertEqual(
                    default_audit_path(),
                    Path(directory) / "judikt" / "judikt.db",
                )

    def test_explicit_audit_database_wins(self) -> None:
        with patch.dict(os.environ, {"JUDIKT_AUDIT_DB": "~/custom.db"}, clear=True):
            self.assertEqual(default_audit_path(), Path.home() / "custom.db")

    def test_repository_config_copies_match_packaged_resources(self) -> None:
        # config/ holds the documented, editable copies; the package ships its own.
        # They must never drift, or docs describe behaviour the runtime does not have.
        config = Path(__file__).resolve().parents[1] / "config"
        pairs = {
            "interop_profiles.json": DEFAULT_INTEROP_PROFILES_PATH,
            "mcp38_coverage.json": DEFAULT_MCP38_COVERAGE_PATH,
            "policies.yaml": DEMO_POLICY_PATH,
        }
        for name, packaged in pairs.items():
            with self.subTest(config=name):
                self.assertEqual(
                    json.loads((config / name).read_text()),
                    json.loads(packaged.read_text()),
                )


if __name__ == "__main__":
    unittest.main()
