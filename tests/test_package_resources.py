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


if __name__ == "__main__":
    unittest.main()
