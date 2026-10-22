from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from judikt.interop import load_interop_profiles, run_interop_profiles


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "external_mcp_server.py"


class CommunityInteropTest(unittest.TestCase):
    def test_loads_versioned_profiles_and_runs_full_guarded_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile_path = Path(directory) / "profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "profiles": {
                            "independent-fixture": {
                                "implementation": "independent/test-fixture",
                                "version": "1.0.0",
                                "source_url": "https://example.test/independent-fixture",
                                "command": [sys.executable, str(FIXTURE)],
                                "env": {"ATTACK_FIXTURE_MODE": "safe"},
                                "expected_tools": ["external.fetch_issue"],
                                "safe_call": {
                                    "tool": "external.fetch_issue",
                                    "arguments": {"issue_id": "INC-INTEROP"},
                                },
                                "ci": True,
                            }
                        },
                    }
                )
            )

            profiles = load_interop_profiles(profile_path)
            report = run_interop_profiles(
                profile_path,
                PROJECT_ROOT / "config" / "policies.yaml",
            )

        self.assertEqual(profiles["independent-fixture"].version, "1.0.0")
        self.assertTrue(report["passed"])
        self.assertEqual(report["passed_count"], 1)
        self.assertTrue(report["results"][0]["audit_chain_valid"])
        self.assertEqual(report["results"][0]["metadata_reconnect_check"], "verified")

    def test_failure_evidence_does_not_retain_raw_upstream_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile_path = Path(directory) / "profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "profiles": {
                            "missing-tool-fixture": {
                                "implementation": "independent/test-fixture",
                                "version": "1.0.0",
                                "source_url": "https://example.test/independent-fixture",
                                "command": [sys.executable, str(FIXTURE)],
                                "env": {"ATTACK_FIXTURE_MODE": "safe"},
                                "expected_tools": ["secret-upstream-tool-name"],
                                "safe_call": {
                                    "tool": "external.fetch_issue",
                                    "arguments": {"issue_id": "INC-INTEROP"},
                                },
                                "ci": True,
                            }
                        },
                    }
                )
            )

            report = run_interop_profiles(
                profile_path,
                PROJECT_ROOT / "config" / "policies.yaml",
            )

        self.assertFalse(report["passed"])
        self.assertIn("error_hash", report["results"][0])
        self.assertNotIn("secret-upstream-tool-name", json.dumps(report))
