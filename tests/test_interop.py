from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from judikt.interop import load_interop_profiles, run_interop_profiles, with_network_passthrough


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "external_mcp_server.py"


class CommunityInteropTest(unittest.TestCase):
    def test_network_settings_are_forwarded_only_when_set(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HTTPS_PROXY": "http://proxy.example:3128", "NODE_EXTRA_CA_CERTS": "/ca.pem"},
            clear=True,
        ):
            merged = with_network_passthrough(
                {"NPM_CONFIG_CACHE": "/sandbox/npm", "HTTPS_PROXY": "profile-owned"}
            )
        self.assertEqual(
            merged,
            {
                "NPM_CONFIG_CACHE": "/sandbox/npm",
                "HTTPS_PROXY": "profile-owned",
                "NODE_EXTRA_CA_CERTS": {"from_env": "NODE_EXTRA_CA_CERTS"},
            },
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(with_network_passthrough({"A": "b"}), {"A": "b"})

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

    def test_pending_write_tools_do_not_fail_safe_read_interoperability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory)
            profile_path = sandbox / "profiles.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "profiles": {
                            "mixed-fixture": {
                                "implementation": "independent/test-fixture",
                                "version": "1.0.0",
                                "source_url": "https://example.test/mixed-fixture",
                                "command": [
                                    sys.executable,
                                    str(FIXTURE),
                                    "policy-profiles",
                                    str(sandbox / "calls.jsonl"),
                                ],
                                "expected_tools": ["read_file", "update_issue"],
                                "safe_call": {
                                    "tool": "read_file",
                                    "arguments": {"target": "fixture.txt"},
                                },
                                "ci": True,
                            }
                        },
                    }
                )
            )
            policy = json.loads((PROJECT_ROOT / "config" / "policies.yaml").read_text())
            policy["tool_pinning"]["first_use"] = {
                "read": "auto",
                "write": "require_approval",
                "destructive": "require_approval",
            }
            policy_path = sandbox / "policy.json"
            policy_path.write_text(json.dumps(policy))

            report = run_interop_profiles(profile_path, policy_path)

        self.assertTrue(report["passed"])
        self.assertEqual(report["results"][0]["metadata_first_check"], "pending")
        self.assertEqual(report["results"][0]["metadata_reconnect_check"], "pending")
        self.assertGreater(report["results"][0]["metadata_pending_count"], 0)
