from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from judikt.approval import ApprovalAuthority
from judikt.paths import DEFAULT_POLICY_PATH, DEMO_POLICY_PATH
from judikt.policy import PolicyEngine
from judikt.risk import RiskConfigError, RiskEngine


DEMO_CASES = [
    (
        "platform-ops",
        "platform.health",
        {"service": "checkout-worker"},
        20,
        "low",
        ["base MCP tool invocation risk", "production operations server"],
    ),
    (
        "platform-ops",
        "platform.read_config",
        {"service": "payments-api"},
        50,
        "medium",
        [
            "base MCP tool invocation risk",
            "production operations server",
            "configuration may contain secrets",
            "payments-api is business critical",
        ],
    ),
    (
        "platform-ops",
        "platform.read_logs",
        {"service": "payments-api"},
        45,
        "medium",
        [
            "base MCP tool invocation risk",
            "production operations server",
            "logs may include sensitive operational context",
            "payments-api is business critical",
        ],
    ),
    (
        "platform-ops",
        "platform.run_diagnostic",
        {"service": "payments-api"},
        55,
        "medium",
        [
            "base MCP tool invocation risk",
            "production operations server",
            "diagnostic commands can expose infrastructure details",
            "payments-api is business critical",
        ],
    ),
    (
        "platform-ops",
        "platform.restart_deployment",
        {"service": "payments-api"},
        75,
        "high",
        [
            "base MCP tool invocation risk",
            "production operations server",
            "deployment restart can affect availability",
            "payments-api is business critical",
        ],
    ),
    (
        "platform-ops",
        "platform.rollback_deployment",
        {"service": "payments-api", "version": "payments-api@2026.05.2"},
        90,
        "critical",
        [
            "base MCP tool invocation risk",
            "production operations server",
            "deployment rollback can change live production traffic",
            "payments-api is business critical",
            "request references a production release artifact",
        ],
    ),
    (
        "kubernetes",
        "kubernetes.restart_pod",
        {"namespace": "prod", "pod": "payment-api-1"},
        100,
        "critical",
        [
            "base MCP tool invocation risk",
            "kubernetes operations server",
            "pod restart can affect production availability",
            "request targets a production namespace",
            "request targets a payment-system pod",
        ],
    ),
    (
        "incident",
        "incident.timeline",
        {},
        10,
        "low",
        ["base MCP tool invocation risk"],
    ),
]


class RiskEngineTest(unittest.TestCase):
    def test_demo_scores_levels_and_evidence_are_unchanged(self) -> None:
        engine = RiskEngine(json.loads(DEMO_POLICY_PATH.read_text()))

        for server, tool, arguments, score, level, evidence in DEMO_CASES:
            with self.subTest(tool=tool):
                assessment = engine.assess(server, tool, arguments)
                self.assertEqual(assessment.score, score)
                self.assertEqual(assessment.level, level)
                self.assertEqual(assessment.evidence, evidence)

    def test_generic_tools_are_scored_by_configured_tier(self) -> None:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        policy["tool_classification"] = {
            "records.fetch": {"tier": "read"},
            "records.change": {"tier": "write"},
            "records.destroy": {"tier": "destructive"},
        }
        engine = RiskEngine(policy)

        self.assertEqual(engine.assess("generic", "records.fetch", {}).score, 10)
        self.assertEqual(engine.assess("generic", "records.change", {}).score, 40)
        self.assertEqual(engine.assess("generic", "records.destroy", {}).score, 70)

    def test_runtime_annotations_classify_when_policy_has_no_entry(self) -> None:
        engine = RiskEngine(json.loads(DEFAULT_POLICY_PATH.read_text()))

        read = engine.assess(
            "generic",
            "records.fetch",
            {},
            {"name": "records.fetch", "annotations": {"readOnlyHint": True}},
        )
        write = engine.assess(
            "generic",
            "records.change",
            {},
            {
                "name": "records.change",
                "annotations": {"readOnlyHint": False, "destructiveHint": False},
            },
        )

        self.assertEqual(read.score, 10)
        self.assertEqual(write.score, 40)

    def test_argument_rules_support_in_prefix_and_regex(self) -> None:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        policy["risk"]["argument_rules"] = [
            {
                "argument": "namespace",
                "in": ["prod"],
                "add": 10,
                "evidence": "production namespace",
            },
            {
                "argument": "release",
                "prefix": "critical@",
                "add": 5,
                "evidence": "critical release",
            },
            {
                "argument": "ticket",
                "regex": "^SEC-[0-9]+$",
                "add": 7,
                "evidence": "security ticket",
            },
        ]

        assessment = RiskEngine(policy).assess(
            "generic",
            "records.fetch",
            {"namespace": "prod", "release": "critical@2", "ticket": "SEC-42"},
        )

        self.assertEqual(assessment.score, 32)
        self.assertEqual(
            assessment.evidence,
            [
                "base MCP tool invocation risk",
                "production namespace",
                "critical release",
                "security ticket",
            ],
        )

    def test_untrusted_read_only_annotation_cannot_lower_delete_tool(self) -> None:
        engine = RiskEngine(json.loads(DEFAULT_POLICY_PATH.read_text()))

        assessment = engine.assess(
            "generic",
            "delete_repository",
            {},
            {
                "name": "delete_repository",
                "annotations": {"readOnlyHint": True},
            },
        )

        self.assertGreaterEqual(assessment.score, 70)

    def test_risk_action_adds_approval_requirement(self) -> None:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        policy["allowed_tools"] = {"generic": ["deploy_release"]}
        policy["actor_permissions"] = {"operator": ["deploy_release"]}
        policy["risk"]["tool_rules"] = [
            {
                "match": "deploy_release",
                "add": 10,
                "evidence": "production deployment",
            }
        ]
        policy["risk"]["risk_actions"] = {"critical": "require_approval"}
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(json.dumps(policy))
            engine = PolicyEngine(
                policy_path,
                ApprovalAuthority("risk-test-approval-secret-at-least-32-bytes"),
            )
            decision = engine.evaluate(
                "generic", "deploy_release", {}, authenticated_actor="operator"
            )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "approval_required")
        self.assertEqual(decision.action, "REQUIRE_APPROVAL")
        self.assertEqual(decision.risk_level, "critical")

    def test_validation_names_unknown_keys_and_bad_regex_paths(self) -> None:
        policy = json.loads(DEFAULT_POLICY_PATH.read_text())
        unknown = deepcopy(policy)
        unknown["risk"]["mystery"] = True
        with self.assertRaisesRegex(RiskConfigError, r"risk\.mystery: unknown key"):
            RiskEngine(unknown)

        invalid = deepcopy(policy)
        invalid["risk"]["argument_rules"] = [
            {
                "argument": "name",
                "regex": "[",
                "add": 1,
                "evidence": "invalid",
            }
        ]
        with self.assertRaisesRegex(
            RiskConfigError,
            r"risk\.argument_rules\[0\]\.regex: invalid regex",
        ):
            RiskEngine(invalid)


if __name__ == "__main__":
    unittest.main()
