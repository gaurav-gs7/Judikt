from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.approval import ApprovalAuthority
from judikt.audit import AuditStore
from judikt.auth import AuthConfig
from judikt.slack_approval import SlackApprovalWorkflow


class _SecretsManagerClient:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.calls: list[str] = []

    def get_secret_value(self, SecretId: str) -> dict[str, str]:
        self.calls.append(SecretId)
        return {"SecretString": self.values[SecretId]}


class SecretConsumerIntegrationTest(unittest.TestCase):
    def test_auth_and_approval_load_independent_aws_secrets(self) -> None:
        client = _SecretsManagerClient(
            {
                "auth-secret": "brokered-bearer-token",
                "approval-secret": "brokered-approval-secret-at-least-32-bytes",
            }
        )
        boto3 = types.SimpleNamespace(client=lambda service: client)
        with patch.dict(sys.modules, {"boto3": boto3}), patch.dict(
            os.environ,
            {
                "JUDIKT_HTTP_BEARER_TOKEN_SECRET_ARN": "auth-secret",
                "JUDIKT_APPROVAL_SECRET_ARN": "approval-secret",
            },
            clear=True,
        ):
            config = AuthConfig.from_env()
            authority = ApprovalAuthority()

        self.assertEqual(config.bearer_token, "brokered-bearer-token")
        token = authority.issue(
            actor="sre-oncall",
            reason="incident mitigation",
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments={"service": "payments-api"},
        )
        authority.verify(
            token=token,
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments={"service": "payments-api"},
        )
        self.assertEqual(client.calls, ["auth-secret", "approval-secret"])

    def test_audit_signing_key_loads_from_aws_and_seals_chain(self) -> None:
        client = _SecretsManagerClient(
            {"audit-secret": "brokered-audit-secret-with-at-least-32-bytes"}
        )
        boto3 = types.SimpleNamespace(client=lambda service: client)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            sys.modules, {"boto3": boto3}
        ), patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET_ARN": "audit-secret",
                "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            },
            clear=True,
        ):
            store = AuditStore(Path(directory) / "audit.db")
            try:
                store.record(
                    correlation_id="corr-1",
                    server="platform-ops",
                    tool="platform.health",
                    allowed=True,
                    rule="allow",
                    reason="allowed by policy",
                    arguments={"service": "payments-api"},
                    result={"status": "healthy"},
                    duration_ms=1.0,
                )
                report = store.verify_chain()
            finally:
                store.close()

        self.assertTrue(report["valid"])
        self.assertTrue(report["signed"])
        self.assertEqual(client.calls, ["audit-secret"])

    def test_slack_workflow_loads_webhook_and_signing_secret_from_aws(self) -> None:
        client = _SecretsManagerClient(
            {
                "slack-webhook": "https://hooks.slack.test/services/example",
                "slack-signing": "brokered-slack-signing-secret",
            }
        )
        boto3 = types.SimpleNamespace(client=lambda service: client)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            sys.modules, {"boto3": boto3}
        ), patch.dict(
            os.environ,
            {
                "JUDIKT_SLACK_WEBHOOK_SECRET_ARN": "slack-webhook",
                "JUDIKT_SLACK_SIGNING_SECRET_ARN": "slack-signing",
                "JUDIKT_SLACK_APPROVER_IDS": "U-ONCALL",
            },
            clear=True,
        ):
            workflow = SlackApprovalWorkflow(
                Path(directory) / "approvals.db",
                ApprovalAuthority("test-approval-secret-at-least-32-bytes"),
            )
            try:
                self.assertTrue(workflow.enabled)
                self.assertEqual(
                    workflow.webhook_url,
                    "https://hooks.slack.test/services/example",
                )
                self.assertEqual(
                    workflow.signing_secret,
                    "brokered-slack-signing-secret",
                )
            finally:
                workflow.close()

        self.assertEqual(client.calls, ["slack-webhook", "slack-signing"])


if __name__ == "__main__":
    unittest.main()
