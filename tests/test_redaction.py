from __future__ import annotations

import json
import unittest
from pathlib import Path

from judikt.approval import ApprovalAuthority
from judikt.policy import PolicyEngine


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SecretValueRedactionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = PolicyEngine(
            PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json",
            ApprovalAuthority("redaction-test-approval-secret-32-bytes"),
        )

    def test_redacts_supported_production_credential_shapes(self) -> None:
        credentials = {
            "aws_akia": "AKIAABCDEFGHIJKLMNOP",
            "aws_asia": "ASIA1234567890ABCDEF",
            "github_fine_grained": "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "github_oauth": "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "github_server": "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "github_user": "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "github_refresh": "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "slack": "xox" + "b-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "google": "AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ123456789",
            "stripe_secret": "sk_" + "live_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "stripe_restricted": "rk_" + "live_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature_value",
            "bearer": "Bearer opaque-production-token-1234567890",
            "url_credentials": "https://deploy-user:correct-horse-battery@service.example.com",
        }

        for name, credential in credentials.items():
            with self.subTest(name=name):
                self.assertEqual(
                    self.policy.redact(f"before {credential} after"),
                    "before [REDACTED] after",
                )

    def test_does_not_redact_common_non_secret_identifiers(self) -> None:
        values = [
            "0123456789abcdef0123456789abcdef01234567",
            "123e4567-e89b-12d3-a456-426614174000",
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA",
            "sk_test_not-a-production-secret",
            "pk_test_placeholder",
            "Bearer test-token",
            "github_pat_test",
            "AKIAEXAMPLE",
        ]

        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.policy.redact(value), value)

    def test_shipped_policies_use_the_same_value_patterns(self) -> None:
        paths = [
            PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json",
            PROJECT_ROOT / "src" / "judikt" / "resources" / "demo-policy.json",
            PROJECT_ROOT / "config" / "policies.yaml",
        ]
        pattern_sets = [json.loads(path.read_text())["redacted_value_patterns"] for path in paths]

        self.assertEqual(pattern_sets[0], pattern_sets[1])
        self.assertEqual(pattern_sets[0], pattern_sets[2])


if __name__ == "__main__":
    unittest.main()
