from __future__ import annotations

import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SecurityPolicyTest(unittest.TestCase):
    def test_supported_boundaries_and_identity_limit_are_documented(self) -> None:
        policy = (PROJECT_ROOT / "SECURITY.md").read_text()

        for heading in (
            "## Local And Demo Boundary",
            "## Authenticated Remote Boundary",
            "## Production Boundary",
        ):
            self.assertIn(heading, policy)
        for requirement in (
            "Streamable HTTP",
            "JWT",
            "JWKS",
            "Redis-backed distributed rate limiting",
            "AWS Secrets Manager",
            "Unauthenticated stdio does not authenticate individual callers",
            "every client sharing that policy is represented as the same local principal",
            "not an authorization server",
            "does not currently provide built-in multi-tenant isolation",
        ):
            self.assertIn(requirement, policy)

    def test_optional_network_integrations_are_disclosed(self) -> None:
        policy = (PROJECT_ROOT / "SECURITY.md").read_text()

        for integration in (
            "Groq",
            "Slack",
            "AWS services",
            "SIEM",
            "Redis",
            "Vault",
            "OIDC/JWKS",
            "OTLP",
        ):
            self.assertIn(integration, policy)
        self.assertIn("make outbound calls only when configured", policy)


if __name__ == "__main__":
    unittest.main()
