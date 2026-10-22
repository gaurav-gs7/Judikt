from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from judikt.cli import parser


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BrandIdentityTest(unittest.TestCase):
    def test_canonical_package_cli_and_distribution_are_judikt(self) -> None:
        metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

        self.assertEqual(metadata["project"]["name"], "judikt")
        self.assertEqual(metadata["project"]["scripts"], {"judikt": "judikt.cli:main"})
        self.assertEqual(parser().description, "Judikt runtime firewall")
        self.assertEqual(parser().get_default("audit_db").name, "judikt.db")

    def test_deployment_artifacts_use_canonical_names(self) -> None:
        self.assertTrue((PROJECT_ROOT / "charts" / "judikt" / "Chart.yaml").is_file())
        self.assertTrue(
            (
                PROJECT_ROOT
                / "infra"
                / "aws"
                / "cloudformation"
                / "judikt-ec2.yml"
            ).is_file()
        )
        self.assertTrue(
            (
                PROJECT_ROOT
                / "deploy"
                / "observability"
                / "grafana"
                / "dashboards"
                / "judikt.json"
            ).is_file()
        )



if __name__ == "__main__":
    unittest.main()
