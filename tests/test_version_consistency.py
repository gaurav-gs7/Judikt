from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

import judikt

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class VersionConsistencyTest(unittest.TestCase):
    """Every place that states Judikt's version must agree with pyproject.toml."""

    def test_package_chart_and_pyproject_versions_match(self) -> None:
        pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
        version = pyproject["project"]["version"]
        self.assertEqual(judikt.__version__, version)
        chart = (PROJECT_ROOT / "charts" / "judikt" / "Chart.yaml").read_text()
        self.assertRegex(chart, rf"(?m)^version:\s*{re.escape(version)}\s*$")
        self.assertRegex(chart, rf'(?m)^appVersion:\s*"{re.escape(version)}"\s*$')

    def test_source_has_no_hardcoded_runtime_version(self) -> None:
        for path in (PROJECT_ROOT / "src" / "judikt").rglob("*.py"):
            if path.name == "__init__.py":
                continue
            with self.subTest(path=path.name):
                self.assertNotRegex(path.read_text(), r'"version":\s*"\d+\.\d+\.\d+"')

    def test_cli_reports_the_package_version(self) -> None:
        process = subprocess.run(
            [sys.executable, "-m", "judikt.cli", "--version"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(process.stdout.strip(), f"judikt {judikt.__version__}")

    def test_stdio_server_info_reports_the_package_version(self) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        }
        process = subprocess.run(
            [sys.executable, "-m", "judikt.cli", "backend", "incident"],
            input=json.dumps(request) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "HOME": os.environ.get("HOME", "/tmp")},
            check=False,
        )
        response = json.loads(process.stdout.splitlines()[0])
        self.assertEqual(response["result"]["serverInfo"]["version"], judikt.__version__)


if __name__ == "__main__":
    unittest.main()
