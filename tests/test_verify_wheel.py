from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.verify_wheel import REQUIRED_RESOURCES, verify_wheel


class WheelVerificationTest(unittest.TestCase):
    def write_wheel(self, path: Path, *, extra_package: str = "") -> None:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("judikt/__init__.py", "")
            for resource in REQUIRED_RESOURCES:
                archive.writestr(resource, "{}")
            archive.writestr(
                "judikt-1.0.dist-info/entry_points.txt",
                "[console_scripts]\njudikt = judikt.cli:main\n",
            )
            if extra_package:
                archive.writestr(f"{extra_package}/__init__.py", "")

    def test_accepts_canonical_distribution_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "judikt.whl"
            self.write_wheel(wheel)

            verify_wheel(wheel)

    def test_rejects_unexpected_packages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "judikt.whl"
            self.write_wheel(wheel, extra_package="unexpected_alias")

            with self.assertRaisesRegex(SystemExit, "unexpected top-level packages: unexpected_alias"):
                verify_wheel(wheel)


if __name__ == "__main__":
    unittest.main()
