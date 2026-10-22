from __future__ import annotations

import argparse
import configparser
import zipfile
from pathlib import Path, PurePosixPath


REQUIRED_RESOURCES = {
    "judikt/resources/default-policy.json",
    "judikt/resources/demo-policy.json",
    "judikt/resources/interop-profiles.json",
    "judikt/resources/mcp38-coverage.json",
}


def verify_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        missing = REQUIRED_RESOURCES - names
        if missing:
            raise SystemExit(f"wheel is missing package data: {', '.join(sorted(missing))}")

        package_roots = {
            PurePosixPath(name).parts[0]
            for name in names
            if ".dist-info/" not in name and not name.endswith(".dist-info")
        }
        if package_roots != {"judikt"}:
            raise SystemExit(
                "wheel contains unexpected top-level packages: "
                + ", ".join(sorted(package_roots - {"judikt"}))
            )

        entry_point_name = next(
            (name for name in names if name.endswith(".dist-info/entry_points.txt")),
            None,
        )
        if entry_point_name is None:
            raise SystemExit("wheel is missing console entry-point metadata")
        entry_points = configparser.ConfigParser()
        entry_points.read_string(archive.read(entry_point_name).decode())
        console_scripts = dict(entry_points.items("console_scripts"))
        if console_scripts != {"judikt": "judikt.cli:main"}:
            raise SystemExit(f"wheel exposes unexpected console scripts: {console_scripts}")

    print(f"Verified Judikt wheel: {path}")


def main() -> None:
    arguments = argparse.ArgumentParser(description="verify the Judikt wheel contract")
    arguments.add_argument("wheel", type=Path)
    args = arguments.parse_args()
    verify_wheel(args.wheel)


if __name__ == "__main__":
    main()
