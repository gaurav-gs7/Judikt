from __future__ import annotations

import argparse
import importlib.metadata
import json
import shutil
import sys
from pathlib import Path
from typing import Any


MINIMUM_PYTHON = (3, 11)


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _candidate(path: str) -> dict[str, Any]:
    expanded = Path(path).expanduser()
    return {"path": str(expanded), "exists": expanded.is_file()}


def diagnose() -> dict[str, Any]:
    version = sys.version_info
    clients = [
        {
            "name": "Claude Desktop",
            "executable": shutil.which("claude"),
            "config_candidates": [
                _candidate("~/Library/Application Support/Claude/claude_desktop_config.json"),
                _candidate("~/.config/Claude/claude_desktop_config.json"),
            ],
        },
        {
            "name": "Cursor",
            "executable": shutil.which("cursor"),
            "config_candidates": [_candidate("~/.cursor/mcp.json")],
        },
        {
            "name": "Codex",
            "executable": shutil.which("codex"),
            "config_candidates": [_candidate("~/.codex/config.toml")],
        },
    ]
    judikt_version = _package_version("judikt")
    return {
        "diagnostic_contract": {
            "read_only": True,
            "network_calls": False,
            "config_contents_read": False,
            "environment_values_read": False,
        },
        "python": {
            "executable": sys.executable,
            "version": f"{version.major}.{version.minor}.{version.micro}",
            "supported": version[:2] >= MINIMUM_PYTHON,
            "minimum": ".".join(map(str, MINIMUM_PYTHON)),
        },
        "judikt": {
            "executable": shutil.which("judikt"),
            "package_version": judikt_version,
            "installed": judikt_version is not None,
        },
        "mcp_clients": clients,
    }


def main() -> None:
    arguments = argparse.ArgumentParser(
        description="Read-only local environment detection for the Judikt MCP security skill."
    )
    arguments.add_argument("--compact", action="store_true")
    args = arguments.parse_args()
    print(json.dumps(diagnose(), indent=None if args.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
