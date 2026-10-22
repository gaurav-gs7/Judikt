from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path


def packaged_resource(name: str) -> Path:
    """Return an installed Judikt data file.

    Python wheels are installed as ordinary directories, so the Traversable
    returned by importlib.resources can be exposed as a Path to components
    that already accept file-backed configuration.
    """
    resource = files("judikt.resources").joinpath(name)
    path = Path(str(resource))
    if not path.is_file():
        raise FileNotFoundError(f"packaged Judikt resource is missing: {name}")
    return path


DEFAULT_POLICY_PATH = packaged_resource("default-policy.json")
DEFAULT_INTEROP_PROFILES_PATH = packaged_resource("interop-profiles.json")
DEFAULT_MCP38_COVERAGE_PATH = packaged_resource("mcp38-coverage.json")


def default_audit_path() -> Path:
    explicit = os.getenv("JUDIKT_AUDIT_DB")
    if explicit:
        return Path(explicit).expanduser()
    state_home = os.getenv("XDG_STATE_HOME")
    root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return root / "judikt" / "judikt.db"
