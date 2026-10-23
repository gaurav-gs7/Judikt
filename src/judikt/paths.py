from __future__ import annotations

import os
import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Sequence


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
DEMO_POLICY_PATH = packaged_resource("demo-policy.json")
DEFAULT_INTEROP_PROFILES_PATH = packaged_resource("interop-profiles.json")
DEFAULT_MCP38_COVERAGE_PATH = packaged_resource("mcp38-coverage.json")


def state_root() -> Path:
    state_home = os.getenv("XDG_STATE_HOME")
    root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return root / "judikt"


def default_audit_path() -> Path:
    explicit = os.getenv("JUDIKT_AUDIT_DB")
    if explicit:
        return Path(explicit).expanduser()
    return state_root() / "judikt.db"


@dataclass(frozen=True)
class UpstreamState:
    display_name: str
    fingerprint: str
    state_key: str
    directory: Path
    command: tuple[str, ...]
    cwd: Path
    environment_names: tuple[str, ...]

    @property
    def audit_path(self) -> Path:
        return self.directory / "audit.db"

    @property
    def pin_path(self) -> Path:
        return self.audit_path.with_suffix(".tool-pins.json")


def upstream_state(
    display_name: str,
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    environment_names: Sequence[str] = (),
) -> UpstreamState:
    resolved_cwd = Path(cwd or os.getcwd()).expanduser().resolve()
    canonical_command = tuple(_resolve_file_argument(part, resolved_cwd) for part in command)
    names = tuple(sorted(set(environment_names)))
    canonical = json.dumps(
        {
            "command": canonical_command,
            "cwd": str(resolved_cwd),
            "environment_names": names,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    state_key = f"{display_name}-{fingerprint}"
    directory = state_root() / "upstreams" / state_key
    return UpstreamState(
        display_name=display_name,
        fingerprint=fingerprint,
        state_key=state_key,
        directory=directory,
        command=canonical_command,
        cwd=resolved_cwd,
        environment_names=names,
    )


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.chmod(0o700)


def _resolve_file_argument(value: str, cwd: Path) -> str:
    candidate = Path(value).expanduser()
    resolved = candidate if candidate.is_absolute() else cwd / candidate
    return str(resolved.resolve()) if resolved.is_file() else value
