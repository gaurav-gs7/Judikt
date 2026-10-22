from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Sequence

from .paths import DEFAULT_POLICY_PATH
from .protocol import StdioMCPClient


class PolicyInitializationError(ValueError):
    pass


def initialize_policy(
    command: Sequence[str],
    *,
    server_name: str,
    output_path: Path,
    identity: str = "local-operator",
    force: bool = False,
) -> dict[str, Any]:
    normalized_command = normalize_command(command)
    normalized_name = normalize_server_name(server_name)
    normalized_identity = identity.strip()
    if not normalized_identity:
        raise PolicyInitializationError("local identity must not be empty")
    if output_path.exists() and not force:
        raise PolicyInitializationError(
            f"refusing to overwrite existing policy: {output_path}; pass --force to replace it"
        )

    client = StdioMCPClient(
        normalized_name,
        command=normalized_command,
        inherit_environment=False,
    )
    try:
        tools = client.list_tools()
    finally:
        client.close()

    policy = starter_policy(normalized_name, tools, identity=normalized_identity)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    return {
        "policy": str(output_path),
        "server": normalized_name,
        "tool_count": len(policy["allowed_tools"][normalized_name]),
        "tools": policy["allowed_tools"][normalized_name],
    }


def starter_policy(
    server_name: str,
    tools: Sequence[dict[str, Any]],
    *,
    identity: str = "local-operator",
) -> dict[str, Any]:
    server_name = normalize_server_name(server_name)
    identity = identity.strip()
    if not identity:
        raise PolicyInitializationError("local identity must not be empty")
    names: list[str] = []
    seen: set[str] = set()
    for tool in tools:
        name = tool.get("name") if isinstance(tool, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise PolicyInitializationError("upstream tools/list returned a tool without a valid name")
        name = name.strip()
        if name in seen:
            raise PolicyInitializationError(f"upstream tools/list returned duplicate tool name: {name}")
        seen.add(name)
        names.append(name)
    if not names:
        raise PolicyInitializationError("upstream tools/list returned no tools")

    policy = deepcopy(json.loads(DEFAULT_POLICY_PATH.read_text()))
    policy["local_stdio_identity"] = identity
    policy["actor_permissions"] = {identity: names, "anonymous": []}
    policy["allowed_tools"] = {server_name: names}
    return policy


def derive_server_name(command: Sequence[str]) -> str:
    normalized = normalize_command(command)
    executable = Path(normalized[0]).name
    candidate = executable
    if executable.lower().startswith("python") and len(normalized) > 1:
        if normalized[1] == "-m" and len(normalized) > 2:
            candidate = normalized[2].rsplit(".", 1)[-1]
        else:
            candidate = Path(normalized[1]).stem
    elif executable.lower() in {"npx", "bunx", "pnpx"}:
        package = next((part for part in normalized[1:] if not part.startswith("-")), "upstream")
        candidate = package.rsplit("/", 1)[-1].lstrip("@")
    candidate = re.sub(r"[^a-zA-Z0-9._-]+", "-", candidate).strip("-.").lower()
    return candidate or "upstream"


def normalize_command(command: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(command[1:] if command and command[0] == "--" else command)
    if not normalized or not all(isinstance(part, str) and part for part in normalized):
        raise PolicyInitializationError("an upstream command is required after --")
    return normalized


def normalize_server_name(value: str) -> str:
    name = value.strip()
    if not name or not re.fullmatch(r"[a-zA-Z0-9._-]+", name):
        raise PolicyInitializationError(
            "server name must contain only letters, numbers, dots, underscores, or hyphens"
        )
    return name
