from __future__ import annotations

import json
import re
import urllib.parse
from copy import deepcopy
from pathlib import Path
from typing import Any, Sequence

from .paths import DEFAULT_POLICY_PATH
from .protocol import StdioMCPClient


STARTER_PROFILES = ("read-only", "approve-writes", "permissive")
WRITE_NAME_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:create|update|put|post|patch|set|move|rename|write|send|upload|push|merge)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
DESTRUCTIVE_NAME_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:delete|remove|drop|destroy|purge|kill|restart|rollback|exec|execute|run|deploy)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
# Union of both verb sets, kept for callers that only need "does this name
# mutate anything".
MUTATION_NAME_PATTERN = re.compile(
    rf"{WRITE_NAME_PATTERN.pattern}|{DESTRUCTIVE_NAME_PATTERN.pattern}",
    re.IGNORECASE,
)


def name_implied_tier(name: str) -> str:
    """Return the minimum tier a tool name implies."""

    if DESTRUCTIVE_NAME_PATTERN.search(name) is not None:
        return "destructive"
    if WRITE_NAME_PATTERN.search(name) is not None:
        return "write"
    return "read"


class PolicyInitializationError(ValueError):
    pass


def initialize_policy(
    command: Sequence[str],
    *,
    server_name: str,
    output_path: Path,
    identity: str = "local-operator",
    profile: str = "read-only",
    force: bool = False,
) -> dict[str, Any]:
    normalized_command = normalize_command(command)
    normalized_name = normalize_server_name(server_name)
    normalized_identity = identity.strip()
    if not normalized_identity:
        raise PolicyInitializationError("local identity must not be empty")
    normalized_profile = normalize_profile(profile)
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

    return _write_starter_policy(
        tools,
        server_name=normalized_name,
        output_path=output_path,
        identity=normalized_identity,
        profile=normalized_profile,
    )


def initialize_policy_from_tools(
    tools: Sequence[dict[str, Any]],
    *,
    server_name: str,
    output_path: Path,
    identity: str = "local-operator",
    profile: str = "read-only",
    force: bool = False,
) -> dict[str, Any]:
    normalized_name = normalize_server_name(server_name)
    normalized_identity = identity.strip()
    if not normalized_identity:
        raise PolicyInitializationError("local identity must not be empty")
    normalized_profile = normalize_profile(profile)
    if output_path.exists() and not force:
        raise PolicyInitializationError(
            f"refusing to overwrite existing policy: {output_path}; pass --force to replace it"
        )
    return _write_starter_policy(
        tools,
        server_name=normalized_name,
        output_path=output_path,
        identity=normalized_identity,
        profile=normalized_profile,
    )


def _write_starter_policy(
    tools: Sequence[dict[str, Any]],
    *,
    server_name: str,
    output_path: Path,
    identity: str,
    profile: str,
) -> dict[str, Any]:

    policy = starter_policy(
        server_name,
        tools,
        identity=identity,
        profile=profile,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    return {
        "policy": str(output_path),
        "server": server_name,
        "tool_count": len(policy["allowed_tools"][server_name]),
        "tools": policy["allowed_tools"][server_name],
        "classification_summary": classification_summary(policy, profile),
    }


def starter_policy(
    server_name: str,
    tools: Sequence[dict[str, Any]],
    *,
    identity: str = "local-operator",
    profile: str = "read-only",
) -> dict[str, Any]:
    server_name = normalize_server_name(server_name)
    identity = identity.strip()
    if not identity:
        raise PolicyInitializationError("local identity must not be empty")
    profile = normalize_profile(profile)
    names: list[str] = []
    classifications: dict[str, dict[str, Any]] = {}
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
        classifications[name] = classify_tool(name, tool)
    if not names:
        raise PolicyInitializationError("upstream tools/list returned no tools")

    policy = deepcopy(json.loads(DEFAULT_POLICY_PATH.read_text()))
    if profile == "read-only":
        allowed_names = [name for name in names if classifications[name]["tier"] == "read"]
        approval_required: list[str] = []
    elif profile == "approve-writes":
        allowed_names = names
        approval_required = [name for name in names if classifications[name]["tier"] != "read"]
    else:
        allowed_names = names
        approval_required = []
    policy["local_stdio_identity"] = identity
    policy["actor_permissions"] = {identity: allowed_names, "anonymous": []}
    policy["allowed_tools"] = {server_name: allowed_names}
    policy["approval_required"] = approval_required
    policy["tool_classification"] = classifications
    return policy


def classify_tool(name: str, tool: dict[str, Any]) -> dict[str, Any]:
    raw_annotations = tool.get("annotations", {})
    annotations = dict(raw_annotations) if isinstance(raw_annotations, dict) else {}
    read_only = annotations.get("readOnlyHint") is True
    mutation_name = MUTATION_NAME_PATTERN.search(name) is not None
    conflict = read_only and mutation_name
    if read_only and not mutation_name:
        tier = "read"
    elif not read_only and annotations.get("destructiveHint") is False:
        tier = "write"
    else:
        tier = "destructive"
    return {
        "tier": tier,
        "annotations": annotations,
        "conflict": conflict,
    }


def classification_summary(policy: dict[str, Any], profile: str) -> dict[str, Any]:
    classifications = policy["tool_classification"]
    allowed = {
        tool
        for tools in policy["allowed_tools"].values()
        for tool in tools
    }
    approval_required = set(policy["approval_required"])
    return {
        "profile": profile,
        "counts": {
            tier: sum(
                details["tier"] == tier for details in classifications.values()
            )
            for tier in ("read", "write", "destructive")
        },
        "excluded_tools": [tool for tool in classifications if tool not in allowed],
        "approval_gated_tools": [
            tool for tool in classifications if tool in approval_required
        ],
        "conflicts": [
            tool for tool, details in classifications.items() if details["conflict"]
        ],
    }


def normalize_profile(value: str) -> str:
    if value not in STARTER_PROFILES:
        choices = ", ".join(STARTER_PROFILES)
        raise PolicyInitializationError(f"profile must be one of: {choices}")
    return value


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


def derive_remote_server_name(url: str) -> str:
    """Derive a default server name from a remote URL's host.

    IPv6 literals such as ``[::1]`` contain colons, so any character outside
    the server-name alphabet becomes ``-`` and leading or trailing separators
    are stripped. The URL's address policy is checked separately.
    """

    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    candidate = re.sub(r"[^a-zA-Z0-9._-]+", "-", host).strip("-._")
    return candidate or "remote"


def normalize_server_name(value: str) -> str:
    name = value.strip()
    if not name or not re.fullmatch(r"[a-zA-Z0-9._-]+", name):
        raise PolicyInitializationError(
            "server name must contain only letters, numbers, dots, underscores, or hyphens"
        )
    return name
