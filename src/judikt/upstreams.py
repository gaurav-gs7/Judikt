from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .secrets import SecretBrokerError, read_aws_secret, read_vault_secret


SENSITIVE_ENV_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "PRIVATE_KEY")


class UpstreamConfigError(ValueError):
    pass


@dataclass(frozen=True)
class UpstreamServer:
    name: str
    command: tuple[str, ...]
    environment: dict[str, str]
    cwd: str | None = None
    state_key: str = ""
    fingerprint: str = ""


def load_upstream_servers(path: str | Path | None = None) -> list[UpstreamServer]:
    configured_path = path or os.getenv("JUDIKT_UPSTREAM_CONFIG", "")
    if not configured_path:
        return []
    source = Path(configured_path)
    try:
        document = json.loads(source.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise UpstreamConfigError(f"cannot load upstream MCP configuration {source}: {exc}") from exc
    servers = document.get("servers") if isinstance(document, dict) else None
    if not isinstance(servers, dict):
        raise UpstreamConfigError("upstream MCP configuration must contain a 'servers' object")

    result = []
    for name, raw in servers.items():
        if not isinstance(name, str) or not name or not isinstance(raw, dict):
            raise UpstreamConfigError("each upstream must have a non-empty name and object configuration")
        command = raw.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
            raise UpstreamConfigError(f"upstream {name!r} command must be a non-empty string array")
        cwd = raw.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise UpstreamConfigError(f"upstream {name!r} cwd must be a string")
        result.append(
            UpstreamServer(
                name=name,
                command=tuple(command),
                environment=resolve_operator_environment(name, raw.get("env", {})),
                cwd=cwd,
            )
        )
    return result


def resolve_operator_environment(server: str, configured: Any) -> dict[str, str]:
    if not isinstance(configured, dict):
        raise UpstreamConfigError(f"upstream {server!r} env must be an object")
    resolved: dict[str, str] = {}
    for target_name, source in configured.items():
        if not isinstance(target_name, str) or not target_name:
            raise UpstreamConfigError(f"upstream {server!r} has an invalid environment variable name")
        if isinstance(source, str):
            if any(marker in target_name.upper() for marker in SENSITIVE_ENV_MARKERS):
                raise UpstreamConfigError(
                    f"upstream {server!r} credential {target_name!r} must use "
                    "from_env or from_aws_secret or from_vault"
                )
            resolved[target_name] = source
            continue
        if not isinstance(source, dict):
            raise UpstreamConfigError(
                f"upstream {server!r} environment value for {target_name!r} must be a string or source object"
            )
        source_types = [
            key for key in ("from_env", "from_aws_secret", "from_vault") if key in source
        ]
        unknown_keys = set(source) - set(source_types) - {"json_key"}
        if len(source_types) != 1 or unknown_keys:
            raise UpstreamConfigError(
                f"upstream {server!r} environment source for {target_name!r} must contain "
                "exactly one supported source and optional json_key"
            )
        source_type = source_types[0]
        source_value = source[source_type]
        if not isinstance(source_value, str) or not source_value.strip():
            raise UpstreamConfigError(
                f"upstream {server!r} environment source for {target_name!r} must be a non-empty string"
            )
        json_key = source.get("json_key", "")
        if not isinstance(json_key, str):
            raise UpstreamConfigError(
                f"upstream {server!r} json_key for {target_name!r} must be a string"
            )
        if source_type == "from_env":
            if json_key:
                raise UpstreamConfigError(
                    f"upstream {server!r} from_env source for {target_name!r} cannot use json_key"
                )
            source_name = source_value
            value = os.getenv(source_name)
            if value is None:
                raise UpstreamConfigError(
                    f"upstream {server!r} requires missing operator environment variable {source_name!r}"
                )
            resolved[target_name] = value
        elif source_type == "from_aws_secret":
            resolved[target_name] = _read_aws_secret(
                source_value,
                json_key,
            )
        else:
            try:
                resolved[target_name] = read_vault_secret(
                    source_value,
                    json_key,
                )
            except SecretBrokerError as exc:
                raise UpstreamConfigError(
                    f"upstream {server!r} could not resolve Vault credential {target_name!r}: {exc}"
                ) from exc
    return resolved


def _read_aws_secret(secret_id: str, json_key: str) -> str:
    try:
        return read_aws_secret(secret_id, json_key)
    except SecretBrokerError as exc:
        raise UpstreamConfigError(str(exc)) from exc
