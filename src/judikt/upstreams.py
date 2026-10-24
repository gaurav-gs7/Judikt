from __future__ import annotations

import json
import ipaddress
import math
import os
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .secrets import SecretBrokerError, read_aws_secret, read_vault_secret


SENSITIVE_ENV_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "PRIVATE_KEY")
MCP_TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
HTTP_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
CLOUD_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
}


class UpstreamConfigError(ValueError):
    pass


@dataclass(frozen=True)
class UpstreamServer:
    name: str
    command: tuple[str, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    state_key: str = ""
    fingerprint: str = ""
    timeouts: dict[str, float] = field(default_factory=dict)
    tool_name_prefix: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    allow_private_network: bool = False
    expose_error_messages: bool = False


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
        url = raw.get("url")
        if (command is None) == (url is None):
            raise UpstreamConfigError(
                f"upstream {name!r} must configure exactly one of command or url"
            )
        if command is not None and (
            not isinstance(command, list)
            or not command
            or not all(isinstance(part, str) and part for part in command)
        ):
            raise UpstreamConfigError(
                f"upstream {name!r} command must be a non-empty string array"
            )
        if url is not None and (not isinstance(url, str) or not url.strip()):
            raise UpstreamConfigError(f"upstream {name!r} url must be a non-empty string")
        if command is not None and ("headers" in raw or "allow_private_network" in raw):
            raise UpstreamConfigError(
                f"upstream {name!r} headers and allow_private_network require url"
            )
        if url is not None and "env" in raw:
            raise UpstreamConfigError(f"upstream {name!r} env is only valid with command")
        allow_private_network = raw.get("allow_private_network", False)
        if not isinstance(allow_private_network, bool):
            raise UpstreamConfigError(
                f"upstream {name!r} allow_private_network must be a boolean"
            )
        if url is not None:
            validate_remote_url(url.strip(), allow_private_network, resolve_dns=False)
        expose_error_messages = raw.get("expose_error_messages", False)
        if not isinstance(expose_error_messages, bool):
            raise UpstreamConfigError(
                f"upstream {name!r} expose_error_messages must be a boolean"
            )
        cwd = raw.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise UpstreamConfigError(f"upstream {name!r} cwd must be a string")
        if url is not None and cwd is not None:
            raise UpstreamConfigError(f"upstream {name!r} cwd is only valid with command")
        tool_name_prefix = raw.get("tool_name_prefix", "")
        if not isinstance(tool_name_prefix, str) or (
            tool_name_prefix and MCP_TOOL_NAME_PATTERN.fullmatch(tool_name_prefix) is None
        ):
            raise UpstreamConfigError(
                f"upstream {name!r} tool_name_prefix must follow MCP tool-name rules"
            )
        result.append(
            UpstreamServer(
                name=name,
                command=tuple(command or ()),
                environment=(
                    resolve_operator_environment(name, raw.get("env", {}))
                    if command is not None
                    else {}
                ),
                cwd=cwd,
                timeouts=_parse_timeouts(name, raw.get("timeouts", {})),
                tool_name_prefix=tool_name_prefix,
                url=url.strip() if isinstance(url, str) else "",
                headers=(
                    resolve_operator_headers(name, raw.get("headers", {}))
                    if url is not None
                    else {}
                ),
                allow_private_network=allow_private_network,
                expose_error_messages=expose_error_messages,
            )
        )
    return result


def _parse_timeouts(server: str, configured: Any) -> dict[str, float]:
    if not isinstance(configured, dict):
        raise UpstreamConfigError(f"upstream {server!r} timeouts must be an object")
    unknown = set(configured) - {"initialize", "list", "call"}
    if unknown:
        raise UpstreamConfigError(
            f"upstream {server!r} has unknown timeout keys: {', '.join(sorted(unknown))}"
        )
    result: dict[str, float] = {}
    for name, value in configured.items():
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise UpstreamConfigError(
                f"upstream {server!r} timeout {name!r} must be a positive number"
            )
        result[name] = float(value)
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


def resolve_operator_headers(server: str, configured: Any) -> dict[str, str]:
    if not isinstance(configured, dict):
        raise UpstreamConfigError(f"upstream {server!r} headers must be an object")
    resolved: dict[str, str] = {}
    for header_name, source in configured.items():
        if (
            not isinstance(header_name, str)
            or HTTP_HEADER_NAME_PATTERN.fullmatch(header_name) is None
        ):
            raise UpstreamConfigError(f"upstream {server!r} has an invalid HTTP header name")
        if header_name.lower() in {"host", "content-length", "transfer-encoding"}:
            raise UpstreamConfigError(
                f"upstream {server!r} may not configure transport header {header_name!r}"
            )
        if not isinstance(source, dict):
            raise UpstreamConfigError(
                f"upstream {server!r} header {header_name!r} must use "
                "from_env or from_aws_secret or from_vault"
            )
        value = _resolve_operator_source(server, f"header {header_name!r}", source)
        if "\r" in value or "\n" in value:
            raise UpstreamConfigError(
                f"upstream {server!r} header {header_name!r} contains a newline"
            )
        resolved[header_name] = value
    return resolved


def validate_remote_url(
    url: str,
    allow_private_network: bool,
    *,
    resolve_dns: bool = True,
) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UpstreamConfigError("remote upstream url has an invalid port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UpstreamConfigError("remote upstream url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise UpstreamConfigError(
            "remote upstream url must not contain credentials or a fragment"
        )
    localhost = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not localhost:
        raise UpstreamConfigError("remote upstream url requires HTTPS except on localhost")
    if allow_private_network:
        return
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    try:
        addresses.add(ipaddress.ip_address(parsed.hostname))
    except ValueError:
        if not resolve_dns:
            return
        try:
            for item in socket.getaddrinfo(
                parsed.hostname,
                port,
                type=socket.SOCK_STREAM,
            ):
                addresses.add(ipaddress.ip_address(item[4][0]))
        except socket.gaierror as exc:
            raise UpstreamConfigError(
                f"remote upstream hostname {parsed.hostname!r} could not be resolved"
            ) from exc
    if not addresses:
        raise UpstreamConfigError(
            f"remote upstream hostname {parsed.hostname!r} resolved to no addresses"
        )
    for address in addresses:
        if (
            address in CLOUD_METADATA_ADDRESSES
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise UpstreamConfigError(
                f"remote upstream url resolves to disallowed address {address}"
            )


def _resolve_operator_source(server: str, label: str, source: dict[str, Any]) -> str:
    source_types = [
        key for key in ("from_env", "from_aws_secret", "from_vault") if key in source
    ]
    unknown_keys = set(source) - set(source_types) - {"json_key"}
    if len(source_types) != 1 or unknown_keys:
        raise UpstreamConfigError(
            f"upstream {server!r} source for {label} must contain exactly one "
            "supported source and optional json_key"
        )
    source_type = source_types[0]
    source_value = source[source_type]
    if not isinstance(source_value, str) or not source_value.strip():
        raise UpstreamConfigError(
            f"upstream {server!r} source for {label} must be a non-empty string"
        )
    json_key = source.get("json_key", "")
    if not isinstance(json_key, str):
        raise UpstreamConfigError(f"upstream {server!r} json_key for {label} must be a string")
    if source_type == "from_env":
        if json_key:
            raise UpstreamConfigError(
                f"upstream {server!r} from_env source for {label} cannot use json_key"
            )
        value = os.getenv(source_value)
        if value is None:
            raise UpstreamConfigError(
                f"upstream {server!r} requires missing operator environment variable {source_value!r}"
            )
        return value
    if source_type == "from_aws_secret":
        return _read_aws_secret(source_value, json_key)
    try:
        return read_vault_secret(source_value, json_key)
    except SecretBrokerError as exc:
        raise UpstreamConfigError(
            f"upstream {server!r} could not resolve Vault credential for {label}: {exc}"
        ) from exc


def _read_aws_secret(secret_id: str, json_key: str) -> str:
    try:
        return read_aws_secret(secret_id, json_key)
    except SecretBrokerError as exc:
        raise UpstreamConfigError(str(exc)) from exc


def create_upstream_client(upstream: UpstreamServer, metrics: Any = None) -> Any:
    if upstream.url:
        from .remote_protocol import StreamableHTTPMCPClient

        return StreamableHTTPMCPClient(
            upstream.name,
            url=upstream.url,
            headers=upstream.headers,
            allow_private_network=upstream.allow_private_network,
            timeouts=upstream.timeouts,
            metrics=metrics,
            expose_error_messages=upstream.expose_error_messages,
        )
    from .protocol import StdioMCPClient

    return StdioMCPClient(
        upstream.name,
        command=upstream.command,
        environment=upstream.environment,
        cwd=upstream.cwd,
        inherit_environment=False,
        timeouts=upstream.timeouts,
        metrics=metrics,
        expose_error_messages=upstream.expose_error_messages,
    )
