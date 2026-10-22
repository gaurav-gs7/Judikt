from __future__ import annotations

from typing import Any

from .models import Tool
from .protocol import MCPProtocolError, serve_stdio
from .runtime import JudiktRuntime


IDENTITY_FIELDS = ("actor", "user", "requested_by")


def serve_gateway(runtime: JudiktRuntime) -> None:
    try:
        indexed_tools: dict[str, str] = {}
        tool_schemas: dict[str, dict[str, Any]] = {}
        tools: list[Tool] = []
        local_identity = _local_stdio_identity(runtime)
        for server, upstream_tools in runtime.list_tools().items():
            for upstream in upstream_tools:
                indexed_tools[upstream["name"]] = server
                tool_schemas[upstream["name"]] = upstream["inputSchema"]
                tools.append(
                    Tool(
                        upstream["name"],
                        f"[proxied via Judikt from {server}] {upstream['description']}",
                        upstream["inputSchema"],
                    )
                )

        def call(tool: str, arguments: dict[str, Any]) -> Any:
            server = indexed_tools.get(tool)
            if server is None:
                raise MCPProtocolError(f"unknown proxied tool: {tool}")
            trusted_arguments = _bind_local_identity(
                arguments,
                tool_schemas[tool],
                local_identity,
            )
            guarded = runtime.call_tool(
                server,
                tool,
                trusted_arguments,
                trusted_actor=local_identity,
            )
            if not guarded.allowed:
                return {
                    "blocked": True,
                    "correlation_id": guarded.correlation_id,
                    "reason": guarded.reason,
                }
            return guarded.as_dict()

        serve_stdio("judikt", tools, call)
    finally:
        runtime.close()


def _local_stdio_identity(runtime: JudiktRuntime) -> str:
    identity = runtime.policy.config.get("local_stdio_identity")
    if not isinstance(identity, str) or not identity.strip():
        raise ValueError(
            "unauthenticated stdio requires a non-empty local_stdio_identity in the policy config"
        )
    return identity.strip()


def _bind_local_identity(
    arguments: dict[str, Any],
    input_schema: dict[str, Any],
    identity: str,
) -> dict[str, Any]:
    """Replace untrusted stdio identity claims with operator-controlled identity."""
    trusted = {key: value for key, value in arguments.items() if key not in IDENTITY_FIELDS}
    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return trusted
    for field in IDENTITY_FIELDS:
        field_schema = properties.get(field)
        if isinstance(field_schema, dict) and field_schema.get("type", "string") == "string":
            trusted[field] = identity
    return trusted
