from __future__ import annotations

from typing import Any

from .models import Tool
from .protocol import MCPProtocolError, serve_stdio
from .runtime import JudiktRuntime


def serve_gateway(runtime: JudiktRuntime) -> None:
    try:
        indexed_tools: dict[str, str] = {}
        tools: list[Tool] = []
        local_identity = _local_stdio_identity(runtime)
        for server, upstream_tools in runtime.list_tools().items():
            for upstream in upstream_tools:
                indexed_tools[upstream["name"]] = server
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
            guarded = runtime.call_tool(
                server,
                tool,
                arguments,
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
