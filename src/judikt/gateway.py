from __future__ import annotations

from typing import Any

from .catalog import (
    ToolCatalog as _GatewayCatalog,
    gateway_result as _gateway_result,
    proxy_tool,
)
from .protocol import serve_stdio
from .runtime import JudiktRuntime


def _proxy_tool(runtime: Any, server: str, upstream: dict[str, Any]) -> Any:
    return proxy_tool(runtime, server, upstream)


def serve_gateway(runtime: JudiktRuntime) -> None:
    try:
        local_identity = _local_stdio_identity(runtime)
        catalog = _GatewayCatalog(runtime, local_identity)

        def call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            server = catalog.server_for(tool)
            if server is None:
                raise ValueError(f"unknown proxied tool: {tool}")
            guarded = runtime.call_tool(
                server,
                tool,
                arguments,
                trusted_actor=local_identity,
            )
            return _gateway_result(guarded)

        serve_stdio(
            "judikt",
            catalog.tools(),
            call,
            tools_provider=catalog.tools,
            accepted_tool_names_provider=catalog.names,
            subscribe_list_changed=catalog.subscribe,
        )
    finally:
        runtime.close()


def _local_stdio_identity(runtime: JudiktRuntime) -> str:
    identity = runtime.policy.config.get("local_stdio_identity")
    if not isinstance(identity, str) or not identity.strip():
        raise ValueError(
            "unauthenticated stdio requires a non-empty local_stdio_identity in the policy config"
        )
    return identity.strip()
