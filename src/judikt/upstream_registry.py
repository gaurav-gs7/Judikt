from __future__ import annotations

from typing import Any, Protocol

from .backends import (
    INCIDENT_TOOLS,
    KUBERNETES_TOOLS,
    PLATFORM_TOOLS,
    IncidentBackend,
    KubernetesBackend,
    PlatformOpsBackend,
)
from .protocol import StdioMCPClient
from .tool_integrity import verify_unique_tool_names


class UpstreamRegistry(Protocol):
    @property
    def clients(self) -> dict[str, StdioMCPClient]: ...

    @property
    def incident_backend(self) -> IncidentBackend | None: ...

    def definitions(self) -> dict[str, list[dict[str, Any]]]: ...

    def execute(self, server: str, tool: str, arguments: dict[str, Any]) -> Any: ...

    def close(self) -> None: ...


class StdioUpstreamRegistry:
    """Registry for upstream MCP servers managed as stdio subprocesses."""

    def __init__(self, clients: dict[str, StdioMCPClient]) -> None:
        self._clients = clients

    @property
    def clients(self) -> dict[str, StdioMCPClient]:
        return self._clients

    @property
    def incident_backend(self) -> None:
        return None

    def definitions(self) -> dict[str, list[dict[str, Any]]]:
        result = {server: client.list_tools() for server, client in self._clients.items()}
        verify_unique_tool_names(result)
        return result

    def execute(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        client = self._clients.get(server)
        if client is None:
            raise ValueError(f"unknown server: {server}")
        return client.call_tool(tool, arguments)

    def close(self) -> None:
        for client in self._clients.values():
            client.close()


class OperationsUpstreamRegistry:
    """Registry for in-process operational adapters plus external MCP servers."""

    def __init__(
        self,
        *,
        platform: PlatformOpsBackend | None,
        kubernetes: KubernetesBackend | None,
        incidents: IncidentBackend | None,
        external_clients: dict[str, StdioMCPClient],
    ) -> None:
        self.platform = platform
        self.kubernetes = kubernetes
        self.incidents = incidents
        self._clients = external_clients

    @property
    def clients(self) -> dict[str, StdioMCPClient]:
        return self._clients

    @property
    def incident_backend(self) -> IncidentBackend | None:
        return self.incidents

    def definitions(self) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        if self.platform is not None:
            result["platform-ops"] = [tool.as_mcp() for tool in PLATFORM_TOOLS]
        if self.kubernetes is not None:
            result["kubernetes"] = [tool.as_mcp() for tool in KUBERNETES_TOOLS]
        if self.incidents is not None:
            result["incident"] = [tool.as_mcp() for tool in INCIDENT_TOOLS]
        result.update(
            {server: client.list_tools() for server, client in self._clients.items()}
        )
        verify_unique_tool_names(result)
        return result

    def execute(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        if server == "platform-ops" and self.platform is not None:
            return self.platform.call(tool, arguments)
        if server == "kubernetes" and self.kubernetes is not None:
            return self.kubernetes.call(tool, arguments)
        if server == "incident" and self.incidents is not None:
            return self.incidents.call(tool, arguments)
        client = self._clients.get(server)
        if client is not None:
            return client.call_tool(tool, arguments)
        raise ValueError(f"unknown server: {server}")

    def close(self) -> None:
        for client in self._clients.values():
            client.close()
