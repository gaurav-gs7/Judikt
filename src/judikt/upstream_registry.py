from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .backends import (
    INCIDENT_TOOLS,
    KUBERNETES_TOOLS,
    PLATFORM_TOOLS,
    IncidentBackend,
    KubernetesBackend,
    PlatformOpsBackend,
)
from .diagnostics import emit_operator_diagnostic, exception_diagnostic, redact_diagnostic
from .tool_integrity import verify_unique_tool_names
from .upstreams import MCP_TOOL_NAME_PATTERN

DEFAULT_CATALOG_TTL_SECONDS = 30.0


class UpstreamRegistry(Protocol):
    @property
    def clients(self) -> dict[str, Any]: ...

    @property
    def incident_backend(self) -> IncidentBackend | None: ...

    def definitions(
        self,
        require: str | None = None,
    ) -> dict[str, list[dict[str, Any]]]: ...

    def invalidate(self, server: str) -> None: ...

    def execute(self, server: str, tool: str, arguments: dict[str, Any]) -> Any: ...

    def close(self) -> None: ...


def default_catalog_ttl_seconds() -> float:
    raw = os.getenv("JUDIKT_UPSTREAM_CATALOG_TTL_SECONDS", "").strip()
    if not raw:
        return DEFAULT_CATALOG_TTL_SECONDS
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError("JUDIKT_UPSTREAM_CATALOG_TTL_SECONDS must be a number >= 0") from exc
    if value != value or value < 0 or value == float("inf"):
        raise ValueError("JUDIKT_UPSTREAM_CATALOG_TTL_SECONDS must be a number >= 0")
    return value


@dataclass
class _CatalogEntry:
    definitions: list[dict[str, Any]]
    fetched_at: float
    stale: bool = False


class UpstreamCatalogCache:
    """Per-upstream cache of tool definitions.

    ``tools/list`` is no longer sent on every guarded call. An entry is
    refreshed when its TTL expires, when the upstream sends
    ``notifications/tools/list_changed``, and when a subprocess restarts.
    A TTL of 0 refreshes on every call.

    When a refresh fails, the last successfully fetched catalog keeps serving
    for up to twice the TTL after that fetch; the pipeline still applies pins
    and policy to it, so only already-pinned, allowed tools can run. After
    that window the original failure is raised.
    """

    def __init__(
        self,
        clients: dict[str, Any],
        tool_name_prefixes: dict[str, str],
        ttl_seconds: dict[str, float] | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clients = clients
        self._prefixes = tool_name_prefixes
        default_ttl = default_catalog_ttl_seconds()
        self._ttls = {
            server: float((ttl_seconds or {}).get(server, default_ttl))
            for server in clients
        }
        self._clock = clock
        self._entries: dict[str, _CatalogEntry] = {}
        # Re-entrant: a refresh can restart a subprocess whose restart hook
        # re-lists the same upstream on this thread.
        self._locks = {server: threading.RLock() for server in clients}
        self._entries_lock = threading.Lock()
        for server, client in clients.items():
            add_notification = getattr(client, "add_notification_handler", None)
            if callable(add_notification):
                add_notification(
                    "notifications/tools/list_changed",
                    lambda _message, server=server: self.invalidate(server),
                )
            add_restart = getattr(client, "add_restart_handler", None)
            if callable(add_restart):
                add_restart(lambda _client, server=server: self.invalidate(server))

    def ttl(self, server: str) -> float:
        return self._ttls.get(server, DEFAULT_CATALOG_TTL_SECONDS)

    def invalidate(self, server: str) -> None:
        with self._entries_lock:
            entry = self._entries.get(server)
            if entry is not None:
                entry.stale = True

    def peek(self, server: str) -> list[dict[str, Any]] | None:
        """Return the last fetched catalog without refreshing it."""

        with self._entries_lock:
            entry = self._entries.get(server)
        return entry.definitions if entry is not None else None

    def get(self, server: str) -> list[dict[str, Any]]:
        client = self._clients[server]
        ttl = self.ttl(server)
        with self._locks[server]:
            with self._entries_lock:
                entry = self._entries.get(server)
            now = self._clock()
            if (
                entry is not None
                and not entry.stale
                and ttl > 0
                and now - entry.fetched_at < ttl
            ):
                return entry.definitions
            try:
                definitions = _prefixed_definitions(
                    client.list_tools(), self._prefixes.get(server, ""), server
                )
            except Exception as exc:
                now = self._clock()
                if entry is not None and ttl > 0 and now - entry.fetched_at < 2 * ttl:
                    emit_operator_diagnostic(
                        redact_diagnostic(
                            "tool catalog refresh failed; serving the last verified "
                            f"catalog for up to {2 * ttl:g}s: {exception_diagnostic(exc)}"
                        ),
                        server=server,
                    )
                    return entry.definitions
                raise
            with self._entries_lock:
                self._entries[server] = _CatalogEntry(definitions, self._clock())
            return definitions


class StdioUpstreamRegistry:
    """Registry for upstream MCP servers managed as stdio subprocesses."""

    def __init__(
        self,
        clients: dict[str, Any],
        tool_name_prefixes: dict[str, str] | None = None,
        catalog_ttl_seconds: dict[str, float] | None = None,
    ) -> None:
        self._clients = clients
        self._tool_name_prefixes = tool_name_prefixes or {}
        self.catalog = UpstreamCatalogCache(
            clients, self._tool_name_prefixes, catalog_ttl_seconds
        )

    @property
    def clients(self) -> dict[str, Any]:
        return self._clients

    @property
    def incident_backend(self) -> None:
        return None

    def definitions(
        self,
        require: str | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        result = _cached_definitions(self.catalog, self._clients, require)
        verify_unique_tool_names(result)
        return result

    def invalidate(self, server: str) -> None:
        self.catalog.invalidate(server)

    def execute(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        client = self._clients.get(server)
        if client is None:
            raise ValueError(f"unknown server: {server}")
        return client.call_tool(
            _upstream_tool_name(tool, self._tool_name_prefixes.get(server, "")),
            arguments,
        )

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
        external_clients: dict[str, Any],
        tool_name_prefixes: dict[str, str] | None = None,
        catalog_ttl_seconds: dict[str, float] | None = None,
    ) -> None:
        self.platform = platform
        self.kubernetes = kubernetes
        self.incidents = incidents
        self._clients = external_clients
        self._tool_name_prefixes = tool_name_prefixes or {}
        self.catalog = UpstreamCatalogCache(
            external_clients, self._tool_name_prefixes, catalog_ttl_seconds
        )

    @property
    def clients(self) -> dict[str, Any]:
        return self._clients

    @property
    def incident_backend(self) -> IncidentBackend | None:
        return self.incidents

    def definitions(
        self,
        require: str | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        if self.platform is not None:
            result["platform-ops"] = [tool.as_mcp() for tool in PLATFORM_TOOLS]
        if self.kubernetes is not None:
            result["kubernetes"] = [tool.as_mcp() for tool in KUBERNETES_TOOLS]
        if self.incidents is not None:
            result["incident"] = [tool.as_mcp() for tool in INCIDENT_TOOLS]
        result.update(_cached_definitions(self.catalog, self._clients, require))
        verify_unique_tool_names(result)
        return result

    def invalidate(self, server: str) -> None:
        self.catalog.invalidate(server)

    def execute(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        if server == "platform-ops" and self.platform is not None:
            return self.platform.call(tool, arguments)
        if server == "kubernetes" and self.kubernetes is not None:
            return self.kubernetes.call(tool, arguments)
        if server == "incident" and self.incidents is not None:
            return self.incidents.call(tool, arguments)
        client = self._clients.get(server)
        if client is not None:
            return client.call_tool(
                _upstream_tool_name(tool, self._tool_name_prefixes.get(server, "")),
                arguments,
            )
        raise ValueError(f"unknown server: {server}")

    def close(self) -> None:
        for client in self._clients.values():
            client.close()


def _cached_definitions(
    catalog: UpstreamCatalogCache,
    clients: dict[str, Any],
    require: str | None,
) -> dict[str, list[dict[str, Any]]]:
    """Collect cached catalogs.

    Without ``require`` every catalog is refreshed as needed and every failure
    is raised (startup and catalog listing). With ``require`` only that
    server's catalog is refreshed; the others are read from cache for the
    cross-server shadowing check, so a slow or failed upstream never delays or
    denies calls to a healthy one.
    """

    result: dict[str, list[dict[str, Any]]] = {}
    for server in clients:
        if require is None or server == require:
            result[server] = catalog.get(server)
            continue
        cached = catalog.peek(server)
        if cached is not None:
            result[server] = cached
            continue
        try:
            result[server] = catalog.get(server)
        except Exception as exc:
            emit_operator_diagnostic(
                redact_diagnostic(exception_diagnostic(exc)),
                server=server,
            )
    return result


def _prefixed_definitions(
    definitions: list[dict[str, Any]], prefix: str, server: str
) -> list[dict[str, Any]]:
    if not prefix:
        return definitions
    result = []
    for definition in definitions:
        prefixed = dict(definition)
        prefixed["name"] = f"{prefix}{definition.get('name', '')}"
        if MCP_TOOL_NAME_PATTERN.fullmatch(str(prefixed["name"])) is None:
            raise ValueError(
                f"prefixed tool name {prefixed['name']!r} from {server!r} "
                "does not follow MCP tool-name rules"
            )
        result.append(prefixed)
    return result


def _upstream_tool_name(tool: str, prefix: str) -> str:
    if not prefix:
        return tool
    if not tool.startswith(prefix):
        raise ValueError(f"tool {tool!r} does not use configured prefix {prefix!r}")
    return tool[len(prefix) :]
