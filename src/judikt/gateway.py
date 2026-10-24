from __future__ import annotations

import json
import threading
from typing import Any, Callable

from .models import Tool, ToolCallResult
from .protocol import serve_stdio
from .runtime import JudiktRuntime
from .tool_integrity import ToolDriftError, ToolIntegrityError


class _GatewayCatalog:
    def __init__(self, runtime: JudiktRuntime, local_identity: str) -> None:
        self.runtime = runtime
        self.local_identity = local_identity
        self._lock = threading.RLock()
        self._definitions = runtime.list_tools()
        self._tools: list[Tool] = []
        self._call_servers: dict[str, str] = {}
        self._rebuild()

    def tools(self) -> list[Tool]:
        with self._lock:
            return list(self._tools)

    def names(self) -> set[str]:
        with self._lock:
            return set(self._call_servers)

    def server_for(self, tool: str) -> str | None:
        with self._lock:
            return self._call_servers.get(tool)

    def subscribe(self, emit: Callable[[], None]) -> None:
        for server, client in self.runtime.clients.items():
            client.add_notification_handler(
                "notifications/tools/list_changed",
                lambda _message, server=server: self._refresh(server, emit),
            )

    def _refresh(self, server: str, emit: Callable[[], None]) -> None:
        client = self.runtime.clients[server]
        try:
            definitions = client.list_tools()
            report = self.runtime.tool_integrity.verify(server, definitions)
            trusted = definitions
            self.runtime.tool_integrity_reports[server] = report.as_dict()
        except ToolDriftError as exc:
            excluded = set(exc.added_tools) | set(exc.changed_tools)
            trusted = [tool for tool in definitions if tool.get("name") not in excluded]
            self.runtime.tool_integrity_reports[server] = {
                "server": server,
                "status": "drifted",
                "excluded_tools": sorted(excluded),
            }
        except ToolIntegrityError:
            trusted = []
            self.runtime.tool_integrity_reports[server] = {
                "server": server,
                "status": "quarantined",
            }
        with self._lock:
            self._definitions[server] = trusted
            self._rebuild()
        emit()

    def _rebuild(self) -> None:
        tools: list[Tool] = []
        call_servers: dict[str, str] = {}
        for server, definitions in self._definitions.items():
            for upstream in definitions:
                name = str(upstream.get("name", ""))
                if not name or name in call_servers:
                    continue
                call_servers[name] = server
                if not self._is_allowed(server, name):
                    continue
                tools.append(_proxy_tool(self.runtime, server, upstream))
        self._tools = tools
        self._call_servers = call_servers

    def _is_allowed(self, server: str, tool: str) -> bool:
        return (
            tool in self.runtime.policy.config["allowed_tools"].get(server, [])
            and self.runtime.policy.actor_can_call(self.local_identity, tool)
        )


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


def _proxy_tool(runtime: JudiktRuntime, server: str, upstream: dict[str, Any]) -> Tool:
    name = str(upstream["name"])
    annotations = dict(upstream.get("annotations") or {})
    classification = runtime.policy.config.get("tool_classification", {}).get(name, {})
    tier = classification.get("tier") if isinstance(classification, dict) else None
    if name in runtime.policy.config.get("approval_required", []) or tier in {
        "write",
        "destructive",
    }:
        annotations["readOnlyHint"] = False
        annotations["destructiveHint"] = True
    return Tool(
        name=name,
        description=(
            f"[proxied via Judikt from {server}] "
            f"{str(upstream.get('description', ''))}"
        ),
        input_schema=dict(upstream.get("inputSchema") or {}),
        title=upstream.get("title") if isinstance(upstream.get("title"), str) else None,
        annotations=annotations or None,
        output_schema=(
            dict(upstream["outputSchema"])
            if isinstance(upstream.get("outputSchema"), dict)
            else None
        ),
        meta=dict(upstream["_meta"]) if isinstance(upstream.get("_meta"), dict) else None,
    )


def _gateway_result(guarded: ToolCallResult) -> dict[str, Any]:
    decision = {
        "correlation_id": guarded.correlation_id,
        "rule": guarded.rule,
        "action": guarded.action,
        "risk_level": guarded.risk_level,
    }
    for evidence in guarded.evidence:
        if evidence.startswith("approval_jti_sha256:"):
            decision["approval_jti_sha256"] = evidence.partition(":")[2]
        elif evidence.startswith("retry_after_seconds:"):
            try:
                decision["retry_after_seconds"] = float(evidence.partition(":")[2])
            except ValueError:
                continue
    if guarded.mcp_result is not None and (
        guarded.allowed or guarded.mcp_result.get("isError") is True
    ):
        result = dict(guarded.mcp_result)
        meta = dict(result.get("_meta") or {})
        meta["io.judikt/decision"] = decision
        result["_meta"] = meta
        return result
    if guarded.allowed:
        return {
            "content": [
                {"type": "text", "text": json.dumps(guarded.result, sort_keys=True)}
            ],
            "structuredContent": guarded.result,
            "isError": False,
            "_meta": {"io.judikt/decision": decision},
        }
    message = (
        f"Judikt blocked this call: {guarded.reason} "
        f"(rule: {guarded.rule}, correlation: {guarded.correlation_id})"
    )
    if guarded.rule == "approval_required":
        message += " A human must obtain approval through the configured Judikt approval workflow."
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
        "_meta": {"io.judikt/decision": decision},
    }


def _local_stdio_identity(runtime: JudiktRuntime) -> str:
    identity = runtime.policy.config.get("local_stdio_identity")
    if not isinstance(identity, str) or not identity.strip():
        raise ValueError(
            "unauthenticated stdio requires a non-empty local_stdio_identity in the policy config"
        )
    return identity.strip()
