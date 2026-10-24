from __future__ import annotations

import copy
import json
import sys
import threading
from typing import Any, Callable

from .diagnostics import emit_operator_diagnostic, exception_diagnostic, redact_diagnostic
from .models import (
    APPROVAL_TOKEN_ARGUMENT,
    DEMO_APPROVAL_ARGUMENT,
    Tool,
    ToolCallResult,
    declared_control_arguments,
)
from .tool_integrity import ToolDriftError, ToolIntegrityError


class ToolCatalog:
    """Policy- and pin-filtered native tool catalog shared by all transports."""

    def __init__(self, runtime: Any, local_identity: str = "") -> None:
        self.runtime = runtime
        self.local_identity = local_identity
        self._lock = threading.RLock()
        self._definitions = runtime.list_tools()
        self._tools: list[Tool] = []
        self._call_servers: dict[str, str] = {}
        self._warned_pending: set[tuple[str, str]] = set()
        self._warned_collisions: set[tuple[str, str]] = set()
        self._rebuild()
        self._warn_pending()

    def tools(self, actor: str | None = None) -> list[Tool]:
        actual_actor = self.local_identity if actor is None else actor
        with self._lock:
            return [
                tool
                for tool in self._tools
                if self.runtime.policy.actor_can_call(actual_actor, tool.name)
            ]

    def names(self) -> set[str]:
        with self._lock:
            return set(self._call_servers)

    def server_for(self, tool: str) -> str | None:
        with self._lock:
            return self._call_servers.get(tool)

    def subscribe(self, emit: Callable[[], None]) -> None:
        clients = getattr(
            self.runtime,
            "clients",
            getattr(self.runtime, "external_clients", {}),
        )
        for server, client in clients.items():
            client.add_notification_handler(
                "notifications/tools/list_changed",
                lambda _message, server=server: self._refresh(server, emit),
            )

    def _refresh(self, server: str, emit: Callable[[], None]) -> None:
        try:
            definitions = self._server_definitions(server)
        except Exception as exc:
            # A failed refresh keeps the last verified catalog. Upstream text in
            # the failure is operator-only, so it goes to stderr, redacted.
            emit_operator_diagnostic(
                self._redact(exception_diagnostic(exc)),
                server=server,
            )
            return
        try:
            report = self.runtime.tool_integrity.verify(server, definitions)
            trusted = definitions
            self.runtime.tool_integrity_reports[server] = report.as_dict()
            self._warn_pending(server)
        except ToolDriftError as exc:
            excluded = set(exc.added_tools) | set(exc.changed_tools)
            trusted = [
                tool for tool in definitions if tool.get("name") not in excluded
            ]
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

    def _redact(self, text: str) -> str:
        policy = getattr(self.runtime, "policy", None)
        redact = getattr(policy, "redact_diagnostic", None)
        return redact(text) if callable(redact) else redact_diagnostic(text)

    def _server_definitions(self, server: str) -> list[dict[str, Any]]:
        upstreams = getattr(self.runtime, "upstreams", None)
        if upstreams is not None:
            return upstreams.definitions()[server]
        clients = getattr(
            self.runtime,
            "clients",
            getattr(self.runtime, "external_clients", {}),
        )
        return clients[server].list_tools()

    def _warn_pending(self, only_server: str = "") -> None:
        servers = [only_server] if only_server else list(self._definitions)
        for server in servers:
            integrity = getattr(self.runtime, "tool_integrity", None)
            metadata_map = getattr(integrity, "metadata", {})
            metadata = metadata_map.get(server)
            state_key = metadata.state_key if metadata is not None else server
            for tool in self._pending_tools(server):
                key = (server, tool)
                if key in self._warned_pending:
                    continue
                print(
                    f"Judikt pin pending: {tool}; accept with: judikt pins accept "
                    f"{state_key} --tool {tool} --yes",
                    file=sys.stderr,
                )
                self._warned_pending.add(key)

    def _pending_tools(self, server: str) -> list[str]:
        integrity = getattr(self.runtime, "tool_integrity", None)
        pending = getattr(integrity, "pending_tools", None)
        return list(pending(server)) if callable(pending) else []

    def _rebuild(self) -> None:
        tools: list[Tool] = []
        call_servers: dict[str, str] = {}
        for server, definitions in self._definitions.items():
            pending = set(self._pending_tools(server))
            for upstream in definitions:
                name = str(upstream.get("name", ""))
                if not name or name in call_servers:
                    continue
                call_servers[name] = server
                if name in pending or not self._is_allowed(server, name):
                    continue
                collisions = declared_control_arguments(upstream)
                if collisions:
                    self._warn_collision(server, name, collisions)
                    continue
                tools.append(proxy_tool(self.runtime, server, upstream))
        self._tools = tools
        self._call_servers = call_servers

    def _warn_collision(self, server: str, tool: str, fields: list[str]) -> None:
        key = (server, tool)
        if key in self._warned_collisions:
            return
        self._warned_collisions.add(key)
        print(
            f"Judikt refused to proxy {tool!r} from {server!r}: its input schema declares "
            f"Judikt control argument(s) {', '.join(fields)}. Judikt never forwards these "
            "arguments, so the tool is excluded and calls are denied with rule "
            "control_argument_collision.",
            file=sys.stderr,
        )

    def _is_allowed(self, server: str, tool: str) -> bool:
        return tool in self.runtime.policy.config["allowed_tools"].get(server, [])


def proxy_tool(runtime: Any, server: str, upstream: dict[str, Any]) -> Tool:
    name = str(upstream["name"])
    annotations = dict(upstream.get("annotations") or {})
    classification = runtime.policy.config.get("tool_classification", {}).get(
        name, {}
    )
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
        input_schema=advertised_input_schema(runtime, name, upstream),
        title=(
            upstream.get("title")
            if isinstance(upstream.get("title"), str)
            else None
        ),
        annotations=annotations or None,
        output_schema=(
            dict(upstream["outputSchema"])
            if isinstance(upstream.get("outputSchema"), dict)
            else None
        ),
        meta=(
            dict(upstream["_meta"])
            if isinstance(upstream.get("_meta"), dict)
            else None
        ),
    )


def advertised_input_schema(
    runtime: Any,
    name: str,
    upstream: dict[str, Any],
) -> dict[str, Any]:
    """Return the schema Judikt advertises for a proxied tool.

    The upstream definition is deep-copied first: pin digests are computed from
    the upstream's own definition, never from what Judikt advertises.
    """

    schema = copy.deepcopy(upstream.get("inputSchema") or {})
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        return schema if isinstance(schema, dict) else {}
    policy = runtime.policy
    may_require_approval = getattr(policy, "may_require_approval", None)
    if not callable(may_require_approval) or not may_require_approval(name, upstream):
        return schema
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        properties = {}
        schema["properties"] = properties
    properties[APPROVAL_TOKEN_ARGUMENT] = {
        "type": "string",
        "description": (
            "Judikt approval token issued by a human approver. Judikt removes it "
            "before the call reaches the upstream."
        ),
    }
    if getattr(policy, "demo_boolean_approval_enabled", False):
        properties[DEMO_APPROVAL_ARGUMENT] = {
            "type": "boolean",
            "description": (
                "Demo-only Judikt approval flag. Judikt removes it before the call "
                "reaches the upstream."
            ),
        }
    return schema


def gateway_result(guarded: ToolCallResult) -> dict[str, Any]:
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
        message += (
            " A human must obtain approval through the configured Judikt "
            "approval workflow."
        )
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
        "_meta": {"io.judikt/decision": decision},
    }
