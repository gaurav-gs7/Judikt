from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any, Sequence

from .approval import ApprovalAuthority
from .approval_replay import build_approval_replay_store
from .audit import AuditStore
from .content_guard import ContentGuard
from .findings import FindingDispatcher, build_finding_event
from .groq import IncidentAnalyst
from .kill_switch import build_kill_switch_store
from .metrics import Metrics
from .models import ToolCallResult
from .pipeline import (
    GuardedCallPipeline,
    InMemoryCircuitBreakerStore,
    TrustedLocalIdentityProvider,
)
from .policy import PolicyEngine
from .protocol import StdioMCPClient
from .slack_approval import SlackApprovalWorkflow
from .telemetry import Telemetry
from .tool_integrity import ToolIntegrityStore, ToolPinMetadata
from .upstream_registry import StdioUpstreamRegistry
from .upstreams import UpstreamServer, create_upstream_client, load_upstream_servers


class JudiktRuntime:
    """Compatibility wrapper for the local stdio guarded-call pipeline."""

    def __init__(
        self,
        policy_path: Path,
        audit_path: Path,
        *,
        include_demo_servers: bool = False,
        upstream_servers: Sequence[UpstreamServer] | None = None,
        approval_authority: ApprovalAuthority | None = None,
        circuit_failure_threshold: int = 3,
        circuit_cooldown_seconds: int = 300,
    ) -> None:
        production = _enabled("JUDIKT_PRODUCTION")
        self.metrics = Metrics()
        self.policy = PolicyEngine(
            policy_path,
            approval_authority,
            metrics=self.metrics,
            production=production,
        )
        self.content_guard = ContentGuard.from_policy(self.policy.config)
        self.approval_replays = build_approval_replay_store(
            audit_path.with_suffix(".approval-replay.db")
        )
        audit_config = self.policy.config.get("audit", {})
        backpressure = (
            audit_config.get("backpressure")
            if isinstance(audit_config, dict)
            else None
        )
        self.audit = AuditStore(
            audit_path,
            backpressure=backpressure,
            metrics=self.metrics,
        )
        self.kill_switch_store = build_kill_switch_store(
            self.policy.config,
            metrics=self.metrics,
            audit=self.audit,
            production=production,
        )
        self.policy.bind_kill_switch_store(self.kill_switch_store)
        self.findings = FindingDispatcher(audit_path.with_suffix(".findings.db"))
        self._dispatch_startup_integrity_finding()
        self.telemetry = Telemetry()
        self.analyst = IncidentAnalyst(telemetry=self.telemetry)
        self.slack_approvals = SlackApprovalWorkflow(
            audit_path.with_suffix(".approvals.db"),
            self.policy.approvals,
        )
        self.demo_servers_enabled = include_demo_servers
        self.clients: dict[str, Any] = {}
        if include_demo_servers:
            self.clients.update(
                {
                    "platform-ops": StdioMCPClient(
                        "platform-ops", metrics=self.metrics
                    ),
                    "incident": StdioMCPClient("incident", metrics=self.metrics),
                    "kubernetes": StdioMCPClient(
                        "kubernetes", metrics=self.metrics
                    ),
                }
            )
        configured_upstreams = (
            load_upstream_servers()
            if upstream_servers is None
            else upstream_servers
        )
        pin_metadata: dict[str, ToolPinMetadata] = {}
        tool_name_prefixes: dict[str, str] = {}
        for upstream in configured_upstreams:
            if upstream.name in self.clients:
                raise ValueError(
                    f"upstream MCP server name collides with demo server: {upstream.name}"
                )
            self.clients[upstream.name] = create_upstream_client(
                upstream,
                self.metrics,
            )
            pin_metadata[upstream.name] = ToolPinMetadata(
                state_key=upstream.state_key or upstream.name,
                fingerprint=upstream.fingerprint,
                command=upstream.command
                or (
                    "streamable-http",
                    *(("--allow-private-network",) if upstream.allow_private_network else ()),
                    upstream.url,
                ),
                cwd=upstream.cwd or "",
                environment_names=tuple(
                    sorted(upstream.environment or upstream.headers)
                ),
            )
            tool_name_prefixes[upstream.name] = upstream.tool_name_prefix

        self.upstreams = StdioUpstreamRegistry(self.clients, tool_name_prefixes)
        self._circuit_store = InMemoryCircuitBreakerStore(
            circuit_failure_threshold,
            circuit_cooldown_seconds,
        )
        self._circuits = self._circuit_store.states
        pin_path = Path(
            os.getenv(
                "JUDIKT_TOOL_PIN_PATH",
                str(audit_path.with_suffix(".tool-pins.json")),
            )
        )
        self.tool_integrity = ToolIntegrityStore(
            pin_path,
            self.content_guard,
            metadata=pin_metadata,
            policy=self.policy.config,
        )
        self.tool_integrity_reports = {
            server: self.tool_integrity.verify(server, tools).as_dict()
            for server, tools in self.upstreams.definitions().items()
        }
        for server, client in self.clients.items():
            client.add_restart_handler(
                lambda restarted, server=server: self._verify_restarted_client(
                    server,
                    restarted,
                )
            )
        self.pipeline = GuardedCallPipeline(
            policy=self.policy,
            identity_provider=TrustedLocalIdentityProvider(),
            upstreams=self.upstreams,
            kill_switches=self.kill_switch_store,
            circuits=self._circuit_store,
            content_guard=self.content_guard,
            tool_integrity=self.tool_integrity,
            tool_integrity_reports=self.tool_integrity_reports,
            approval_replays=self.approval_replays,
            audit=self.audit,
            findings=self.findings,
            metrics=self.metrics,
            telemetry=self.telemetry,
            approval_workflow=self.slack_approvals,
        )

    def list_tools(self) -> dict[str, list[dict[str, Any]]]:
        return self.pipeline.list_tools()

    def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        correlation_id: str | None = None,
        *,
        trusted_actor: str = "",
    ) -> ToolCallResult:
        self.pipeline.approval_replays = self.approval_replays
        return self.pipeline.call_tool(
            server,
            tool,
            arguments,
            correlation_id,
            trusted_actor=trusted_actor,
        )

    def evaluate_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        correlation_id: str | None = None,
        *,
        trusted_actor: str = "",
    ) -> ToolCallResult:
        return self.pipeline.evaluate_tool(
            server,
            tool,
            arguments,
            correlation_id,
            trusted_actor=trusted_actor,
        )

    def request_slack_approval(
        self,
        *,
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        return self.slack_approvals.request(
            requester=actor,
            reason=reason,
            server=server,
            tool=tool,
            arguments=arguments,
            safe_arguments=self.policy.redact(arguments),
            ttl_seconds=ttl_seconds,
        )

    def slack_approval_status(self, request_id: str, actor: str) -> dict[str, Any]:
        return self.slack_approvals.status(request_id, actor)

    def kill_switches(self) -> dict[str, Any]:
        return self.policy.kill_switches()

    def set_tool_enabled(
        self,
        tool: str,
        enabled: bool,
        reason: str = "local operator request",
    ) -> None:
        self.policy.set_tool_enabled(
            tool,
            enabled,
            actor=str(self.policy.config.get("local_stdio_identity", "local-operator")),
            reason=reason,
        )

    def set_server_enabled(
        self,
        server: str,
        enabled: bool,
        reason: str = "local operator request",
    ) -> None:
        self.policy.set_server_enabled(
            server,
            enabled,
            actor=str(self.policy.config.get("local_stdio_identity", "local-operator")),
            reason=reason,
        )

    def circuit_breakers(self) -> dict[str, dict[str, Any]]:
        return self._circuit_store.snapshot()

    def recent_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.audit.recent(limit)

    def audit_integrity(self) -> dict[str, Any]:
        return self.audit.verify_chain()

    def finding_delivery(self) -> dict[str, Any]:
        return self.findings.status()

    def render_metrics(self) -> str:
        return self.metrics.render()

    def summarize_recent_events(self, limit: int = 100) -> dict[str, Any]:
        return self.analyst.summarize(self.audit.recent(limit))

    def close(self) -> None:
        self.pipeline.close()

    def _dispatch_startup_integrity_finding(self) -> None:
        report = self.audit.startup_integrity_failure
        if report is None:
            return
        outcome = self.findings.dispatch(
            build_finding_event(
                correlation_id=str(uuid.uuid4()),
                server="judikt",
                tool="audit.verify",
                allowed=False,
                rule="audit_integrity",
                action="DENY",
                reason="local startup audit verification failed",
                risk_score=100,
                risk_level="critical",
                arguments={},
                result={"status": report["status"], "errors": report["errors"]},
            )
        )
        self.metrics.observe_finding(outcome)

    def _verify_restarted_client(
        self,
        server: str,
        client: Any,
    ) -> None:
        del client
        tools = self.upstreams.definitions()[server]
        self.tool_integrity_reports[server] = self.tool_integrity.verify(
            server, tools
        ).as_dict()


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}
