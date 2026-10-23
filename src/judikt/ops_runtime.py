from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority
from .approval_replay import approval_jti_digest, build_approval_replay_store
from .audit import AuditStore
from .content_guard import ContentGuard, quarantine_result
from .findings import FindingDispatcher, build_finding_event, should_emit_finding
from .backends import (
    INCIDENT_TOOLS,
    KUBERNETES_TOOLS,
    PLATFORM_TOOLS,
    IncidentBackend,
    KubernetesBackend,
    PlatformOpsBackend,
)
from .metrics import Metrics
from .models import ToolCallResult
from .policy import PolicyEngine
from .request_context import authenticated_subject
from .slack_approval import SlackApprovalWorkflow
from .telemetry import Telemetry
from .tool_integrity import (
    ToolDriftError,
    ToolIntegrityError,
    ToolIntegrityStore,
    ToolPinMetadata,
    verify_unique_tool_names,
)
from .protocol import StdioMCPClient, UpstreamTimeoutError, is_mcp_tool_error
from .upstreams import load_upstream_servers


@dataclass
class CircuitState:
    failure_count: int = 0
    open_until: float = 0
    last_error: str = ""


class JudiktOpsRuntime:
    """Production-facing runtime used by the official MCP server.

    Unlike the local demo runtime, this calls durable tool adapters directly
    instead of forking stdio subprocesses. That makes it a better fit for an
    HTTP MCP server running inside Docker on EC2 or ECS.
    """

    def __init__(
        self,
        policy_path: Path,
        audit_path: Path,
        *,
        include_demo_servers: bool = False,
        circuit_failure_threshold: int = 3,
        circuit_cooldown_seconds: int = 300,
        approval_authority: ApprovalAuthority | None = None,
        remote_mode: bool = False,
    ) -> None:
        self.policy = PolicyEngine(policy_path, approval_authority)
        self.content_guard = ContentGuard.from_policy(self.policy.config)
        self.approval_replays = build_approval_replay_store(
            audit_path.with_suffix(".approval-replay.db"),
            remote_mode=remote_mode,
        )
        self.metrics = Metrics()
        audit_config = self.policy.config.get("audit", {})
        backpressure = audit_config.get("backpressure") if isinstance(audit_config, dict) else None
        self.audit = AuditStore(
            audit_path,
            require_configured_key=remote_mode,
            backpressure=backpressure,
            metrics=self.metrics,
        )
        self.findings = FindingDispatcher(audit_path.with_suffix(".findings.db"))
        self._dispatch_startup_integrity_finding()
        self.slack_approvals = SlackApprovalWorkflow(
            audit_path.with_suffix(".approvals.db"),
            self.policy.approvals,
        )
        self.telemetry = Telemetry()
        self.demo_servers_enabled = include_demo_servers
        self.platform = PlatformOpsBackend() if include_demo_servers else None
        self.kubernetes = KubernetesBackend() if include_demo_servers else None
        self.incidents = IncidentBackend() if include_demo_servers else None
        self.external_clients: dict[str, StdioMCPClient] = {}
        pin_metadata: dict[str, ToolPinMetadata] = {}
        for upstream in load_upstream_servers():
            if include_demo_servers and upstream.name in {"platform-ops", "kubernetes", "incident"}:
                raise ValueError(f"upstream MCP server name collides with demo server: {upstream.name}")
            self.external_clients[upstream.name] = StdioMCPClient(
                upstream.name,
                command=upstream.command,
                environment=upstream.environment,
                cwd=upstream.cwd,
                inherit_environment=False,
                timeouts=upstream.timeouts,
                metrics=self.metrics,
            )
            pin_metadata[upstream.name] = ToolPinMetadata(
                state_key=upstream.state_key or upstream.name,
                fingerprint=upstream.fingerprint,
                command=upstream.command,
                cwd=upstream.cwd or "",
                environment_names=tuple(sorted(upstream.environment)),
            )
        self._circuits: dict[tuple[str, str], CircuitState] = {}
        self._circuit_failure_threshold = circuit_failure_threshold
        self._circuit_cooldown_seconds = circuit_cooldown_seconds
        pin_path = Path(os.getenv("JUDIKT_TOOL_PIN_PATH", str(audit_path.with_suffix(".tool-pins.json"))))
        self.tool_integrity = ToolIntegrityStore(
            pin_path,
            self.content_guard,
            metadata=pin_metadata,
        )
        self.tool_integrity_reports = {
            server: self.tool_integrity.verify(server, tools).as_dict()
            for server, tools in self._all_tool_definitions().items()
        }
        for server, client in self.external_clients.items():
            client.add_restart_handler(
                lambda restarted, server=server: self._verify_restarted_client(
                    server,
                    restarted,
                )
            )

    def list_tools(self) -> dict[str, list[dict[str, Any]]]:
        definitions = self._all_tool_definitions()
        verify_unique_tool_names(definitions)
        for server, tools in definitions.items():
            self.tool_integrity_reports[server] = self.tool_integrity.verify(server, tools).as_dict()
        return definitions

    def _all_tool_definitions(self) -> dict[str, list[dict[str, Any]]]:
        definitions = {}
        if self.demo_servers_enabled:
            definitions.update(
                {
                    "platform-ops": [tool.as_mcp() for tool in PLATFORM_TOOLS],
                    "kubernetes": [tool.as_mcp() for tool in KUBERNETES_TOOLS],
                    "incident": [tool.as_mcp() for tool in INCIDENT_TOOLS],
                }
            )
        definitions.update(
            {server: client.list_tools() for server, client in self.external_clients.items()}
        )
        verify_unique_tool_names(definitions)
        return definitions

    def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        correlation_id: str | None = None,
    ) -> ToolCallResult:
        correlation_id = correlation_id or str(uuid.uuid4())
        started = time.perf_counter()
        safe_arguments = self.policy.redact(arguments)
        result: Any = None
        mcp_result: dict[str, Any] | None = None
        decision = self.policy.evaluate(
            server,
            tool,
            arguments,
            authenticated_actor=authenticated_subject(),
        )
        allowed = decision.allowed
        reason = decision.reason
        rule = decision.rule
        evidence = list(decision.evidence)

        if allowed and self.audit.deny_for_backpressure():
            allowed = False
            rule = "audit_backpressure"
            reason = "audit delivery backlog exceeded the configured safety threshold"

        circuit = self._circuits.get((server, tool), CircuitState())
        if allowed and circuit.open_until > time.time():
            allowed = False
            rule = "circuit_breaker"
            reason = "circuit breaker is open after repeated upstream failures"

        with self.telemetry.span(
            "judikt.real_mcp.call_tool",
            "CHAIN",
            {
                "judikt.correlation_id": correlation_id,
                "judikt.server": server,
                "judikt.tool": tool,
            },
        ) as request_span:
            request_span.set_json_input(safe_arguments)
            request_span.set_policy(allowed=allowed, rule=rule, reason=reason)
            request_span.set_attribute("judikt.risk.score", decision.risk_score)
            request_span.set_attribute("judikt.risk.level", decision.risk_level)
            request_span.set_attribute("judikt.policy.action", decision.action)
            if allowed:
                if decision.action in {"DRY_RUN_ONLY", "SHADOW_MODE"}:
                    result = self._evaluation_only_result(decision.action, server, tool, safe_arguments)
                else:
                    try:
                        definitions = self._all_tool_definitions().get(server, [])
                        self.tool_integrity_reports[server] = self.tool_integrity.verify(server, definitions).as_dict()
                        claims = self.policy.approval_claims(server, tool, arguments)
                        if claims is not None:
                            evidence.append(
                                f"approval_jti_sha256:{approval_jti_digest(claims.jti)}"
                            )
                            if not self.approval_replays.consume(claims.jti, claims.expires_at):
                                allowed = False
                                rule = "approval_replay"
                                reason = "approval token has already been used"
                        if not allowed:
                            raise _ApprovalReplayDenied
                        with self.telemetry.span(
                            f"mcp.{tool}",
                            "TOOL",
                            {"tool.name": tool, "judikt.server": server},
                        ) as tool_span:
                            intent_seq = self.audit.record_intent(
                                correlation_id=correlation_id,
                                server=server,
                                tool=tool,
                                arguments=safe_arguments,
                            )
                            evidence.append(f"intent_seq:{intent_seq}")
                            tool_span.set_json_input(safe_arguments)
                            raw_result = self._execute(server, tool, arguments)
                            inspection = self.content_guard.inspect(
                                raw_result,
                                surface="tool_result",
                            )
                            tool_span.set_attribute("judikt.content.allowed", inspection.allowed)
                            tool_span.set_attribute("judikt.content.finding_count", len(inspection.findings))
                            tool_span.set_attribute("judikt.content.hash", inspection.content_hash)
                            if not inspection.allowed:
                                allowed = False
                                rule = "inbound_prompt_injection"
                                reason = "tool output was quarantined by deterministic inbound content inspection"
                                result = quarantine_result(inspection)
                                self._record_failure(server, tool, reason)
                            else:
                                redacted_result = self.policy.redact_mcp_result(
                                    inspection.sanitized_value
                                )
                                if _is_mcp_result(redacted_result):
                                    mcp_result = redacted_result
                                    result = _mcp_result_payload(redacted_result)
                                else:
                                    result = redacted_result
                                if is_mcp_tool_error(raw_result):
                                    allowed = False
                                    rule = "upstream_error"
                                    reason = "upstream MCP tool reported an execution error"
                                    self._record_failure(server, tool, reason)
                            tool_span.set_json_output(result)
                        if allowed:
                            self._reset_circuit(server, tool)
                    except _ApprovalReplayDenied:
                        pass
                    except ToolIntegrityError as exc:
                        allowed = False
                        rule = "tool_integrity"
                        reason = exc.one_line() if isinstance(exc, ToolDriftError) else str(exc)
                    except UpstreamTimeoutError as exc:
                        allowed = False
                        rule = "upstream_timeout"
                        reason = str(exc)
                        self._record_failure(server, tool, reason)
                    except Exception:
                        allowed = False
                        rule = "upstream_error"
                        reason = "upstream tool execution failed"
                        self._record_failure(server, tool, reason)
            if allowed and result is not None:
                result = self._maybe_annotate_incident(arguments, server, tool, correlation_id, decision, result)
            request_span.set_policy(allowed=allowed, rule=rule, reason=reason)
            request_span.set_json_output({"allowed": allowed, "result": result})

        duration_ms = (time.perf_counter() - started) * 1000
        action = decision.action if allowed else ("REQUIRE_APPROVAL" if rule == "approval_required" else "DENY")
        self.audit.record(
            correlation_id=correlation_id,
            server=server,
            tool=tool,
            allowed=allowed,
            rule=rule,
            action=action,
            reason=reason,
            arguments=safe_arguments,
            result=result,
            duration_ms=duration_ms,
            evidence=evidence,
        )
        if should_emit_finding(rule, decision.risk_level, allowed):
            outcome = self.findings.dispatch(
                build_finding_event(
                    correlation_id=correlation_id,
                    server=server,
                    tool=tool,
                    allowed=allowed,
                    rule=rule,
                    action=action,
                    reason=reason,
                    risk_score=decision.risk_score,
                    risk_level=decision.risk_level,
                    arguments=safe_arguments,
                    result=result,
                )
            )
            self.metrics.observe_finding(outcome)
        self.metrics.observe(server, tool, allowed, duration_ms)
        return ToolCallResult(
            correlation_id=correlation_id,
            allowed=allowed,
            server=server,
            tool=tool,
            reason=reason,
            result=result,
            rule=rule,
            action=action,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            evidence=evidence,
            mcp_result=mcp_result,
        )

    def issue_approval(
        self,
        *,
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 300,
    ) -> str:
        authenticated_actor = authenticated_subject()
        if authenticated_actor and actor != authenticated_actor:
            raise PermissionError("approval actor does not match authenticated subject")
        return self.policy.issue_approval(
            actor=authenticated_actor or actor,
            reason=reason,
            server=server,
            tool=tool,
            arguments=arguments,
            ttl_seconds=ttl_seconds,
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
        subject = authenticated_subject()
        if subject and actor != subject:
            raise PermissionError("approval requester does not match authenticated subject")
        return self.slack_approvals.request(
            requester=subject or actor,
            reason=reason,
            server=server,
            tool=tool,
            arguments=arguments,
            safe_arguments=self.policy.redact(arguments),
            ttl_seconds=ttl_seconds,
        )

    def slack_approval_status(self, request_id: str, actor: str) -> dict[str, Any]:
        subject = authenticated_subject()
        if subject and actor != subject:
            raise PermissionError("approval requester does not match authenticated subject")
        return self.slack_approvals.status(request_id, subject or actor)

    def kill_switches(self) -> dict[str, list[str]]:
        return self.policy.kill_switches()

    def set_tool_enabled(self, tool: str, enabled: bool) -> None:
        self.policy.set_tool_enabled(tool, enabled)

    def set_server_enabled(self, server: str, enabled: bool) -> None:
        self.policy.set_server_enabled(server, enabled)

    def circuit_breakers(self) -> dict[str, dict[str, Any]]:
        now = time.time()
        return {
            f"{server}/{tool}": {
                "failure_count": state.failure_count,
                "open": state.open_until > now,
                "open_until": int(state.open_until),
                "last_error": state.last_error,
            }
            for (server, tool), state in sorted(self._circuits.items())
        }

    def recent_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.audit.recent(limit)

    def audit_integrity(self) -> dict[str, Any]:
        return self.audit.verify_chain()

    def finding_delivery(self) -> dict[str, Any]:
        return self.findings.status()

    def render_metrics(self) -> str:
        return self.metrics.render()

    def close(self) -> None:
        for client in self.external_clients.values():
            client.close()
        self.slack_approvals.close()
        self.findings.close()
        self.approval_replays.close()
        self.audit.close()

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

    def _verify_restarted_client(self, server: str, client: StdioMCPClient) -> None:
        tools = client.list_tools()
        self.tool_integrity_reports[server] = self.tool_integrity.verify(server, tools).as_dict()

    def _execute(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        if server == "platform-ops" and self.platform is not None:
            return self.platform.call(tool, arguments)
        if server == "kubernetes" and self.kubernetes is not None:
            return self.kubernetes.call(tool, arguments)
        if server == "incident" and self.incidents is not None:
            return self.incidents.call(tool, arguments)
        client = self.external_clients.get(server)
        if client is not None:
            return client.call_tool(tool, arguments)
        raise ValueError(f"unknown server: {server}")

    @staticmethod
    def _evaluation_only_result(
        action: str,
        server: str,
        tool: str,
        safe_arguments: dict[str, Any],
    ) -> dict[str, Any]:
        mode = "dry_run" if action == "DRY_RUN_ONLY" else "shadow_mode"
        return {
            "mode": mode,
            "executed": False,
            "server": server,
            "tool": tool,
            "arguments": safe_arguments,
            "message": "Judikt evaluated policy and intentionally skipped execution.",
        }

    def _maybe_annotate_incident(
        self,
        arguments: dict[str, Any],
        server: str,
        tool: str,
        correlation_id: str,
        decision: Any,
        result: Any,
    ) -> Any:
        if decision.risk_level not in {"high", "critical"}:
            return result
        if self.incidents is None:
            return result
        incident_id = arguments.get("incident_id")
        if not incident_id and arguments.get("auto_create_incident") is True:
            incident = self.incidents.call(
                "incident.create",
                {"title": f"Guarded {tool} action", "severity": "SEV-3"},
            )
            incident_id = incident["id"]
        if not incident_id:
            return result
        evidence = {
            "correlation_id": correlation_id,
            "server": server,
            "tool": tool,
            "risk_level": decision.risk_level,
            "risk_score": decision.risk_score,
            "action": decision.action,
        }
        annotation = self.incidents.call(
            "incident.attach_evidence",
            {"incident_id": str(incident_id), "evidence": self.policy.redact(evidence)},
        )
        if isinstance(result, dict):
            result = {**result, "incident_annotation": annotation["id"]}
        return result

    def _record_failure(self, server: str, tool: str, reason: str) -> None:
        state = self._circuits.setdefault((server, tool), CircuitState())
        state.failure_count += 1
        state.last_error = reason
        if state.failure_count >= self._circuit_failure_threshold:
            state.open_until = time.time() + self._circuit_cooldown_seconds

    def _reset_circuit(self, server: str, tool: str) -> None:
        self._circuits[(server, tool)] = CircuitState()


class _ApprovalReplayDenied(Exception):
    pass


def _is_mcp_result(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("content"), list)


def _mcp_result_payload(value: dict[str, Any]) -> Any:
    if "structuredContent" in value and value["structuredContent"] is not None:
        return value["structuredContent"]
    return {"content": value.get("content", [])}
