from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any, Sequence

from .approval import ApprovalAuthority
from .approval_replay import approval_jti_digest, build_approval_replay_store
from .audit import AuditStore
from .content_guard import ContentGuard, quarantine_result
from .groq import IncidentAnalyst
from .findings import FindingDispatcher, build_finding_event, should_emit_finding
from .metrics import Metrics
from .models import ToolCallResult
from .policy import PolicyEngine
from .protocol import MCPProtocolError, StdioMCPClient, UpstreamTimeoutError, is_mcp_tool_error
from .telemetry import Telemetry
from .tool_integrity import (
    ToolDriftError,
    ToolIntegrityError,
    ToolIntegrityStore,
    ToolPinMetadata,
    verify_unique_tool_names,
)
from .upstreams import UpstreamServer, load_upstream_servers


class JudiktRuntime:
    def __init__(
        self,
        policy_path: Path,
        audit_path: Path,
        *,
        include_demo_servers: bool = False,
        upstream_servers: Sequence[UpstreamServer] | None = None,
        approval_authority: ApprovalAuthority | None = None,
    ) -> None:
        self.policy = PolicyEngine(policy_path, approval_authority)
        self.content_guard = ContentGuard.from_policy(self.policy.config)
        self.approval_replays = build_approval_replay_store(
            audit_path.with_suffix(".approval-replay.db")
        )
        self.metrics = Metrics()
        audit_config = self.policy.config.get("audit", {})
        backpressure = audit_config.get("backpressure") if isinstance(audit_config, dict) else None
        self.audit = AuditStore(
            audit_path,
            backpressure=backpressure,
            metrics=self.metrics,
        )
        self.findings = FindingDispatcher(audit_path.with_suffix(".findings.db"))
        self._dispatch_startup_integrity_finding()
        self.telemetry = Telemetry()
        self.analyst = IncidentAnalyst(telemetry=self.telemetry)
        self.demo_servers_enabled = include_demo_servers
        self.clients = {}
        if include_demo_servers:
            self.clients.update(
                {
                    "platform-ops": StdioMCPClient("platform-ops", metrics=self.metrics),
                    "incident": StdioMCPClient("incident", metrics=self.metrics),
                    "kubernetes": StdioMCPClient("kubernetes", metrics=self.metrics),
                }
            )
        configured_upstreams = load_upstream_servers() if upstream_servers is None else upstream_servers
        pin_metadata: dict[str, ToolPinMetadata] = {}
        for upstream in configured_upstreams:
            if upstream.name in self.clients:
                raise ValueError(f"upstream MCP server name collides with demo server: {upstream.name}")
            self.clients[upstream.name] = StdioMCPClient(
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
        pin_path = Path(os.getenv("JUDIKT_TOOL_PIN_PATH", str(audit_path.with_suffix(".tool-pins.json"))))
        self.tool_integrity = ToolIntegrityStore(
            pin_path,
            self.content_guard,
            metadata=pin_metadata,
        )
        definitions = {server: client.list_tools() for server, client in self.clients.items()}
        verify_unique_tool_names(definitions)
        self.tool_integrity_reports = {
            server: self.tool_integrity.verify(server, tools).as_dict()
            for server, tools in definitions.items()
        }
        for server, client in self.clients.items():
            client.add_restart_handler(
                lambda restarted, server=server: self._verify_restarted_client(
                    server,
                    restarted,
                )
            )

    def list_tools(self) -> dict[str, list[dict[str, Any]]]:
        result = {server: client.list_tools() for server, client in self.clients.items()}
        verify_unique_tool_names(result)
        for server, tools in result.items():
            self.tool_integrity_reports[server] = self.tool_integrity.verify(server, tools).as_dict()
        return result

    def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        correlation_id: str | None = None,
        *,
        trusted_actor: str = "",
    ) -> ToolCallResult:
        correlation_id = correlation_id or str(uuid.uuid4())
        started = time.perf_counter()
        safe_arguments = self.policy.redact(arguments)
        result: Any = None
        mcp_result: dict[str, Any] | None = None
        with self.telemetry.span(
            "judikt.call_tool",
            "CHAIN",
            {
                "judikt.correlation_id": correlation_id,
                "judikt.server": server,
                "judikt.tool": tool,
            },
        ) as request_span:
            request_span.set_json_input(safe_arguments)
            with self.telemetry.span(
                "judikt.policy.evaluate",
                "GUARDRAIL",
                {"judikt.server": server, "judikt.tool": tool},
            ) as policy_span:
                policy_span.set_json_input(safe_arguments)
                decision = self.policy.evaluate(
                    server,
                    tool,
                    arguments,
                    authenticated_actor=trusted_actor,
                )
                policy_span.set_policy(
                    allowed=decision.allowed,
                    rule=decision.rule,
                    reason=decision.reason,
                )
                policy_span.set_attribute("judikt.risk.score", decision.risk_score)
                policy_span.set_attribute("judikt.risk.level", decision.risk_level)
                policy_span.set_attribute("judikt.policy.action", decision.action)
            reason = decision.reason
            allowed = decision.allowed
            rule = decision.rule
            evidence = list(decision.evidence)
            if allowed and self.audit.deny_for_backpressure():
                allowed = False
                rule = "audit_backpressure"
                reason = "audit delivery backlog exceeded the configured safety threshold"
            if allowed:
                if decision.action in {"DRY_RUN_ONLY", "SHADOW_MODE"}:
                    result = self._evaluation_only_result(decision.action, server, tool, safe_arguments)
                else:
                    client = self.clients.get(server)
                    if client is None:
                        allowed = False
                        rule = "unknown_server"
                        reason = f"unknown MCP server: {server}"
                    else:
                        try:
                            tools = client.list_tools()
                            self.tool_integrity_reports[server] = self.tool_integrity.verify(server, tools).as_dict()
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
                                {
                                    "tool.name": tool,
                                    "judikt.server": server,
                                    "judikt.correlation_id": correlation_id,
                                },
                            ) as tool_span:
                                intent_seq = self.audit.record_intent(
                                    correlation_id=correlation_id,
                                    server=server,
                                    tool=tool,
                                    arguments=safe_arguments,
                                )
                                evidence.append(f"intent_seq:{intent_seq}")
                                tool_span.set_json_input(safe_arguments)
                                raw_result = client.call_tool(tool, arguments)
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
                                else:
                                    redacted_result = self.policy.redact_mcp_result(
                                        inspection.sanitized_value
                                    )
                                    if isinstance(redacted_result, dict):
                                        mcp_result = redacted_result
                                    if is_mcp_tool_error(raw_result):
                                        allowed = False
                                        rule = "upstream_error"
                                        reason = "upstream MCP tool reported an execution error"
                                    result = _result_payload(redacted_result)
                                tool_span.set_json_output(result)
                        except _ApprovalReplayDenied:
                            pass
                        except UpstreamTimeoutError as exc:
                            allowed = False
                            rule = "upstream_timeout"
                            reason = str(exc)
                        except (MCPProtocolError, ToolIntegrityError) as exc:
                            allowed = False
                            rule = "tool_integrity" if isinstance(exc, ToolIntegrityError) else "upstream_error"
                            reason = exc.one_line() if isinstance(exc, ToolDriftError) else str(exc)
            request_span.set_policy(allowed=allowed, rule=rule, reason=reason)
            request_span.set_attribute("judikt.risk.score", decision.risk_score)
            request_span.set_attribute("judikt.risk.level", decision.risk_level)
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
            correlation_id,
            allowed,
            server,
            tool,
            reason,
            result,
            rule=rule,
            action=action,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            evidence=evidence,
            mcp_result=mcp_result,
        )

    def evaluate_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        correlation_id: str | None = None,
    ) -> ToolCallResult:
        """Evaluate and audit a proposal without invoking an upstream tool."""
        correlation_id = correlation_id or str(uuid.uuid4())
        started = time.perf_counter()
        safe_arguments = self.policy.redact(arguments)
        decision = self.policy.evaluate(server, tool, arguments)
        allowed = decision.allowed
        action = "PROPOSE_ONLY" if allowed else (
            "REQUIRE_APPROVAL" if decision.rule == "approval_required" else "DENY"
        )
        result = {
            "mode": "proposal_only",
            "executed": False,
            "server": server,
            "tool": tool,
            "arguments": safe_arguments,
        }
        duration_ms = (time.perf_counter() - started) * 1000
        self.audit.record(
            correlation_id=correlation_id,
            server=server,
            tool=tool,
            allowed=allowed,
            rule=decision.rule,
            action=action,
            reason=decision.reason,
            arguments=safe_arguments,
            result=result,
            duration_ms=duration_ms,
            evidence=decision.evidence,
        )
        if should_emit_finding(decision.rule, decision.risk_level, allowed):
            outcome = self.findings.dispatch(
                build_finding_event(
                    correlation_id=correlation_id,
                    server=server,
                    tool=tool,
                    allowed=allowed,
                    rule=decision.rule,
                    action=action,
                    reason=decision.reason,
                    risk_score=decision.risk_score,
                    risk_level=decision.risk_level,
                    arguments=safe_arguments,
                    result=result,
                )
            )
            self.metrics.observe_finding(outcome)
        self.metrics.observe(server, tool, allowed, duration_ms)
        return ToolCallResult(
            correlation_id,
            allowed,
            server,
            tool,
            decision.reason,
            result,
            rule=decision.rule,
            action=action,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            evidence=decision.evidence,
        )

    def summarize_recent_events(self, limit: int = 100) -> dict[str, Any]:
        return self.analyst.summarize(self.audit.recent(limit))

    def close(self) -> None:
        for client in self.clients.values():
            client.close()
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


class _ApprovalReplayDenied(Exception):
    pass


def _result_payload(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    if "structuredContent" in value and value["structuredContent"] is not None:
        return value["structuredContent"]
    return {"content": value.get("content", [])}
