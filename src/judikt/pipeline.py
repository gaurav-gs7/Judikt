from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .approval_replay import ApprovalReplayStore, approval_jti_digest
from .audit import AuditStore
from .content_guard import ContentGuard, quarantine_result
from .findings import FindingDispatcher, build_finding_event, should_emit_finding
from .metrics import Metrics
from .models import PolicyDecision, ToolCallResult
from .policy import PolicyEngine
from .protocol import MCPProtocolError, UpstreamTimeoutError, is_mcp_tool_error
from .request_context import authenticated_subject
from .telemetry import Telemetry
from .tool_integrity import ToolDriftError, ToolIntegrityError, ToolIntegrityStore
from .upstream_registry import UpstreamRegistry


class IdentityProvider(Protocol):
    def resolve(self, trusted_actor: str = "") -> str: ...


class TrustedLocalIdentityProvider:
    def resolve(self, trusted_actor: str = "") -> str:
        return trusted_actor


class RequestContextIdentityProvider:
    def resolve(self, trusted_actor: str = "") -> str:
        del trusted_actor
        return authenticated_subject()


class ApprovalWorkflow(Protocol):
    def close(self) -> None: ...


class KillSwitchStore(Protocol):
    def get_state(self) -> dict[str, Any]: ...


class PolicyKillSwitchStore:
    """Compatibility adapter for the policy engine's in-memory switches."""

    def __init__(self, policy: PolicyEngine) -> None:
        self._policy = policy

    def get_state(self) -> dict[str, Any]:
        state = self._policy.kill_switches()
        return {
            "tools": set(state["disabled_tools"]),
            "servers": set(state["disabled_servers"]),
            "version": 0,
        }


@dataclass
class CircuitState:
    failure_count: int = 0
    open_until: float = 0
    last_error: str = ""


class CircuitBreakerStore(Protocol):
    def is_open(self, server: str, tool: str) -> bool: ...

    def record_failure(self, server: str, tool: str, reason: str) -> None: ...

    def reset(self, server: str, tool: str) -> None: ...

    def snapshot(self) -> dict[str, dict[str, Any]]: ...


class InMemoryCircuitBreakerStore:
    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 300,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if failure_threshold <= 0:
            raise ValueError("circuit failure threshold must be greater than zero")
        if cooldown_seconds < 0:
            raise ValueError("circuit cooldown must be zero or greater")
        self.states: dict[tuple[str, str], CircuitState] = {}
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock

    def is_open(self, server: str, tool: str) -> bool:
        state = self.states.get((server, tool))
        return state is not None and state.open_until > self._clock()

    def record_failure(self, server: str, tool: str, reason: str) -> None:
        state = self.states.setdefault((server, tool), CircuitState())
        state.failure_count += 1
        state.last_error = reason
        if state.failure_count >= self.failure_threshold:
            state.open_until = self._clock() + self.cooldown_seconds

    def reset(self, server: str, tool: str) -> None:
        self.states[(server, tool)] = CircuitState()

    def snapshot(self) -> dict[str, dict[str, Any]]:
        now = self._clock()
        return {
            f"{server}/{tool}": {
                "failure_count": state.failure_count,
                "open": state.open_until > now,
                "open_until": int(state.open_until),
                "last_error": state.last_error,
            }
            for (server, tool), state in sorted(self.states.items())
        }


class GuardedCallPipeline:
    """Canonical guarded-call pipeline shared by local and remote transports."""

    def __init__(
        self,
        *,
        policy: PolicyEngine,
        identity_provider: IdentityProvider,
        upstreams: UpstreamRegistry,
        kill_switches: KillSwitchStore,
        circuits: CircuitBreakerStore,
        content_guard: ContentGuard,
        tool_integrity: ToolIntegrityStore,
        tool_integrity_reports: dict[str, dict[str, Any]],
        approval_replays: ApprovalReplayStore,
        audit: AuditStore,
        findings: FindingDispatcher,
        metrics: Metrics,
        telemetry: Telemetry,
        approval_workflow: ApprovalWorkflow | None = None,
    ) -> None:
        self.policy = policy
        self.identity_provider = identity_provider
        self.upstreams = upstreams
        self.kill_switches = kill_switches
        self.circuits = circuits
        self.content_guard = content_guard
        self.tool_integrity = tool_integrity
        self.tool_integrity_reports = tool_integrity_reports
        self.approval_replays = approval_replays
        self.audit = audit
        self.findings = findings
        self.metrics = metrics
        self.telemetry = telemetry
        self.approval_workflow = approval_workflow

    def list_tools(self) -> dict[str, list[dict[str, Any]]]:
        definitions = self.upstreams.definitions()
        for server, tools in definitions.items():
            self.tool_integrity_reports[server] = self.tool_integrity.verify(
                server, tools
            ).as_dict()
        return definitions

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
        actor = self.identity_provider.resolve(trusted_actor)
        decision = self._pre_execution_decision(server, tool, arguments, actor)
        allowed = decision.allowed
        reason = decision.reason
        rule = decision.rule
        evidence = list(decision.evidence)
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
            request_span.set_policy(allowed=allowed, rule=rule, reason=reason)
            request_span.set_attribute("judikt.risk.score", decision.risk_score)
            request_span.set_attribute("judikt.risk.level", decision.risk_level)
            request_span.set_attribute("judikt.policy.action", decision.action)

            if allowed and self.audit.deny_for_backpressure():
                allowed = False
                rule = "audit_backpressure"
                reason = "audit delivery backlog exceeded the configured safety threshold"
            if allowed:
                if decision.action in {"DRY_RUN_ONLY", "SHADOW_MODE"}:
                    result = _evaluation_only_result(
                        decision.action, server, tool, safe_arguments
                    )
                else:
                    allowed, rule, reason, result, mcp_result = self._execute_guarded(
                        server=server,
                        tool=tool,
                        arguments=arguments,
                        safe_arguments=safe_arguments,
                        correlation_id=correlation_id,
                        evidence=evidence,
                    )
            if allowed and result is not None:
                result = self._maybe_annotate_incident(
                    arguments, server, tool, correlation_id, decision, result
                )
            request_span.set_policy(allowed=allowed, rule=rule, reason=reason)
            request_span.set_json_output({"allowed": allowed, "result": result})

        duration_ms = (time.perf_counter() - started) * 1000
        action = decision.action if allowed else (
            "REQUIRE_APPROVAL" if rule == "approval_required" else "DENY"
        )
        self._record_outcome(
            correlation_id=correlation_id,
            server=server,
            tool=tool,
            allowed=allowed,
            rule=rule,
            action=action,
            reason=reason,
            safe_arguments=safe_arguments,
            result=result,
            duration_ms=duration_ms,
            decision=decision,
            evidence=evidence,
        )
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

    def evaluate_tool(
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
        actor = self.identity_provider.resolve(trusted_actor)
        decision = self._pre_execution_decision(server, tool, arguments, actor)
        action = "PROPOSE_ONLY" if decision.allowed else (
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
        self._record_outcome(
            correlation_id=correlation_id,
            server=server,
            tool=tool,
            allowed=decision.allowed,
            rule=decision.rule,
            action=action,
            reason=decision.reason,
            safe_arguments=safe_arguments,
            result=result,
            duration_ms=duration_ms,
            decision=decision,
            evidence=list(decision.evidence),
        )
        return ToolCallResult(
            correlation_id=correlation_id,
            allowed=decision.allowed,
            server=server,
            tool=tool,
            reason=decision.reason,
            result=result,
            rule=decision.rule,
            action=action,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            evidence=list(decision.evidence),
        )

    def close(self) -> None:
        self.upstreams.close()
        if self.approval_workflow is not None:
            self.approval_workflow.close()
        self.findings.close()
        self.approval_replays.close()
        self.audit.close()

    def _pre_execution_decision(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        actor: str,
    ) -> PolicyDecision:
        risk = self.policy.risk.assess(server, tool, arguments)
        switches = self.kill_switches.get_state()
        if server in switches["servers"]:
            return self.policy._decision(
                False,
                f"server {server!r} is disabled by kill switch",
                "kill_switch",
                risk,
            )
        if tool in switches["tools"]:
            return self.policy._decision(
                False,
                f"tool {tool!r} is disabled by kill switch",
                "kill_switch",
                risk,
            )
        if self.circuits.is_open(server, tool):
            return self.policy._decision(
                False,
                "circuit breaker is open after repeated upstream failures",
                "circuit_breaker",
                risk,
            )
        with self.telemetry.span(
            "judikt.policy.evaluate",
            "GUARDRAIL",
            {"judikt.server": server, "judikt.tool": tool},
        ) as policy_span:
            policy_span.set_json_input(self.policy.redact(arguments))
            decision = self.policy.evaluate(
                server,
                tool,
                arguments,
                authenticated_actor=actor,
            )
            policy_span.set_policy(
                allowed=decision.allowed,
                rule=decision.rule,
                reason=decision.reason,
            )
            policy_span.set_attribute("judikt.risk.score", decision.risk_score)
            policy_span.set_attribute("judikt.risk.level", decision.risk_level)
            policy_span.set_attribute("judikt.policy.action", decision.action)
            return decision

    def _execute_guarded(
        self,
        *,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        safe_arguments: dict[str, Any],
        correlation_id: str,
        evidence: list[str],
    ) -> tuple[bool, str, str, Any, dict[str, Any] | None]:
        definitions = self.upstreams.definitions()
        if server not in definitions:
            return False, "unknown_server", f"unknown MCP server: {server}", None, None
        try:
            self.tool_integrity_reports[server] = self.tool_integrity.verify(
                server, definitions[server]
            ).as_dict()
            claims = self.policy.approval_claims(server, tool, arguments)
            if claims is not None:
                evidence.append(f"approval_jti_sha256:{approval_jti_digest(claims.jti)}")
                if not self.approval_replays.consume(claims.jti, claims.expires_at):
                    return (
                        False,
                        "approval_replay",
                        "approval token has already been used",
                        None,
                        None,
                    )
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
                raw_result = self.upstreams.execute(server, tool, arguments)
                inspection = self.content_guard.inspect(raw_result, surface="tool_result")
                tool_span.set_attribute("judikt.content.allowed", inspection.allowed)
                tool_span.set_attribute(
                    "judikt.content.finding_count", len(inspection.findings)
                )
                tool_span.set_attribute("judikt.content.hash", inspection.content_hash)
                if not inspection.allowed:
                    reason = (
                        "tool output was quarantined by deterministic inbound "
                        "content inspection"
                    )
                    self.circuits.record_failure(server, tool, reason)
                    result = quarantine_result(inspection)
                    tool_span.set_json_output(result)
                    return False, "inbound_prompt_injection", reason, result, None
                redacted_result = self.policy.redact_mcp_result(
                    inspection.sanitized_value
                )
                mcp_result = redacted_result if _is_mcp_result(redacted_result) else None
                result = _result_payload(redacted_result)
                if is_mcp_tool_error(raw_result):
                    reason = "upstream MCP tool reported an execution error"
                    self.circuits.record_failure(server, tool, reason)
                    tool_span.set_json_output(result)
                    return False, "upstream_error", reason, result, mcp_result
                self.circuits.reset(server, tool)
                tool_span.set_json_output(result)
                return True, "allow", "allowed by policy", result, mcp_result
        except ToolIntegrityError as exc:
            reason = exc.one_line() if isinstance(exc, ToolDriftError) else str(exc)
            return False, "tool_integrity", reason, None, None
        except UpstreamTimeoutError as exc:
            reason = str(exc)
            self.circuits.record_failure(server, tool, reason)
            return False, "upstream_timeout", reason, None, None
        except MCPProtocolError as exc:
            reason = str(exc)
            self.circuits.record_failure(server, tool, reason)
            return False, "upstream_error", reason, None, None
        except Exception:
            reason = "upstream tool execution failed"
            self.circuits.record_failure(server, tool, reason)
            return False, "upstream_error", reason, None, None

    def _maybe_annotate_incident(
        self,
        arguments: dict[str, Any],
        server: str,
        tool: str,
        correlation_id: str,
        decision: PolicyDecision,
        result: Any,
    ) -> Any:
        incidents = self.upstreams.incident_backend
        if decision.risk_level not in {"high", "critical"} or incidents is None:
            return result
        incident_id = arguments.get("incident_id")
        if not incident_id and arguments.get("auto_create_incident") is True:
            incident = incidents.call(
                "incident.create",
                {"title": f"Guarded {tool} action", "severity": "SEV-3"},
            )
            incident_id = incident["id"]
        if not incident_id:
            return result
        annotation = incidents.call(
            "incident.attach_evidence",
            {
                "incident_id": str(incident_id),
                "evidence": self.policy.redact(
                    {
                        "correlation_id": correlation_id,
                        "server": server,
                        "tool": tool,
                        "risk_level": decision.risk_level,
                        "risk_score": decision.risk_score,
                        "action": decision.action,
                    }
                ),
            },
        )
        if isinstance(result, dict):
            return {**result, "incident_annotation": annotation["id"]}
        return result

    def _record_outcome(
        self,
        *,
        correlation_id: str,
        server: str,
        tool: str,
        allowed: bool,
        rule: str,
        action: str,
        reason: str,
        safe_arguments: dict[str, Any],
        result: Any,
        duration_ms: float,
        decision: PolicyDecision,
        evidence: list[str],
    ) -> None:
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


def _is_mcp_result(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("content"), list)


def _result_payload(value: Any) -> Any:
    if not _is_mcp_result(value):
        return value
    if "structuredContent" in value and value["structuredContent"] is not None:
        return value["structuredContent"]
    return {"content": value.get("content", [])}
