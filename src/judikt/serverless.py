from __future__ import annotations

import datetime as dt
import base64
import binascii
import hashlib
import hmac
import json
import os
import time
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority, resolve_approval_secret
from .approval_replay import DynamoDBApprovalReplayStore, approval_jti_digest
from .backends import INCIDENT_TOOLS, KUBERNETES_TOOLS, PLATFORM_TOOLS, IncidentBackend, KubernetesBackend, PlatformOpsBackend
from .content_guard import ContentGuard, quarantine_result
from .findings import build_finding_event, should_emit_finding
from .models import PolicyDecision
from .paths import DEFAULT_POLICY_PATH, DEMO_POLICY_PATH
from .policy import PolicyEngine
from .risk import RiskEngine


POLICY_PATH = Path(os.environ["JUDIKT_POLICY_PATH"]) if "JUDIKT_POLICY_PATH" in os.environ else DEFAULT_POLICY_PATH
NAMESPACE = "Judikt/Serverless"
MAX_REQUEST_BODY_BYTES = 1_048_576
MAX_TOOL_RESPONSE_BYTES = 1_048_576

_POLICY: ServerlessPolicy | None = None
_PLATFORM_BACKEND: PlatformOpsBackend | None = None
_KUBERNETES_BACKEND: KubernetesBackend | None = None
_INCIDENT_BACKEND: IncidentBackend | None = None
_SECRET_CACHE: dict[str, str] = {}
_CONTENT_GUARD: ContentGuard | None = None
_DEMO_SERVERS = {"platform-ops", "kubernetes", "incident"}


def gateway_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """API Gateway HTTP API entrypoint for the serverless Judikt gateway."""

    started = time.perf_counter()
    request_id = getattr(context, "aws_request_id", None) or str(uuid.uuid4())
    path = _path(event)
    method = _method(event)

    try:
        if not _authorized(event):
            return _response(401, {"error": "missing or invalid bearer token"})
        if method == "GET" and path == "/healthz":
            return _response(200, {"status": "ok", "mode": "serverless", "request_id": request_id})
        if method == "GET" and path == "/tools":
            return _response(200, _list_tools())
        if method == "GET" and path == "/events":
            return _response(200, {"events": _recent_audit_events(limit=50)})
        if method == "GET" and path == "/state":
            return _response(200, _runtime_state())
        if method == "POST" and path == "/approval":
            return _response(200, _issue_approval(_json_body(event)))
        if method == "POST" and path == "/kill-switch":
            return _response(200, _set_kill_switch(_json_body(event)))
        if method == "POST" and path == "/call":
            body = _json_body(event)
            result = _call_guarded_tool(
                server=body["server"],
                tool=body["tool"],
                arguments=body.get("arguments") or {},
                correlation_id=_safe_correlation_id(body.get("correlation_id"), request_id),
            )
            _emit_latency(result["server"], result["tool"], result["allowed"], started)
            return _response(200 if result["allowed"] else 403, result)
        return _response(404, {"error": "not found", "path": path})
    except KeyError as exc:
        return _response(400, {"error": f"missing required field: {exc.args[0]}"})
    except PermissionError:
        return _response(403, {"error": "operation is disabled"})
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
        return _response(400, {"error": "invalid request"})
    except Exception as exc:  # pragma: no cover - Lambda safety net
        _metric("GatewayErrors", 1, {"FailureClass": exc.__class__.__name__})
        print(
            json.dumps(
                {
                    "event": "gateway_error",
                    "failure_class": exc.__class__.__name__,
                    "request_id": request_id,
                },
                separators=(",", ":"),
            )
        )
        return _response(
            500,
            {
                "error": "gateway_error",
                "request_id": request_id,
            },
        )


def tool_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda-hosted operational tool adapter.

    This intentionally behaves like the local MCP mock tools, but it does not
    claim to be a full MCP protocol server. API Gateway calls the guarded
    gateway Lambda; the gateway Lambda invokes this adapter after policy passes.
    """

    action = event.get("action", "call")
    if action == "list_tools":
        return _list_tools()

    server = event["server"]
    tool = event["tool"]
    arguments = event.get("arguments") or {}
    if not isinstance(arguments, dict):
        return {"ok": False, "error": "tool arguments must be an object", "failure_class": "ValueError"}
    if server in _DEMO_SERVERS and not _demo_mode_enabled():
        return {"ok": False, "error": f"unknown server: {server}"}

    try:
        if server == "platform-ops":
            result = _platform_backend().call(tool, arguments)
        elif server == "kubernetes":
            result = _kubernetes_backend().call(tool, arguments)
        elif server == "incident":
            result = _incident_backend().call(tool, arguments)
        else:
            return {"ok": False, "error": f"unknown server: {server}"}
        _persist_tool_state(server, tool, arguments, result)
        return {"ok": True, "result": result}
    except Exception as exc:
        return {
            "ok": False,
            "error": "tool execution failed",
            "failure_class": exc.__class__.__name__,
        }


def _call_guarded_tool(
    *,
    server: str,
    tool: str,
    arguments: dict[str, Any],
    correlation_id: str,
) -> dict[str, Any]:
    policy = _policy()
    safe_arguments = policy.redact(arguments)
    decision = policy.evaluate(server, tool, arguments)
    result: Any = None
    allowed = decision.allowed
    reason = decision.reason
    rule = decision.rule
    evidence = list(decision.evidence)

    if server in _DEMO_SERVERS and not _demo_mode_enabled():
        allowed = False
        rule = "unknown_server"
        reason = f"server is not configured: {server}"

    if allowed:
        if decision.action in {"DRY_RUN_ONLY", "SHADOW_MODE"}:
            result = _evaluation_only_result(decision.action, server, tool, safe_arguments)
        else:
            claims = policy.approval_claims(server, tool, arguments)
            if claims is not None:
                evidence.append(f"approval_jti_sha256:{approval_jti_digest(claims.jti)}")
                if not DynamoDBApprovalReplayStore(_state_table()).consume(
                    claims.jti,
                    claims.expires_at,
                ):
                    allowed = False
                    rule = "approval_replay"
                    reason = "approval token has already been used"
            tool_response = (
                _invoke_tool_lambda(server, tool, arguments, correlation_id)
                if allowed
                else None
            )
            if tool_response is None:
                pass
            elif tool_response.get("ok"):
                raw_result = tool_response.get("result")
                inspection = _content_guard().inspect(raw_result)
                if inspection.allowed:
                    result = policy.redact(raw_result)
                    _record_tool_success(server, tool)
                else:
                    allowed = False
                    rule = "inbound_prompt_injection"
                    reason = "tool output was quarantined by deterministic inbound content inspection"
                    result = quarantine_result(inspection)
                    _record_tool_failure(server, tool, reason)
            else:
                allowed = False
                rule = "upstream_error"
                reported_error = tool_response.get("error")
                safe_errors = {
                    "tool execution failed",
                    "tool lambda invocation failed",
                    "tool lambda response exceeded the size limit",
                    "tool lambda returned an invalid response",
                }
                reason = (
                    reported_error
                    if isinstance(reported_error, str) and reported_error in safe_errors
                    else "tool execution failed"
                )
                _record_tool_failure(server, tool, reason)

    event = {
        "correlation_id": correlation_id,
        "server": server,
        "tool": tool,
        "allowed": allowed,
        "rule": rule,
        "action": decision.action if allowed else ("REQUIRE_APPROVAL" if rule == "approval_required" else "DENY"),
        "reason": reason,
        "arguments": safe_arguments,
        "result": result,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "evidence": evidence,
        "at": _utc_now(),
    }
    _write_audit_event(event)
    _emit_decision_metrics(server, tool, event)
    if should_emit_finding(rule, decision.risk_level, allowed):
        _publish_finding(event)

    return {
        "correlation_id": correlation_id,
        "allowed": allowed,
        "server": server,
        "tool": tool,
        "reason": reason,
        "rule": rule,
        "action": decision.action if allowed else ("REQUIRE_APPROVAL" if rule == "approval_required" else "DENY"),
        "result": result,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "evidence": evidence,
    }


class ServerlessPolicy(PolicyEngine):
    """Policy engine with DynamoDB-backed runtime controls."""

    def __init__(self, policy_path: Path) -> None:
        super().__init__(
            policy_path,
            ApprovalAuthority(_approval_secret(), require_configured=True),
        )
        self.risk = RiskEngine()

    def evaluate(self, server: str, tool: str, arguments: dict[str, Any]) -> PolicyDecision:
        with self._lock:
            risk = self.risk.assess(server, tool, arguments)
            if self._server_disabled(server):
                return self._decision(False, f"server {server!r} is disabled by kill switch", "kill_switch", risk)
            if self._tool_disabled(tool):
                return self._decision(False, f"tool {tool!r} is disabled by kill switch", "kill_switch", risk)
            circuit = _get_state("CIRCUIT", f"{server}#{tool}") or {}
            open_until = int(circuit.get("open_until", 0))
            if open_until > int(time.time()):
                return self._decision(False, "circuit breaker is open for this tool", "circuit_breaker", risk)
            if tool not in self.config["allowed_tools"].get(server, []):
                return self._decision(False, f"tool {tool!r} is not allowlisted for {server!r}", "allowlist", risk)
            argument_inspection = self.argument_guard.inspect(arguments)
            if not argument_inspection.allowed:
                return self._decision(
                    False,
                    "tool arguments matched deterministic direct prompt-injection rules",
                    "direct_prompt_injection",
                    risk,
                )
            actor = self._actor(arguments)
            if tool in self.config.get("actor_required_tools", []) and actor == "anonymous":
                return self._decision(False, f"actor is required for {tool!r}", "authz", risk)
            if not self._actor_can_call(actor, tool):
                return self._decision(False, f"actor {actor!r} is not authorized to call {tool!r}", "authz", risk)
            forbidden_key = self._find_forbidden_argument_key(arguments)
            if forbidden_key:
                return self._decision(
                    False,
                    f"caller-supplied credential field {forbidden_key!r} is forbidden; upstream credentials must be brokered by Judikt",
                    "token_passthrough",
                    risk,
                )
            serialized = json.dumps(arguments, sort_keys=True)
            if any(pattern.search(serialized) for pattern in self._blocked):
                return self._decision(False, "arguments matched a blocked security pattern", "blocked_pattern", risk)
            invalid_argument = self._find_disallowed_argument_value(tool, arguments)
            if invalid_argument:
                return self._decision(
                    False,
                    f"argument {invalid_argument!r} is not allowlisted for {tool!r}",
                    "argument_allowlist",
                    risk,
                )
            if self._dry_run_requested(tool, arguments):
                return self._decision(
                    True,
                    "dry-run only: policy evaluated the request without executing the tool",
                    "dry_run_only",
                    risk,
                    action="DRY_RUN_ONLY",
                )
            if self._shadow_mode_requested(tool, arguments):
                return self._decision(
                    True,
                    "shadow mode: policy evaluated the request without executing the tool",
                    "shadow_mode",
                    risk,
                    action="SHADOW_MODE",
                )
            if tool in self.config["approval_required"] and not self._has_approval(server, tool, arguments):
                return self._decision(
                    False,
                    f"approval token is required for this {risk.level}-risk action",
                    "approval_required",
                    risk,
                    action="REQUIRE_APPROVAL",
                )
            if self._needs_rollback_plan(tool, arguments):
                return self._decision(
                    False,
                    "rollback plan is required for this production-impacting action",
                    "rollback_plan_required",
                    risk,
                )
            if not self._within_distributed_rate_limit(tool):
                return self._decision(False, "tool call exceeded its per-minute limit", "rate_limit", risk)
            return self._decision(True, "allowed by policy", "allow", risk)

    def _server_disabled(self, server: str) -> bool:
        state = _get_state("KILL_SWITCH", f"SERVER#{server}") or {}
        return state.get("enabled") is False

    def _tool_disabled(self, tool: str) -> bool:
        state = _get_state("KILL_SWITCH", f"TOOL#{tool}") or {}
        return state.get("enabled") is False

    def _within_distributed_rate_limit(self, tool: str) -> bool:
        limit = self.config["rate_limits_per_minute"].get(tool, self.config["rate_limits_per_minute"]["default"])
        minute = int(time.time() // 60)
        return _increment_rate_counter(tool, minute, limit)


def _policy() -> ServerlessPolicy:
    global _POLICY
    if _POLICY is None:
        _POLICY = ServerlessPolicy(_policy_path())
    return _POLICY


def _content_guard() -> ContentGuard:
    global _CONTENT_GUARD
    if _CONTENT_GUARD is None:
        _CONTENT_GUARD = ContentGuard.from_policy(_policy().config)
    return _CONTENT_GUARD


def _policy_path() -> Path:
    policy_item = _get_state("POLICY", "default")
    if not policy_item or "document" not in policy_item:
        if _demo_mode_enabled() and "JUDIKT_POLICY_PATH" not in os.environ:
            return DEMO_POLICY_PATH
        return POLICY_PATH
    runtime_path = Path("/tmp/judikt/policies.json")
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_path.write_text(policy_item["document"])
    return runtime_path


def _platform_backend() -> PlatformOpsBackend:
    global _PLATFORM_BACKEND
    if _PLATFORM_BACKEND is None:
        _PLATFORM_BACKEND = PlatformOpsBackend()
    return _PLATFORM_BACKEND


def _incident_backend() -> IncidentBackend:
    global _INCIDENT_BACKEND
    if _INCIDENT_BACKEND is None:
        _INCIDENT_BACKEND = IncidentBackend()
    return _INCIDENT_BACKEND


def _kubernetes_backend() -> KubernetesBackend:
    global _KUBERNETES_BACKEND
    if _KUBERNETES_BACKEND is None:
        _KUBERNETES_BACKEND = KubernetesBackend()
    return _KUBERNETES_BACKEND


def _list_tools() -> dict[str, list[dict[str, Any]]]:
    if not _demo_mode_enabled():
        return {}
    return {
        "platform-ops": [tool.as_mcp() for tool in PLATFORM_TOOLS],
        "kubernetes": [tool.as_mcp() for tool in KUBERNETES_TOOLS],
        "incident": [tool.as_mcp() for tool in INCIDENT_TOOLS],
    }


def _demo_mode_enabled() -> bool:
    return os.getenv("JUDIKT_DEMO_MODE", "").lower() in {"1", "true", "yes"}


def _issue_approval(body: dict[str, Any]) -> dict[str, Any]:
    if os.getenv("JUDIKT_ALLOW_DIRECT_APPROVAL", "").lower() not in {"1", "true", "yes"}:
        raise PermissionError("direct approval issuance is disabled; use an external human approval workflow")
    policy = _policy()
    arguments = body.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    ttl_seconds = body.get("ttl_seconds", 300)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ValueError("ttl_seconds must be an integer")
    if not 1 <= ttl_seconds <= 900:
        raise ValueError("ttl_seconds must be between 1 and 900")
    token = policy.issue_approval(
        actor=body["actor"],
        reason=body["reason"],
        server=body["server"],
        tool=body["tool"],
        arguments=arguments,
        ttl_seconds=ttl_seconds,
    )
    expires_at = int(time.time()) + ttl_seconds
    _put_state(
        "APPROVAL",
        _sha256(token),
        {
            "actor": body["actor"],
            "reason": body["reason"],
            "server": body["server"],
            "tool": body["tool"],
            "arguments_hash": _sha256(json.dumps(arguments, sort_keys=True)),
            "expires_at": expires_at,
        },
    )
    return {"approval_token": token, "expires_at": expires_at}


def _set_kill_switch(body: dict[str, Any]) -> dict[str, Any]:
    enabled = body.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    if "tool" in body:
        pk, sk = "KILL_SWITCH", f"TOOL#{body['tool']}"
        target = body["tool"]
        target_type = "tool"
    elif "server" in body:
        pk, sk = "KILL_SWITCH", f"SERVER#{body['server']}"
        target = body["server"]
        target_type = "server"
    else:
        raise KeyError("tool_or_server")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("kill-switch target must be a non-empty string")
    _put_state(pk, sk, {"enabled": enabled, "target": target, "target_type": target_type, "updated_at": _utc_now()})
    return {"target_type": target_type, "target": target, "enabled": enabled}


def _runtime_state() -> dict[str, Any]:
    recent_events = _recent_audit_events(50)
    invalid_events = [event["event_id"] for event in recent_events if not _verify_audit_event(event)]
    return {
        "kill_switches": _query_state("KILL_SWITCH"),
        "open_circuits": [
            item for item in _query_state("CIRCUIT") if int(item.get("open_until", 0)) > int(time.time())
        ],
        "policy_loaded_from": "dynamodb" if _get_state("POLICY", "default") else "lambda_package",
        "audit_integrity": {
            "checked_events": len(recent_events),
            "valid": not invalid_events,
            "invalid_event_ids": invalid_events,
            "mode": "individually_hmac_signed",
        },
    }


def _recent_audit_events(limit: int) -> list[dict[str, Any]]:
    table = _audit_table()
    if table is None:
        return []
    response = table.scan(Limit=limit)
    events = [_from_ddb(item) for item in response.get("Items", [])]
    return sorted(events, key=lambda item: item.get("at", ""), reverse=True)


def _invoke_tool_lambda(server: str, tool: str, arguments: dict[str, Any], correlation_id: str) -> dict[str, Any]:
    function_name = os.environ["TOOL_FUNCTION_NAME"]
    payload = {
        "action": "call",
        "server": server,
        "tool": tool,
        "arguments": arguments,
        "correlation_id": correlation_id,
    }
    response = _lambda_client().invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    if response.get("FunctionError"):
        return {"ok": False, "error": "tool lambda invocation failed"}
    raw = response["Payload"].read(MAX_TOOL_RESPONSE_BYTES + 1)
    if len(raw) > MAX_TOOL_RESPONSE_BYTES:
        return {"ok": False, "error": "tool lambda response exceeded the size limit"}
    try:
        parsed = json.loads(raw or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"ok": False, "error": "tool lambda returned an invalid response"}
    if not isinstance(parsed, dict):
        return {"ok": False, "error": "tool lambda returned an invalid response"}
    return parsed


def _record_tool_success(server: str, tool: str) -> None:
    _put_state("CIRCUIT", f"{server}#{tool}", {"failure_count": 0, "open_until": 0, "updated_at": _utc_now()})


def _record_tool_failure(server: str, tool: str, reason: str) -> None:
    item = _get_state("CIRCUIT", f"{server}#{tool}") or {}
    failures = int(item.get("failure_count", 0)) + 1
    open_until = int(time.time()) + 300 if failures >= 3 else 0
    _put_state(
        "CIRCUIT",
        f"{server}#{tool}",
        {
            "failure_count": failures,
            "open_until": open_until,
            "last_error": reason,
            "updated_at": _utc_now(),
        },
    )
    if open_until:
        _metric("CircuitBreakerOpen", 1, {"Server": server, "Tool": tool})


def _persist_tool_state(server: str, tool: str, arguments: dict[str, Any], result: Any) -> None:
    if tool in {"platform.rollback_deployment", "platform.restart_deployment"}:
        service = arguments.get("service", "unknown")
        _put_state("SERVICE", service, {"server": server, "last_tool": tool, "last_result": result, "updated_at": _utc_now()})
    if tool == "kubernetes.restart_pod":
        pod = f"{arguments.get('namespace', 'unknown')}/{arguments.get('pod', 'unknown')}"
        _put_state("POD", pod, {"server": server, "last_tool": tool, "last_result": result, "updated_at": _utc_now()})


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


def _write_audit_event(event: dict[str, Any]) -> None:
    table = _audit_table()
    if table is None:
        return
    table.put_item(Item=_to_ddb(_seal_audit_event(event)))


def _seal_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    envelope = {
        "correlation_id": event["correlation_id"],
        "event_id": str(uuid.uuid4()),
        "expires_at": int(time.time()) + 60 * 60 * 24 * 14,
        **event,
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=_json_default)
    event_hash = hashlib.sha256(canonical.encode()).hexdigest()
    signature = hmac.new(_audit_signing_secret(), event_hash.encode(), hashlib.sha256).hexdigest()
    return {**envelope, "event_hash": event_hash, "signature": signature}


def _verify_audit_event(event: dict[str, Any]) -> bool:
    event_hash = str(event.get("event_hash", ""))
    signature = str(event.get("signature", ""))
    unsigned = {key: value for key, value in event.items() if key not in {"event_hash", "signature"}}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), default=_json_default)
    expected_hash = hashlib.sha256(canonical.encode()).hexdigest()
    expected_signature = hmac.new(
        _audit_signing_secret(), event_hash.encode(), hashlib.sha256
    ).hexdigest()
    return bool(
        event_hash
        and signature
        and hmac.compare_digest(event_hash, expected_hash)
        and hmac.compare_digest(signature, expected_signature)
    )


def _publish_finding(event: dict[str, Any]) -> None:
    bus_name = os.getenv("EVENT_BUS_NAME")
    if not bus_name:
        return
    detail = build_finding_event(
        correlation_id=event["correlation_id"],
        server=event["server"],
        tool=event["tool"],
        allowed=event["allowed"],
        rule=event["rule"],
        action=event["action"],
        reason=event["reason"],
        risk_score=event["risk_score"],
        risk_level=event["risk_level"],
        arguments=event["arguments"],
        result=event["result"],
    )
    try:
        response = _events_client().put_events(
            Entries=[
                {
                    "Source": "judikt.mcp",
                    "DetailType": "RemediationFinding",
                    "EventBusName": bus_name,
                    "Detail": json.dumps(detail, separators=(",", ":")),
                }
            ]
        )
        if response.get("FailedEntryCount", 0):
            _record_finding_publish_failure("RejectedEntry")
    except Exception as exc:
        # Finding export is secondary to the audited policy decision.
        _record_finding_publish_failure(exc.__class__.__name__)


def _record_finding_publish_failure(failure_class: str) -> None:
    print(
        json.dumps(
            {
                "event": "finding_publish_failure",
                "failure_class": failure_class,
            },
            separators=(",", ":"),
        )
    )
    _metric("FindingPublishFailures", 1, {})


def _emit_decision_metrics(server: str, tool: str, event: dict[str, Any]) -> None:
    dimensions = {"Server": server, "Tool": tool}
    _metric("AllowedCalls" if event["allowed"] else "BlockedCalls", 1, dimensions)
    if event["risk_level"] in {"high", "critical"} and event["allowed"]:
        _metric("HighRiskAllowedCalls", 1, dimensions)


def _emit_latency(server: str, tool: str, allowed: bool, started: float) -> None:
    elapsed_ms = (time.perf_counter() - started) * 1000
    _metric("ToolCallLatencyMs", elapsed_ms, {"Server": server, "Tool": tool, "Allowed": str(allowed).lower()}, "Milliseconds")


def _metric(name: str, value: float, dimensions: dict[str, str], unit: str = "Count") -> None:
    if not os.getenv("AWS_LAMBDA_FUNCTION_NAME") and os.getenv(
        "JUDIKT_SERVERLESS_METRICS_LOCAL", ""
    ).lower() not in {"1", "true", "yes"}:
        return
    try:
        _cloudwatch_client().put_metric_data(
            Namespace=NAMESPACE,
            MetricData=[
                {
                    "MetricName": name,
                    "Dimensions": [{"Name": key, "Value": str(val)} for key, val in dimensions.items()],
                    "Value": value,
                    "Unit": unit,
                }
            ],
        )
    except Exception:
        # Metrics must never break the control plane path.
        return


def _get_state(pk: str, sk: str) -> dict[str, Any] | None:
    table = _state_table()
    if table is None:
        return None
    response = table.get_item(Key={"pk": pk, "sk": sk})
    item = response.get("Item")
    return _from_ddb(item) if item else None


def _put_state(pk: str, sk: str, attributes: dict[str, Any]) -> None:
    table = _state_table()
    if table is None:
        return
    table.put_item(Item=_to_ddb({"pk": pk, "sk": sk, **attributes}))


def _query_state(pk: str) -> list[dict[str, Any]]:
    table = _state_table()
    if table is None:
        return []
    response = table.query(KeyConditionExpression=_key("pk").eq(pk))
    return [_from_ddb(item) for item in response.get("Items", [])]


def _increment_rate_counter(tool: str, minute: int, limit: int) -> bool:
    table = _state_table()
    if table is None:
        return True
    expires_at = int(time.time()) + 120
    try:
        table.update_item(
            Key={"pk": "RATE", "sk": f"{tool}#{minute}"},
            UpdateExpression="SET expires_at = :ttl, tool = :tool ADD #count :one",
            ConditionExpression="attribute_not_exists(#count) OR #count < :limit",
            ExpressionAttributeNames={"#count": "count"},
            ExpressionAttributeValues={":one": 1, ":ttl": expires_at, ":limit": limit, ":tool": tool},
        )
        return True
    except Exception as exc:
        if exc.__class__.__name__ == "ConditionalCheckFailedException":
            return False
        if "ConditionalCheckFailed" in str(exc):
            return False
        raise


def _state_table() -> Any:
    table_name = os.getenv("STATE_TABLE_NAME")
    if not table_name:
        return None
    return _dynamodb().Table(table_name)


def _audit_table() -> Any:
    table_name = os.getenv("AUDIT_TABLE_NAME")
    if not table_name:
        return None
    return _dynamodb().Table(table_name)


def _dynamodb() -> Any:
    import boto3

    return boto3.resource("dynamodb")


def _lambda_client() -> Any:
    import boto3

    return boto3.client("lambda")


def _events_client() -> Any:
    import boto3

    return boto3.client("events")


def _cloudwatch_client() -> Any:
    import boto3

    return boto3.client("cloudwatch")


def _secretsmanager_client() -> Any:
    import boto3

    return boto3.client("secretsmanager")


def _key(name: str) -> Any:
    from boto3.dynamodb.conditions import Key

    return Key(name)


def _authorized(event: dict[str, Any]) -> bool:
    expected = _api_token()
    if not expected:
        return os.getenv("JUDIKT_ALLOW_UNAUTHENTICATED_SERVERLESS", "").lower() in {
            "1",
            "true",
            "yes",
        }
    headers = {str(key).lower(): value for key, value in (event.get("headers") or {}).items()}
    supplied = headers.get("authorization")
    return isinstance(supplied, str) and hmac.compare_digest(supplied, f"Bearer {expected}")


def _api_token() -> str:
    return _secret_from_env("JUDIKT_API_TOKEN_SECRET_ARN") or os.getenv("JUDIKT_API_TOKEN", "")


def _approval_secret() -> str:
    configured = _secret_from_env("JUDIKT_APPROVAL_SECRET_ARN") or os.getenv(
        "JUDIKT_APPROVAL_SECRET"
    )
    return resolve_approval_secret(configured, require_configured=True)


def _audit_signing_secret() -> bytes:
    value = _secret_from_env("JUDIKT_AUDIT_HMAC_SECRET_ARN") or os.getenv(
        "JUDIKT_AUDIT_HMAC_SECRET"
    )
    if not value and os.getenv("JUDIKT_AUDIT_SIGNATURE_REQUIRED", "").lower() in {
        "1",
        "true",
        "yes",
    }:
        raise RuntimeError("audit signatures are required but no audit HMAC secret is configured")
    value = value or _approval_secret()
    return (value or "local-dev-audit-secret-change-me").encode()


def _secret_from_env(env_name: str) -> str:
    secret_arn = os.getenv(env_name, "")
    if not secret_arn:
        return ""
    if secret_arn not in _SECRET_CACHE:
        response = _secretsmanager_client().get_secret_value(SecretId=secret_arn)
        _SECRET_CACHE[secret_arn] = response.get("SecretString", "")
    return _SECRET_CACHE[secret_arn]


def _path(event: dict[str, Any]) -> str:
    raw_path = event.get("rawPath") or event.get("path") or "/"
    return raw_path.rstrip("/") or "/"


def _method(event: dict[str, Any]) -> str:
    return (event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod") or "GET").upper()


def _json_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body") or "{}"
    if not isinstance(body, str):
        raise ValueError("request body must be a string")
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(body, validate=True)
    else:
        raw = body.encode()
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        raise ValueError("request body exceeded the size limit")
    body = raw.decode()
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise ValueError("request body must be a JSON object")
    return parsed


def _safe_correlation_id(value: Any, fallback: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        return fallback
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return fallback
    return value


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body, default=_json_default, separators=(",", ":")),
    }


def _to_ddb(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _to_ddb(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_ddb(item) for item in value]
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def _from_ddb(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _from_ddb(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_from_ddb(item) for item in value]
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    return value


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"{value!r} is not JSON serializable")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()
