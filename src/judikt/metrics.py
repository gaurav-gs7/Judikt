from __future__ import annotations

import threading
from collections import Counter


class Metrics:
    def __init__(self) -> None:
        self._counters: Counter[tuple[str, str, str]] = Counter()
        self._duration_total_ms: Counter[tuple[str, str]] = Counter()
        self._finding_counters: Counter[str] = Counter()
        self._upstream_counters: Counter[tuple[str, str]] = Counter()
        self._audit_delivery_failures = 0
        self._audit_outbox_pending = 0
        self._audit_outbox_oldest_age_seconds = 0.0
        self._kill_switch_store_failures: Counter[str] = Counter()
        self._rate_limiter_fallbacks: Counter[str] = Counter()
        self._lock = threading.Lock()

    def observe(self, server: str, tool: str, allowed: bool, duration_ms: float) -> None:
        outcome = "allowed" if allowed else "blocked"
        with self._lock:
            self._counters[(server, tool, outcome)] += 1
            self._duration_total_ms[(server, tool)] += duration_ms

    def observe_finding(self, outcome: str) -> None:
        with self._lock:
            self._finding_counters[outcome] += 1

    def observe_upstream_timeout(self, server: str) -> None:
        self._observe_upstream("timeouts", server)

    def observe_upstream_restart(self, server: str) -> None:
        self._observe_upstream("restarts", server)

    def observe_upstream_protocol_violation(self, server: str) -> None:
        self._observe_upstream("protocol_violations", server)

    def observe_audit_delivery_failure(self) -> None:
        with self._lock:
            self._audit_delivery_failures += 1

    def set_audit_outbox(self, pending: int, oldest_age_seconds: float) -> None:
        with self._lock:
            self._audit_outbox_pending = pending
            self._audit_outbox_oldest_age_seconds = oldest_age_seconds

    def observe_kill_switch_store_failure(self, mode: str) -> None:
        with self._lock:
            self._kill_switch_store_failures[mode] += 1

    def observe_rate_limiter_fallback(self, mode: str) -> None:
        with self._lock:
            self._rate_limiter_fallbacks[mode] += 1

    def _observe_upstream(self, kind: str, server: str) -> None:
        with self._lock:
            self._upstream_counters[(kind, server)] += 1

    def render(self) -> str:
        lines = [
            "# HELP judikt_tool_calls_total MCP tool calls evaluated by the gateway.",
            "# TYPE judikt_tool_calls_total counter",
        ]
        with self._lock:
            for (server, tool, outcome), count in sorted(self._counters.items()):
                lines.append(
                    f'judikt_tool_calls_total{{server="{server}",tool="{tool}",outcome="{outcome}"}} {count}'
                )
            lines.extend(
                [
                    "# HELP judikt_tool_duration_ms_total Total gateway tool-call duration in milliseconds.",
                    "# TYPE judikt_tool_duration_ms_total counter",
                ]
            )
            for (server, tool), duration_ms in sorted(self._duration_total_ms.items()):
                lines.append(
                    f'judikt_tool_duration_ms_total{{server="{server}",tool="{tool}"}} {duration_ms:.3f}'
                )
            lines.extend(
                [
                    "# HELP judikt_findings_total Security findings exported by outcome.",
                    "# TYPE judikt_findings_total counter",
                ]
            )
            for outcome, count in sorted(self._finding_counters.items()):
                lines.append(f'judikt_findings_total{{outcome="{outcome}"}} {count}')
            lines.extend(
                [
                    "# HELP judikt_audit_outbox_pending Audit records awaiting sink delivery.",
                    "# TYPE judikt_audit_outbox_pending gauge",
                    f"judikt_audit_outbox_pending {self._audit_outbox_pending}",
                    "# HELP judikt_audit_outbox_oldest_age_seconds Age of the oldest pending audit record.",
                    "# TYPE judikt_audit_outbox_oldest_age_seconds gauge",
                    f"judikt_audit_outbox_oldest_age_seconds {self._audit_outbox_oldest_age_seconds:.3f}",
                    "# HELP judikt_audit_delivery_failures_total Audit sink delivery failures.",
                    "# TYPE judikt_audit_delivery_failures_total counter",
                    f"judikt_audit_delivery_failures_total {self._audit_delivery_failures}",
                    "# HELP judikt_kill_switch_store_failures_total Kill-switch store read failures.",
                    "# TYPE judikt_kill_switch_store_failures_total counter",
                ]
            )
            for mode, count in sorted(self._kill_switch_store_failures.items()):
                lines.append(
                    f'judikt_kill_switch_store_failures_total{{mode="{mode}"}} {count}'
                )
            lines.extend(
                [
                    "# HELP judikt_rate_limiter_fallback_total Redis rate-limiter backend failures.",
                    "# TYPE judikt_rate_limiter_fallback_total counter",
                ]
            )
            for mode, count in sorted(self._rate_limiter_fallbacks.items()):
                lines.append(
                    f'judikt_rate_limiter_fallback_total{{mode="{mode}"}} {count}'
                )
            for kind, description in (
                ("timeouts", "Upstream MCP request deadlines exceeded."),
                ("restarts", "Upstream MCP subprocess restart attempts."),
                ("protocol_violations", "Upstream MCP protocol violations."),
            ):
                name = f"judikt_upstream_{kind}_total"
                lines.extend([f"# HELP {name} {description}", f"# TYPE {name} counter"])
                for (observed_kind, server), count in sorted(self._upstream_counters.items()):
                    if observed_kind == kind:
                        lines.append(f'{name}{{server="{server}"}} {count}')
        return "\n".join(lines) + "\n"
