from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority, ApprovalTokenError
from .content_guard import ContentGuard
from .models import PolicyDecision
from .rate_limiter import build_rate_limiter
from .risk import RiskEngine


class PolicyEngine:
    def __init__(self, policy_path: Path) -> None:
        # JSON is a YAML subset, which keeps this demo dependency-free.
        self.config = json.loads(policy_path.read_text())
        self.approvals = ApprovalAuthority()
        self.argument_guard = ContentGuard.from_policy(self.config)
        self.risk = RiskEngine()
        self._blocked = [re.compile(pattern, re.IGNORECASE) for pattern in self.config["blocked_argument_patterns"]]
        self._redacted_keys = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.config["redacted_key_patterns"]
        ]
        self._redacted_values = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.config["redacted_value_patterns"]
        ]
        self._rate_limiter = build_rate_limiter()
        self._disabled_tools: set[str] = set()
        self._disabled_servers: set[str] = set()
        self._lock = threading.Lock()

    @property
    def rate_limiter_mode(self) -> str:
        return self._rate_limiter.mode

    def evaluate(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        authenticated_actor: str = "",
    ) -> PolicyDecision:
        with self._lock:
            risk = self.risk.assess(server, tool, arguments)
            if server in self._disabled_servers:
                return self._decision(False, f"server {server!r} is disabled by kill switch", "kill_switch", risk)
            if tool in self._disabled_tools:
                return self._decision(False, f"tool {tool!r} is disabled by kill switch", "kill_switch", risk)
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
            claimed_actor = self._actor(arguments)
            if authenticated_actor and claimed_actor not in {"anonymous", authenticated_actor}:
                return self._decision(
                    False,
                    f"caller-supplied actor {claimed_actor!r} does not match authenticated subject",
                    "identity_mismatch",
                    risk,
                    action="DENY",
                )
            actor = authenticated_actor or claimed_actor
            if tool in self.config.get("actor_required_tools", []) and actor == "anonymous":
                return self._decision(
                    False,
                    f"actor is required for {tool!r}",
                    "authz",
                    risk,
                    action="DENY",
                )
            if not self._actor_can_call(actor, tool):
                return self._decision(
                    False,
                    f"actor {actor!r} is not authorized to call {tool!r}",
                    "authz",
                    risk,
                    action="DENY",
                )
            forbidden_key = self._find_forbidden_argument_key(arguments)
            if forbidden_key:
                return self._decision(
                    False,
                    f"caller-supplied credential field {forbidden_key!r} is forbidden; upstream credentials must be brokered by Judikt",
                    "token_passthrough",
                    risk,
                    action="DENY",
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
                    action="DENY",
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
                    action="DENY",
                )
            if not self._within_rate_limit(tool, actor, arguments):
                return self._decision(False, "tool call exceeded its per-minute limit", "rate_limit", risk)
            return self._decision(True, "allowed by policy", "allow", risk)

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
        return self.approvals.issue(
            actor=actor,
            reason=reason,
            server=server,
            tool=tool,
            arguments=arguments,
            ttl_seconds=ttl_seconds,
        )

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if self._is_redacted_key(str(key)) else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, str):
            result = value
            for pattern in self._redacted_values:
                result = pattern.sub("[REDACTED]", result)
            return result
        return value

    def set_tool_enabled(self, tool: str, enabled: bool) -> None:
        with self._lock:
            if enabled:
                self._disabled_tools.discard(tool)
            else:
                self._disabled_tools.add(tool)

    def set_server_enabled(self, server: str, enabled: bool) -> None:
        with self._lock:
            if enabled:
                self._disabled_servers.discard(server)
            else:
                self._disabled_servers.add(server)

    def kill_switches(self) -> dict[str, list[str]]:
        with self._lock:
            return {
                "disabled_tools": sorted(self._disabled_tools),
                "disabled_servers": sorted(self._disabled_servers),
            }

    def actor_can_call(self, actor: str, tool: str) -> bool:
        return self._actor_can_call(actor, tool)

    def _within_rate_limit(self, tool: str, actor: str, arguments: dict[str, Any]) -> bool:
        limit = self.config["rate_limits_per_minute"].get(
            tool, self.config["rate_limits_per_minute"]["default"]
        )
        environment = str(arguments.get("environment", "default")).lower()
        keys = [f"tool:{tool}"]
        if actor != "anonymous":
            keys.append(f"actor:{actor}:tool:{tool}")
        if environment in {"prod", "production"}:
            keys.append(f"environment:{environment}:tool:{tool}")
        for key in keys:
            if not self._rate_limiter.allow(key, limit, 60):
                return False
        global_limit = int(self.config.get("global_rate_limit_per_minute", 0) or 0)
        if global_limit and not self._rate_limiter.allow("global", global_limit, 60):
            return False
        return True

    def _is_redacted_key(self, key: str) -> bool:
        return any(pattern.search(key) for pattern in self._redacted_keys)

    def _has_approval(self, server: str, tool: str, arguments: dict[str, Any]) -> bool:
        token = arguments.get("approval_token")
        if isinstance(token, str) and token:
            try:
                self.approvals.verify(token=token, server=server, tool=tool, arguments=arguments)
                return True
            except ApprovalTokenError:
                return False
        return bool(self.config.get("allow_demo_boolean_approval", False) and arguments.get("approved") is True)

    def _actor(self, arguments: dict[str, Any]) -> str:
        for field in self.config.get("identity_argument_fields", []):
            actor = arguments.get(field)
            if actor:
                return str(actor)
        return "anonymous"

    def _actor_can_call(self, actor: str, tool: str) -> bool:
        permissions = self.config.get("actor_permissions", {})
        allowed_patterns = permissions.get(actor, permissions.get("anonymous", []))
        return any(self._permission_matches(pattern, tool) for pattern in allowed_patterns)

    @staticmethod
    def _permission_matches(pattern: str, tool: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            return tool.startswith(pattern[:-1])
        return pattern == tool

    def _dry_run_requested(self, tool: str, arguments: dict[str, Any]) -> bool:
        return bool(arguments.get("dry_run") is True and tool in self.config.get("dry_run_supported", []))

    def _shadow_mode_requested(self, tool: str, arguments: dict[str, Any]) -> bool:
        return bool(arguments.get("shadow_mode") is True and tool in self.config.get("shadow_mode_supported", []))

    def _needs_rollback_plan(self, tool: str, arguments: dict[str, Any]) -> bool:
        if tool not in self.config.get("rollback_plan_required", []):
            return False
        environment = str(arguments.get("environment", "production")).lower()
        if environment not in set(self.config.get("production_environments", ["prod", "production"])):
            return False
        plan = arguments.get("rollback_plan")
        if isinstance(plan, dict):
            return not plan
        if isinstance(plan, str):
            return len(plan.strip()) < 12
        return True

    def _find_forbidden_argument_key(self, value: Any) -> str | None:
        forbidden = {str(key).lower() for key in self.config.get("forbidden_argument_keys", [])}
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in forbidden:
                    return str(key)
                nested = self._find_forbidden_argument_key(item)
                if nested:
                    return nested
        elif isinstance(value, list):
            for item in value:
                nested = self._find_forbidden_argument_key(item)
                if nested:
                    return nested
        return None

    def _find_disallowed_argument_value(
        self, tool: str, arguments: dict[str, Any]
    ) -> str | None:
        constraints = self.config.get("allowed_argument_values", {}).get(tool, {})
        for key, allowed_values in constraints.items():
            if key not in arguments:
                continue
            if arguments[key] not in allowed_values:
                return str(key)
        return None

    @staticmethod
    def _decision(allowed: bool, reason: str, rule: str, risk: Any, action: str | None = None) -> PolicyDecision:
        if action is None:
            action = "ALLOW" if allowed else "DENY"
        return PolicyDecision(
            allowed,
            reason,
            rule,
            action=action,
            risk_score=risk.score,
            risk_level=risk.level,
            evidence=risk.evidence,
        )
