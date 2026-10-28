from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority, ApprovalClaims, ApprovalTokenError
from .content_guard import ContentGuard
from .diagnostics import redact_diagnostic
from .metrics import Metrics
from .provenance import ProvenanceConfig
from .models import (
    APPROVAL_TOKEN_ARGUMENT,
    DEMO_APPROVAL_ARGUMENT,
    PolicyDecision,
)
from .rate_limiter import RateLimit, RateLimitResult, build_rate_limiter
from .risk import RiskEngine


class PolicyConfigurationError(ValueError):
    """A policy file is missing, unreadable, or not shaped the way Judikt needs."""


_REQUIRED_PATTERN_LISTS = (
    "blocked_argument_patterns",
    "redacted_key_patterns",
    "redacted_value_patterns",
)
_OPTIONAL_STRING_LISTS = (
    "forbidden_argument_keys",
    "approval_required",
    "actor_required_tools",
    "production_environments",
    "rollback_plan_required",
    "dry_run_supported",
    "shadow_mode_supported",
    "identity_argument_fields",
)


def load_policy_config(policy_path: Path) -> dict[str, Any]:
    """Read and validate a policy file, failing with an operator-readable error."""
    path = Path(policy_path)
    try:
        text = path.read_text()
    except FileNotFoundError:
        raise PolicyConfigurationError(f"policy file not found: {path}") from None
    except OSError as exc:
        raise PolicyConfigurationError(
            f"policy file {path} could not be read: {exc.strerror or exc}"
        ) from None
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyConfigurationError(
            f"policy file {path} is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"
        ) from None
    validate_policy_config(config, source=str(path))
    return config


def validate_policy_config(config: Any, *, source: str = "policy") -> None:
    def fail(location: str, expectation: str) -> None:
        raise PolicyConfigurationError(f"{source}: {location} {expectation}")

    def string_list(key: str) -> None:
        value = config[key]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            fail(f"'{key}'", "must be a list of strings")

    if not isinstance(config, dict):
        fail("the document", "must be a JSON object")
    for key in _REQUIRED_PATTERN_LISTS:
        if key not in config:
            fail(f"'{key}'", "is required")
        string_list(key)
        for index, pattern in enumerate(config[key]):
            try:
                re.compile(pattern)
            except re.error as exc:
                fail(f"'{key}[{index}]'", f"is not a valid regular expression ({exc})")
    for key in _OPTIONAL_STRING_LISTS:
        if key in config:
            string_list(key)
    allowed_tools = config.get("allowed_tools")
    if not isinstance(allowed_tools, dict):
        fail("'allowed_tools'", "is required and must map server names to lists of tool names")
    for server, tools in allowed_tools.items():
        if not isinstance(tools, list) or not all(isinstance(tool, str) for tool in tools):
            fail(f"'allowed_tools.{server}'", "must be a list of tool names")
    permissions = config.get("actor_permissions", {})
    if not isinstance(permissions, dict):
        fail("'actor_permissions'", "must map actor names to lists of tool patterns")
    for actor, patterns in permissions.items():
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            fail(f"'actor_permissions.{actor}'", "must be a list of tool patterns")
    limits = config.get("rate_limits_per_minute")
    if not isinstance(limits, dict) or "default" not in limits:
        fail("'rate_limits_per_minute'", "is required and must contain a 'default' limit")
    for tool, limit in limits.items():
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            fail(f"'rate_limits_per_minute.{tool}'", "must be a non-negative integer")
    if "global_rate_limit_per_minute" in config:
        limit = config["global_rate_limit_per_minute"]
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            fail("'global_rate_limit_per_minute'", "must be a non-negative integer")
    if "local_stdio_identity" in config and not isinstance(config["local_stdio_identity"], str):
        fail("'local_stdio_identity'", "must be a string")
    if "allow_demo_boolean_approval" in config and not isinstance(
        config["allow_demo_boolean_approval"], bool
    ):
        fail("'allow_demo_boolean_approval'", "must be true or false")
    try:
        ProvenanceConfig.from_policy(config)
    except ValueError as exc:
        raise PolicyConfigurationError(f"{source}: {exc}") from None


class PolicyEngine:
    def __init__(
        self,
        policy_path: Path,
        approval_authority: ApprovalAuthority | None = None,
        *,
        metrics: Metrics | None = None,
        production: bool = False,
    ) -> None:
        # JSON is a YAML subset, which keeps policy files dependency-free.
        self.config = load_policy_config(policy_path)
        self.approvals = approval_authority or ApprovalAuthority()
        self.argument_guard = ContentGuard.from_policy(self.config)
        self.risk = RiskEngine(self.config)
        self.provenance = ProvenanceConfig.from_policy(self.config)
        self._blocked = [re.compile(pattern, re.IGNORECASE) for pattern in self.config["blocked_argument_patterns"]]
        self._redacted_keys = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.config["redacted_key_patterns"]
        ]
        self._redacted_values = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.config["redacted_value_patterns"]
        ]
        self._rate_limiter = build_rate_limiter(
            self.config,
            metrics=metrics,
            production=production,
        )
        self._disabled_tools: set[str] = set()
        self._disabled_servers: set[str] = set()
        self._kill_switch_store: Any = None
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
        tool_definition: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        with self._lock:
            risk = self.risk.assess(server, tool, arguments, tool_definition)
            if self._kill_switch_store is not None:
                state = self._kill_switch_store.get_state()
                self._disabled_tools = set(state["tools"])
                self._disabled_servers = set(state["servers"])
            if server in self._disabled_servers:
                return self._decision(False, f"server {server!r} is disabled by kill switch", "kill_switch", risk)
            if tool in self._disabled_tools:
                return self._decision(False, f"tool {tool!r} is disabled by kill switch", "kill_switch", risk)
            if tool not in self.config["allowed_tools"].get(server, []):
                return self._decision(False, f"tool {tool!r} is not allowlisted for {server!r}", "allowlist", risk)
            argument_inspection = self.argument_guard.inspect(
                arguments,
                surface="tool_argument",
            )
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
            risk_requires_approval = (
                self.risk.action_for(risk.level) == "require_approval"
            )
            if (
                tool in self.config["approval_required"] or risk_requires_approval
            ) and not self._has_approval(server, tool, arguments):
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
            rate_limit = self._within_rate_limit(tool, actor, arguments)
            if rate_limit.unavailable:
                return self._decision(
                    False,
                    "shared rate-limiter backend is unavailable",
                    "rate_limiter_unavailable",
                    risk,
                )
            if not rate_limit.allowed:
                return self._decision(
                    False,
                    "tool call exceeded its per-minute limit",
                    "rate_limit",
                    risk,
                    extra_evidence=[
                        f"retry_after_seconds:{rate_limit.retry_after_seconds:.3f}"
                    ],
                )
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

    def redact_diagnostic(self, text: str) -> str:
        """Redact and bound operator-only diagnostic text before storing it."""

        return redact_diagnostic(text, self._redacted_values)

    def redact_mcp_result(self, value: Any) -> Any:
        if not isinstance(value, dict) or not isinstance(value.get("content"), list):
            return self.redact(value)
        result = dict(value)
        result["content"] = [self._redact_content_block(block) for block in value["content"]]
        if "structuredContent" in value:
            result["structuredContent"] = self.redact(value["structuredContent"])
        if "_meta" in value:
            result["_meta"] = self.redact(value["_meta"])
        return result

    def _redact_content_block(self, block: Any) -> Any:
        if not isinstance(block, dict):
            return self.redact(block)
        block_type = block.get("type")
        if block_type in {"image", "audio"}:
            return dict(block)
        if block_type == "resource":
            result = dict(block)
            resource = block.get("resource")
            if isinstance(resource, dict):
                redacted_resource = {
                    key: item if key == "blob" else self.redact(item)
                    for key, item in resource.items()
                }
                result["resource"] = redacted_resource
            return result
        return self.redact(block)

    def bind_kill_switch_store(self, store: Any) -> None:
        self._kill_switch_store = store

    def set_tool_enabled(
        self,
        tool: str,
        enabled: bool,
        *,
        actor: str = "local-operator",
        reason: str = "policy API request",
    ) -> None:
        if self._kill_switch_store is not None:
            self._kill_switch_store.set("tool", tool, enabled, actor, reason)
        with self._lock:
            if enabled:
                self._disabled_tools.discard(tool)
            else:
                self._disabled_tools.add(tool)

    def set_server_enabled(
        self,
        server: str,
        enabled: bool,
        *,
        actor: str = "local-operator",
        reason: str = "policy API request",
    ) -> None:
        if self._kill_switch_store is not None:
            self._kill_switch_store.set("server", server, enabled, actor, reason)
        with self._lock:
            if enabled:
                self._disabled_servers.discard(server)
            else:
                self._disabled_servers.add(server)

    def kill_switches(self) -> dict[str, Any]:
        if self._kill_switch_store is not None:
            state = self._kill_switch_store.get_state()
            return {
                "disabled_tools": sorted(state["tools"]),
                "disabled_servers": sorted(state["servers"]),
                "version": state["version"],
            }
        with self._lock:
            return {
                "disabled_tools": sorted(self._disabled_tools),
                "disabled_servers": sorted(self._disabled_servers),
            }

    def actor_can_call(self, actor: str, tool: str) -> bool:
        return self._actor_can_call(actor, tool)

    def approval_claims(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> ApprovalClaims | None:
        token = arguments.get(APPROVAL_TOKEN_ARGUMENT)
        if not isinstance(token, str) or not token:
            return None
        try:
            return self.approvals.verify(
                token=token,
                server=server,
                tool=tool,
                arguments=arguments,
            )
        except ApprovalTokenError:
            return None

    def _within_rate_limit(
        self,
        tool: str,
        actor: str,
        arguments: dict[str, Any],
    ) -> RateLimitResult:
        configured_limit = self.config["rate_limits_per_minute"].get(
            tool, self.config["rate_limits_per_minute"]["default"]
        )
        rate, burst = self._rate_limit_values(configured_limit)
        environment = str(arguments.get("environment", "default")).lower()
        keys = [f"tool:{tool}"]
        if actor != "anonymous":
            keys.append(f"actor:{actor}:tool:{tool}")
        if environment in {"prod", "production"}:
            keys.append(f"environment:{environment}:tool:{tool}")
        limits = [RateLimit(key, rate, burst) for key in keys]
        configured_global = self.config.get("global_rate_limit_per_minute", 0)
        global_rate, global_burst = self._rate_limit_values(configured_global)
        if global_rate:
            limits.append(RateLimit("global", global_rate, global_burst))
        return self._rate_limiter.allow_all(limits)

    @staticmethod
    def _rate_limit_values(configured: Any) -> tuple[float, int | None]:
        if isinstance(configured, dict):
            rate = float(configured.get("rate", 0))
            burst_value = configured.get("burst")
            burst = int(burst_value) if burst_value is not None else None
            return rate, burst
        return float(configured or 0), None

    def _is_redacted_key(self, key: str) -> bool:
        return any(pattern.search(key) for pattern in self._redacted_keys)

    def _has_approval(self, server: str, tool: str, arguments: dict[str, Any]) -> bool:
        if self.approval_claims(server, tool, arguments) is not None:
            return True
        return bool(
            self.demo_boolean_approval_enabled
            and arguments.get(DEMO_APPROVAL_ARGUMENT) is True
        )

    @property
    def demo_boolean_approval_enabled(self) -> bool:
        return self.config.get("allow_demo_boolean_approval", False) is True

    def may_require_approval(
        self,
        tool: str,
        tool_definition: dict[str, Any] | None = None,
    ) -> bool:
        """Whether some call to ``tool`` can need an approval under this policy.

        Used to advertise Judikt's optional ``approval_token`` argument. Risk
        rules that depend on argument values are considered at their worst case.
        """

        if tool in self.config.get("approval_required", []):
            return True
        if self.provenance.mode == "require_approval" and self.risk.tier(tool, tool_definition) != "read":
            return True
        return self.risk.may_require_approval(tool, tool_definition)

    def has_approval(self, server: str, tool: str, arguments: dict[str, Any]) -> bool:
        return self._has_approval(server, tool, arguments)

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
    def _decision(
        allowed: bool,
        reason: str,
        rule: str,
        risk: Any,
        action: str | None = None,
        extra_evidence: list[str] | None = None,
    ) -> PolicyDecision:
        if action is None:
            action = "ALLOW" if allowed else "DENY"
        return PolicyDecision(
            allowed,
            reason,
            rule,
            action=action,
            risk_score=risk.score,
            risk_level=risk.level,
            evidence=[*risk.evidence, *(extra_evidence or [])],
        )
