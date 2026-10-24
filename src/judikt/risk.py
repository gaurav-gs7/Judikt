from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any

from .policy_init import MUTATION_NAME_PATTERN, classify_tool


TIERS = ("read", "write", "destructive")
RISK_KEYS = {
    "tier_scores",
    "annotation_modifiers",
    "tool_rules",
    "argument_rules",
    "levels",
    "risk_actions",
}
DEFAULT_RISK = {
    "tier_scores": {"read": 10, "write": 40, "destructive": 70},
    "annotation_modifiers": [],
    "tool_rules": [],
    "argument_rules": [],
    "levels": {"critical": 80, "high": 60, "medium": 30},
    "risk_actions": {},
}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    evidence: list[str]


class RiskConfigError(ValueError):
    pass


class RiskEngine:
    """Deterministic policy-driven risk scorer."""

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        policy = policy or {}
        configured = policy.get("risk", DEFAULT_RISK)
        if not isinstance(configured, dict):
            raise RiskConfigError("risk: expected an object")
        self.config = _validate_risk_config(configured)
        classifications = policy.get("tool_classification", {})
        if not isinstance(classifications, dict):
            raise RiskConfigError("tool_classification: expected an object")
        self.classifications = classifications

    def assess(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        tool_definition: dict[str, Any] | None = None,
    ) -> RiskAssessment:
        del server
        tier, annotations = self._classification(tool, tool_definition)
        score = self.config["tier_scores"][tier]
        evidence = ["base MCP tool invocation risk"]

        for modifier in self.config["annotation_modifiers"]:
            if annotations.get(modifier["annotation"]) == modifier["equals"]:
                score += modifier["add"]
                evidence.append(modifier["evidence"])

        for rule in self.config["tool_rules"]:
            if _tool_matches(tool, rule):
                score += rule["add"]
                evidence.append(rule["evidence"])

        for rule in self.config["argument_rules"]:
            if _argument_matches(arguments.get(rule["argument"]), rule):
                score += rule["add"]
                evidence.append(rule["evidence"])

        score = min(score, 100)
        return RiskAssessment(score, self._level(score), evidence)

    def action_for(self, level: str) -> str | None:
        return self.config["risk_actions"].get(level)

    def may_require_approval(
        self,
        tool: str,
        tool_definition: dict[str, Any] | None = None,
    ) -> bool:
        """Whether any argument values can push ``tool`` into an approval level."""

        if not self.config["risk_actions"]:
            return False
        lowest = self.assess("", tool, {}, tool_definition).score
        highest = min(
            lowest + sum(rule["add"] for rule in self.config["argument_rules"]),
            100,
        )
        order = ["low", "medium", "high", "critical"]
        start = order.index(self._level(lowest))
        end = order.index(self._level(highest))
        reachable = order[start : end + 1]
        return any(self.action_for(level) == "require_approval" for level in reachable)

    def _classification(
        self,
        tool: str,
        tool_definition: dict[str, Any] | None,
    ) -> tuple[str, dict[str, Any]]:
        configured = self.classifications.get(tool, {})
        if not isinstance(configured, dict):
            configured = {}
        annotations = configured.get("annotations", {})
        if not isinstance(annotations, dict):
            annotations = {}
        configured_tier = configured.get("tier")

        runtime_tier: str | None = None
        if tool_definition is not None:
            runtime = classify_tool(tool, tool_definition)
            runtime_tier = runtime["tier"]
            runtime_annotations = runtime["annotations"]
            if isinstance(runtime_annotations, dict):
                annotations = runtime_annotations

        implied_tier = (
            "destructive" if MUTATION_NAME_PATTERN.search(tool) is not None else "read"
        )
        tiers = [implied_tier]
        if configured_tier in TIERS:
            tiers.append(configured_tier)
        if runtime_tier in TIERS:
            tiers.append(runtime_tier)
        tier = max(tiers, key=TIERS.index)
        return tier, annotations

    def _level(self, score: int) -> str:
        levels = self.config["levels"]
        if score >= levels["critical"]:
            return "critical"
        if score >= levels["high"]:
            return "high"
        if score >= levels["medium"]:
            return "medium"
        return "low"


def _validate_risk_config(config: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(config) - RISK_KEYS)
    if unknown:
        raise RiskConfigError(f"risk.{unknown[0]}: unknown key")
    merged = {**DEFAULT_RISK, **config}
    _validate_number_map("risk.tier_scores", merged["tier_scores"], set(TIERS))
    _validate_number_map(
        "risk.levels", merged["levels"], {"critical", "high", "medium"}
    )
    levels = merged["levels"]
    if not levels["critical"] > levels["high"] > levels["medium"]:
        raise RiskConfigError(
            "risk.levels: expected critical > high > medium thresholds"
        )

    modifiers = merged["annotation_modifiers"]
    if not isinstance(modifiers, list):
        raise RiskConfigError("risk.annotation_modifiers: expected a list")
    for index, modifier in enumerate(modifiers):
        path = f"risk.annotation_modifiers[{index}]"
        _validate_rule_keys(
            path, modifier, {"annotation", "equals", "add", "evidence"}
        )
        _validate_text(modifier, "annotation", path)
        _validate_add_and_evidence(modifier, path)

    tool_rules = merged["tool_rules"]
    if not isinstance(tool_rules, list):
        raise RiskConfigError("risk.tool_rules: expected a list")
    for index, rule in enumerate(tool_rules):
        path = f"risk.tool_rules[{index}]"
        _validate_rule_keys(
            path, rule, {"match", "match_type", "add", "evidence"}
        )
        _validate_text(rule, "match", path)
        match_type = rule.get("match_type", "glob")
        if match_type not in {"glob", "regex"}:
            raise RiskConfigError(f"{path}.match_type: expected 'glob' or 'regex'")
        if match_type == "regex":
            _compile_regex(rule["match"], f"{path}.match")
        _validate_add_and_evidence(rule, path)

    argument_rules = merged["argument_rules"]
    if not isinstance(argument_rules, list):
        raise RiskConfigError("risk.argument_rules: expected a list")
    for index, rule in enumerate(argument_rules):
        path = f"risk.argument_rules[{index}]"
        _validate_rule_keys(
            path,
            rule,
            {"argument", "in", "prefix", "regex", "add", "evidence"},
        )
        _validate_text(rule, "argument", path)
        operators = [name for name in ("in", "prefix", "regex") if name in rule]
        if len(operators) != 1:
            raise RiskConfigError(
                f"{path}: expected exactly one of 'in', 'prefix', or 'regex'"
            )
        operator = operators[0]
        if operator == "in" and not isinstance(rule["in"], list):
            raise RiskConfigError(f"{path}.in: expected a list")
        if operator == "prefix" and not isinstance(rule["prefix"], (str, list)):
            raise RiskConfigError(f"{path}.prefix: expected a string or list")
        if operator == "regex":
            _validate_text(rule, "regex", path)
            _compile_regex(rule["regex"], f"{path}.regex")
        _validate_add_and_evidence(rule, path)

    actions = merged["risk_actions"]
    if not isinstance(actions, dict):
        raise RiskConfigError("risk.risk_actions: expected an object")
    for level, action in actions.items():
        path = f"risk.risk_actions.{level}"
        if level not in {"low", "medium", "high", "critical"}:
            raise RiskConfigError(f"{path}: unknown risk level")
        if action != "require_approval":
            raise RiskConfigError(f"{path}: expected 'require_approval'")
    return merged


def _validate_number_map(path: str, value: Any, keys: set[str]) -> None:
    if not isinstance(value, dict):
        raise RiskConfigError(f"{path}: expected an object")
    unknown = sorted(set(value) - keys)
    missing = sorted(keys - set(value))
    if unknown:
        raise RiskConfigError(f"{path}.{unknown[0]}: unknown key")
    if missing:
        raise RiskConfigError(f"{path}.{missing[0]}: missing key")
    for key in sorted(keys):
        number = value[key]
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            raise RiskConfigError(f"{path}.{key}: expected a number")
        if number < 0 or number > 100:
            raise RiskConfigError(f"{path}.{key}: expected a number from 0 to 100")


def _validate_rule_keys(path: str, rule: Any, allowed: set[str]) -> None:
    if not isinstance(rule, dict):
        raise RiskConfigError(f"{path}: expected an object")
    unknown = sorted(set(rule) - allowed)
    if unknown:
        raise RiskConfigError(f"{path}.{unknown[0]}: unknown key")


def _validate_text(rule: dict[str, Any], key: str, path: str) -> None:
    if not isinstance(rule.get(key), str) or not rule[key]:
        raise RiskConfigError(f"{path}.{key}: expected a non-empty string")


def _validate_add_and_evidence(rule: dict[str, Any], path: str) -> None:
    add = rule.get("add")
    if isinstance(add, bool) or not isinstance(add, (int, float)) or add < 0:
        raise RiskConfigError(f"{path}.add: expected a non-negative number")
    _validate_text(rule, "evidence", path)


def _compile_regex(pattern: str, path: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RiskConfigError(f"{path}: invalid regex: {exc}") from exc


def _tool_matches(tool: str, rule: dict[str, Any]) -> bool:
    if rule.get("match_type", "glob") == "regex":
        return re.search(rule["match"], tool) is not None
    return fnmatch.fnmatchcase(tool, rule["match"])


def _argument_matches(value: Any, rule: dict[str, Any]) -> bool:
    if "in" in rule:
        return value in rule["in"]
    rendered = str(value) if value is not None else ""
    if "prefix" in rule:
        prefixes = rule["prefix"]
        if isinstance(prefixes, str):
            prefixes = [prefixes]
        return any(rendered.startswith(prefix) for prefix in prefixes)
    return re.search(rule["regex"], rendered) is not None
