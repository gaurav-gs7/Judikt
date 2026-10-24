from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Arguments owned by Judikt itself. They carry approval evidence for Judikt's
# policy engine and are never forwarded to an upstream MCP server.
APPROVAL_TOKEN_ARGUMENT = "approval_token"
DEMO_APPROVAL_ARGUMENT = "approved"
JUDIKT_CONTROL_ARGUMENTS = frozenset({APPROVAL_TOKEN_ARGUMENT, DEMO_APPROVAL_ARGUMENT})


def strip_control_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Return the arguments an upstream may receive."""

    return {
        key: value
        for key, value in arguments.items()
        if key not in JUDIKT_CONTROL_ARGUMENTS
    }


def declared_control_arguments(definition: dict[str, Any] | None) -> list[str]:
    """Return Judikt control argument names an upstream schema declares itself."""

    if not isinstance(definition, dict):
        return []
    schema = definition.get("inputSchema")
    properties = schema.get("properties") if isinstance(schema, dict) else None
    required = schema.get("required") if isinstance(schema, dict) else None
    declared = set(properties) if isinstance(properties, dict) else set()
    if isinstance(required, list):
        declared |= {name for name in required if isinstance(name, str)}
    return sorted(declared & JUDIKT_CONTROL_ARGUMENTS)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    title: str | None = None
    annotations: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None

    def as_mcp(self) -> dict[str, Any]:
        result = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.title is not None:
            result["title"] = self.title
        if self.annotations is not None:
            result["annotations"] = self.annotations
        if self.output_schema is not None:
            result["outputSchema"] = self.output_schema
        if self.meta is not None:
            result["_meta"] = self.meta
        return result


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    rule: str
    action: str = "ALLOW"
    risk_score: int = 0
    risk_level: str = "low"
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCallResult:
    correlation_id: str
    allowed: bool
    server: str
    tool: str
    reason: str
    result: Any = None
    rule: str = ""
    action: str = "ALLOW"
    risk_score: int = 0
    risk_level: str = "low"
    evidence: list[str] = field(default_factory=list)
    mcp_result: dict[str, Any] | None = field(default=None, repr=False)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("mcp_result", None)
        return result
