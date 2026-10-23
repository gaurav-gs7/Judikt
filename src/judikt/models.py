from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


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
