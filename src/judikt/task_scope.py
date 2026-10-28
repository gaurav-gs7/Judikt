"""Per-task write scopes: the writes a task is expected to make, declared up front.

Some injections carry nothing to trace: "unlock the front door" names no
address, account or identifier. What gives them away is that the user's task
never needed that write. A task scope lists the write and destructive tools a
task may call; any other write needs human approval under rule ``task_scope``.

The scope must come from the user, before untrusted content can influence it:

* ``operator``: the operator sets ``task_scope.write_tools`` in the policy, or
  ``judikt wrap --task-writes`` / ``JUDIKT_TASK_WRITES`` for one session.
* ``agent``: the gateway also exposes ``judikt_declare_task``. The agent calls
  it once, from the user's request, before any tool result has reached it. The
  first tool result seals the scope; an agent that never declared is sealed
  with an empty scope, so every later write needs approval.

Read tools are never limited by a scope. No model is involved.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Any, Mapping

DECLARE_TOOL = "judikt_declare_task"
MODES = ("off", "operator", "agent")
DEFAULT_MODE = "operator"
ENVIRONMENT_VARIABLE = "JUDIKT_TASK_WRITES"
MAX_DECLARED_TOOLS = 64
MAX_SCOPES = 10_000


def parse_tool_list(text: str) -> frozenset[str]:
    """``"a, b"`` -> {"a", "b"}; ``"none"`` or blank -> an empty scope."""

    names = {name.strip() for name in text.split(",") if name.strip()}
    return frozenset() if names == {"none"} else frozenset(names)


@dataclass(frozen=True)
class TaskScopeConfig:
    mode: str = DEFAULT_MODE
    write_tools: frozenset[str] | None = None

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    @property
    def can_limit(self) -> bool:
        """Whether some write can ever fall outside a scope under this config."""

        return self.mode == "agent" or (self.mode == "operator" and self.write_tools is not None)

    @classmethod
    def from_policy(
        cls, policy: dict[str, Any], environment: Mapping[str, str] | None = None
    ) -> TaskScopeConfig:
        """Read ``task_scope``, raising ``ValueError`` when malformed.

        ``JUDIKT_TASK_WRITES`` in ``environment`` replaces the policy's list.
        """

        section = policy.get("task_scope", {})
        if not isinstance(section, dict):
            raise ValueError("'task_scope' must be an object")
        unknown = set(section) - {"mode", "write_tools"}
        if unknown:
            raise ValueError(f"'task_scope' has unknown key(s): {', '.join(sorted(unknown))}")
        mode = section.get("mode", DEFAULT_MODE)
        if mode not in MODES:
            raise ValueError(f"'task_scope.mode' must be one of {', '.join(MODES)}")
        tools = section.get("write_tools")
        if tools is not None and (not isinstance(tools, list) or not all(isinstance(t, str) for t in tools)):
            raise ValueError("'task_scope.write_tools' must be a list of tool names")
        write_tools = frozenset(tools) if tools is not None else None
        override = (environment if environment is not None else os.environ).get(ENVIRONMENT_VARIABLE)
        if override is not None:
            write_tools = parse_tool_list(override)
        return cls(mode=mode, write_tools=write_tools)


def declare_tool_definition() -> dict[str, Any]:
    return {
        "name": DECLARE_TOOL,
        "description": (
            "Declare, before reading anything, which write or destructive tools the user's "
            "request needs. Call once, at the start of the task, from the user's own words. "
            "After the first tool result the declaration is sealed: other writes need human "
            "approval, so declare everything the user asked for and nothing else."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "write_tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": MAX_DECLARED_TOOLS,
                    "description": "Names of the write or destructive tools this task will call.",
                },
                "purpose": {"type": "string", "description": "The user's request, in one line."},
            },
            "required": ["write_tools"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "title": "Declare task writes"},
    }


class TaskScopeStore:
    def __init__(self, config: TaskScopeConfig | None = None) -> None:
        self.config = config or TaskScopeConfig()
        self._declared: dict[str, frozenset[str]] = {}
        self._sealed: set[str] = set()
        self._lock = threading.Lock()

    @property
    def agent_declarations(self) -> bool:
        return self.config.mode == "agent"

    def declare(self, actor: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        if not self.agent_declarations:
            return False, "task declarations are not enabled (task_scope.mode is not 'agent')"
        tools = arguments.get("write_tools")
        if (
            not isinstance(tools, list)
            or len(tools) > MAX_DECLARED_TOOLS
            or not all(isinstance(tool, str) and tool for tool in tools)
        ):
            return False, f"write_tools must be a list of at most {MAX_DECLARED_TOOLS} tool names"
        with self._lock:
            if actor in self._sealed:
                return False, "the task scope is sealed: a tool result has already reached the agent"
            if actor in self._declared:
                return False, "the task scope was already declared for this session"
            if len(self._declared) >= MAX_SCOPES:
                return False, "too many task scopes are open"
            self._declared[actor] = frozenset(tools)
        return True, f"task scope declared: {', '.join(sorted(tools)) or 'no writes'}"

    def seal(self, actor: str) -> None:
        """Called when a tool result reaches ``actor``; later declarations are refused."""

        if not self.agent_declarations:
            return
        with self._lock:
            if actor in self._sealed or len(self._sealed) >= MAX_SCOPES:
                return
            self._sealed.add(actor)
            self._declared.setdefault(actor, frozenset())

    def scope(self, actor: str) -> frozenset[str] | None:
        """The write tools ``actor`` may call, or ``None`` when nothing limits it."""

        if not self.config.enabled:
            return None
        operator = self.config.write_tools
        if not self.agent_declarations:
            return operator
        with self._lock:
            declared = self._declared.get(actor)
        if declared is None:
            return operator
        return declared if operator is None else declared & operator

    def permits(self, actor: str, server: str, tool: str) -> bool:
        scope = self.scope(actor)
        return scope is None or tool in scope or f"{server}/{tool}" in scope
