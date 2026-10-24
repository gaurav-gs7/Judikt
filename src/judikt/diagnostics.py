"""Operator-only diagnostics for upstream failures.

Judikt splits every upstream failure into two parts:

* a *public reason*: a fixed, Judikt-authored string that may be shown to an
  agent (only Judikt-controlled values such as the configured server name, the
  MCP method and the timeout are interpolated), and
* a *diagnostic*: the full operator detail, which can contain upstream stderr,
  upstream JSON-RPC error messages or transport exception text.

Diagnostics are written to the audit record, the operator's stderr and
telemetry. They never reach an agent, and they are always redacted first.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Iterable
from importlib import resources
from typing import Any

MAX_DIAGNOSTIC_BYTES = 4096
MAX_EXPOSED_MESSAGE_CHARS = 500
SAFE_RULE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ASSIGNMENT_KEYS = (
    r"api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|authorization|"
    r"password|passwd|pwd|secret|token|credential|private[_-]?key"
)
_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)\b((?:[a-z0-9_.-]*)(?:{_ASSIGNMENT_KEYS})[a-z0-9_.-]*)(\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;|]+)"
)


def _default_value_patterns() -> list[re.Pattern[str]]:
    try:
        document = json.loads(
            resources.files("judikt.resources").joinpath("default-policy.json").read_text()
        )
        patterns = document.get("redacted_value_patterns", [])
    except (OSError, ValueError):  # pragma: no cover - packaged resource is always present
        patterns = []
    return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]


_DEFAULT_VALUE_PATTERNS = _default_value_patterns()


def strip_control_characters(text: str) -> str:
    return "".join(
        character
        for character in text
        if character in "\t\n" or (ord(character) >= 32 and ord(character) != 127)
    )


def redact_diagnostic(
    text: str,
    value_patterns: Iterable[re.Pattern[str]] | None = None,
    *,
    limit_bytes: int = MAX_DIAGNOSTIC_BYTES,
) -> str:
    """Redact secrets from operator diagnostics and bound their size.

    ``value_patterns`` are the active policy's ``redacted_value_patterns``.
    Judikt's packaged default patterns are always applied as well, together
    with ``key=value`` assignments whose key names a credential.
    """

    result = strip_control_characters(str(text))
    for pattern in (*(value_patterns or ()), *_DEFAULT_VALUE_PATTERNS):
        result = pattern.sub("[REDACTED]", result)
    result = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", result)
    encoded = result.encode("utf-8", errors="replace")
    if len(encoded) > limit_bytes:
        result = encoded[: limit_bytes - 3].decode("utf-8", errors="ignore") + "..."
    return result


def exception_diagnostic(exc: BaseException) -> str:
    """Return the operator diagnostic for any exception."""

    diagnostic = getattr(exc, "diagnostic", None)
    if isinstance(diagnostic, str) and diagnostic:
        return diagnostic
    return f"{exc.__class__.__name__}: {exc}"


def safe_rule(value: Any, default: str = "upstream_error") -> str:
    """Accept an upstream-supplied rule only when it is a plain identifier."""

    if isinstance(value, str) and SAFE_RULE_PATTERN.fullmatch(value):
        return value
    return default


def emit_operator_diagnostic(
    diagnostic: str,
    *,
    correlation_id: str = "",
    server: str = "",
    tool: str = "",
    write: Callable[[str], Any] | None = None,
) -> None:
    """Write an already-redacted diagnostic to the operator's stderr.

    stdout is reserved for MCP protocol messages in stdio transports, so this
    only ever writes to stderr (which MCP clients log for the operator).
    """

    if not diagnostic:
        return
    prefix = "Judikt upstream diagnostic"
    context = " ".join(
        f"{key}={value}"
        for key, value in (
            ("correlation", correlation_id),
            ("server", server),
            ("tool", tool),
        )
        if value
    )
    line = f"{prefix} ({context}): {diagnostic}" if context else f"{prefix}: {diagnostic}"
    if write is not None:
        write(line)
        return
    try:
        print(line.replace("\n", " | "), file=sys.stderr, flush=True)
    except (OSError, ValueError):  # pragma: no cover - stderr closed during shutdown
        return
