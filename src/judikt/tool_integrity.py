from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .content_guard import ContentGuard


PIN_FIELDS = ("description", "inputSchema", "annotations", "outputSchema")


class ToolIntegrityError(RuntimeError):
    pass


class ToolDriftError(ToolIntegrityError):
    def __init__(
        self,
        *,
        server: str,
        state_key: str,
        pin_path: Path,
        added_tools: list[str],
        removed_tools: list[str],
        changed_tools: dict[str, list[str]],
        legacy: bool = False,
    ) -> None:
        self.server = server
        self.state_key = state_key
        self.pin_path = pin_path
        self.added_tools = added_tools
        self.removed_tools = removed_tools
        self.changed_tools = changed_tools
        self.legacy = legacy
        super().__init__(self.format_message())

    @property
    def accept_command(self) -> str:
        return f"judikt pins accept {shlex.quote(self.state_key)} --yes"

    def one_line(self) -> str:
        if self.legacy:
            details = "legacy pin; per-tool diff unavailable"
        else:
            parts = []
            if self.added_tools:
                parts.append(f"added: {_safe_names(self.added_tools)}")
            if self.removed_tools:
                parts.append(f"removed: {_safe_names(self.removed_tools)}")
            if self.changed_tools:
                changed = ", ".join(
                    f"{_safe_name(name)} ({', '.join(fields)})"
                    for name, fields in self.changed_tools.items()
                )
                parts.append(f"changed: {changed}")
            details = "; ".join(parts) or "catalog digest changed"
        return f"tool definition drift detected for {_safe_name(self.server)}: {details}; accept with: {self.accept_command}"

    def format_message(self) -> str:
        lines = [
            f"Tool definition drift detected for {_safe_name(self.server)}.",
            f"State key: {self.state_key}",
            f"Pin file: {self.pin_path}",
        ]
        if self.legacy:
            lines.append("Changes: legacy pin; per-tool diff unavailable")
        else:
            lines.extend(
                [
                    f"Added tools: {_safe_names(self.added_tools) if self.added_tools else 'none'}",
                    f"Removed tools: {_safe_names(self.removed_tools) if self.removed_tools else 'none'}",
                    "Changed tools: " + (
                        ", ".join(
                            f"{_safe_name(name)} ({', '.join(fields)})"
                            for name, fields in self.changed_tools.items()
                        )
                        if self.changed_tools
                        else "none"
                    ),
                ]
            )
        lines.extend(
            [
                f"Review: judikt pins show {shlex.quote(self.state_key)}",
                f"Accept: {self.accept_command}",
            ]
        )
        return "\n".join(lines)


@dataclass(frozen=True)
class ToolPinMetadata:
    state_key: str
    fingerprint: str = ""
    command: tuple[str, ...] = ()
    cwd: str = ""
    environment_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolIntegrityReport:
    server: str
    digest: str
    status: str
    tool_count: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolIntegrityStore:
    """Trust-on-first-use pins for MCP tool definitions with fail-closed drift checks."""

    def __init__(
        self,
        path: Path,
        content_guard: ContentGuard,
        mode: str | None = None,
        metadata: dict[str, ToolPinMetadata] | None = None,
    ) -> None:
        self.path = path
        self.content_guard = content_guard
        self.mode = mode or os.getenv("JUDIKT_TOOL_PIN_MODE", "enforce")
        if self.mode not in {"enforce", "refresh", "disabled"}:
            raise ValueError("tool pin mode must be enforce, refresh, or disabled")
        if self.mode == "refresh":
            print(
                "WARNING: JUDIKT_TOOL_PIN_MODE=refresh re-trusts every MCP server in this pin file.",
                file=sys.stderr,
            )
        self.metadata = metadata or {}
        self._lock = threading.Lock()

    def verify(self, server: str, tools: list[dict[str, Any]]) -> ToolIntegrityReport:
        self._inspect(server, tools)
        digest = _tool_digest(tools)
        if self.mode == "disabled":
            return ToolIntegrityReport(server, digest, "disabled", len(tools))
        with self._lock:
            pins = self._read()
            observed = pins.get(server)
            if observed is None or self.mode == "refresh":
                pins[server] = self._entry(server, tools)
                self._write(pins)
                status = "pinned" if observed is None else "refreshed"
                return ToolIntegrityReport(server, digest, status, len(tools))
            if isinstance(observed, str):
                if observed != _legacy_tool_digest(tools):
                    raise self._drift(server, {}, tools, legacy=True)
                pins[server] = self._entry(server, tools)
                self._write(pins)
                return ToolIntegrityReport(server, digest, "upgraded", len(tools))
            pinned_tools = _pinned_tools(observed)
            drift = self._drift(server, pinned_tools, tools)
            if drift.added_tools or drift.removed_tools or drift.changed_tools:
                raise drift
            return ToolIntegrityReport(server, digest, "verified", len(tools))

    def compare(self, server: str, tools: list[dict[str, Any]]) -> ToolDriftError | None:
        self._inspect(server, tools)
        observed = self._read().get(server)
        if observed is None:
            return self._drift(server, {}, tools)
        if isinstance(observed, str):
            return None if observed == _legacy_tool_digest(tools) else self._drift(
                server, {}, tools, legacy=True
            )
        drift = self._drift(server, _pinned_tools(observed), tools)
        return drift if drift.added_tools or drift.removed_tools or drift.changed_tools else None

    def accept(
        self,
        server: str,
        tools: list[dict[str, Any]],
        tool_names: list[str] | None = None,
    ) -> ToolIntegrityReport:
        self._inspect(server, tools)
        with self._lock:
            pins = self._read()
            observed = pins.get(server)
            current = _tool_records(tools)
            if tool_names:
                pinned = {} if isinstance(observed, str) else dict(_pinned_tools(observed or {}))
                known = set(pinned) | set(current)
                unknown = sorted(set(tool_names) - known)
                if unknown:
                    raise ToolIntegrityError(f"unknown tool selection: {', '.join(unknown)}")
                for name in tool_names:
                    if name in current:
                        pinned[name] = current[name]
                    else:
                        pinned.pop(name, None)
                pins[server] = self._entry_from_records(server, pinned, observed)
            else:
                pins[server] = self._entry(server, tools, observed)
            self._write(pins)
        return ToolIntegrityReport(server, _tool_digest(tools), "accepted", len(tools))

    def entries(self) -> dict[str, Any]:
        return self._read()

    def _inspect(self, server: str, tools: list[dict[str, Any]]) -> None:
        inspection = self.content_guard.inspect(tools)
        if not inspection.allowed:
            rules = sorted({finding.rule for finding in inspection.findings})
            raise ToolIntegrityError(
                f"tool metadata from {server!r} was quarantined: {', '.join(rules)}"
            )

    def _entry(
        self,
        server: str,
        tools: list[dict[str, Any]],
        previous: Any = None,
    ) -> dict[str, Any]:
        return self._entry_from_records(server, _tool_records(tools), previous)

    def _entry_from_records(
        self,
        server: str,
        records: dict[str, dict[str, Any]],
        previous: Any = None,
    ) -> dict[str, Any]:
        metadata = self.metadata.get(server, ToolPinMetadata(server))
        previous_entry = previous if isinstance(previous, dict) else {}
        command = shlex.join(metadata.command) if metadata.command else previous_entry.get("command", "")
        return {
            "schema_version": 2,
            "digest": _records_digest(records),
            "fingerprint": metadata.fingerprint or previous_entry.get("fingerprint", ""),
            "command": command,
            "cwd": metadata.cwd or previous_entry.get("cwd", ""),
            "environment_names": list(
                metadata.environment_names or previous_entry.get("environment_names", [])
            ),
            "pinned_at": datetime.now(UTC).isoformat(),
            "tools": records,
        }

    def _drift(
        self,
        server: str,
        pinned: dict[str, dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        legacy: bool = False,
    ) -> ToolDriftError:
        current = _tool_records(tools)
        added = sorted(set(current) - set(pinned))
        removed = sorted(set(pinned) - set(current))
        changed = {}
        for name in sorted(set(pinned) & set(current)):
            if pinned[name].get("digest") == current[name]["digest"]:
                continue
            old_fields = pinned[name].get("fields", {})
            fields = [
                field
                for field in PIN_FIELDS
                if old_fields.get(field) != current[name]["fields"][field]
            ]
            changed[name] = fields or ["definition"]
        metadata = self.metadata.get(server, ToolPinMetadata(server))
        return ToolDriftError(
            server=server,
            state_key=metadata.state_key,
            pin_path=self.path,
            added_tools=added,
            removed_tools=removed,
            changed_tools=changed,
            legacy=legacy,
        )

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        parsed = json.loads(self.path.read_text())
        if not isinstance(parsed, dict):
            raise ToolIntegrityError("tool pin file must contain a JSON object")
        return parsed

    def _write(self, pins: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n")
        temporary.replace(self.path)


def _pinned_tools(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if entry.get("schema_version") != 2 or not isinstance(entry.get("tools"), dict):
        raise ToolIntegrityError("tool pin entry must use schema_version 2")
    return entry["tools"]


def _tool_records(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    records = {}
    for tool in tools:
        name = str(tool.get("name", ""))
        records[name] = {
            "digest": _canonical_digest(tool),
            "fields": {field: _canonical_digest(tool.get(field)) for field in PIN_FIELDS},
        }
    return records


def _tool_digest(tools: list[dict[str, Any]]) -> str:
    return _records_digest(_tool_records(tools))


def _records_digest(records: dict[str, dict[str, Any]]) -> str:
    return _canonical_digest({name: record["digest"] for name, record in sorted(records.items())})


def _legacy_tool_digest(tools: list[dict[str, Any]]) -> str:
    return _canonical_digest(tools)


def _canonical_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _safe_name(value: str) -> str:
    clean = "".join(character for character in str(value) if character.isprintable())
    return clean[:80]


def _safe_names(values: list[str]) -> str:
    return ", ".join(_safe_name(value) for value in values)


def verify_unique_tool_names(definitions: dict[str, list[dict[str, Any]]]) -> None:
    owners: dict[str, str] = {}
    for server, tools in definitions.items():
        for tool in tools:
            name = str(tool.get("name", ""))
            if not name:
                raise ToolIntegrityError(f"MCP server {server!r} advertised a tool without a name")
            previous = owners.get(name)
            if previous is not None:
                raise ToolIntegrityError(
                    f"cross-server tool shadowing detected: {name!r} is advertised by {previous!r} and {server!r}"
                )
            owners[name] = server
