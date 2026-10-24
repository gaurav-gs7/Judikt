from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from .content_guard import ContentGuard
from .paths import state_root
from .protocol import StdioMCPClient
from .remote_protocol import StreamableHTTPMCPClient
from .tool_integrity import ToolIntegrityError, ToolIntegrityStore, ToolPinMetadata


def run_pins_command(args: Any) -> None:
    if args.pins_command == "list":
        _list_pins()
    elif args.pins_command == "show":
        _show_pin(args.state_key)
    elif args.pins_command == "accept":
        _accept_pin(args.state_key, args.tools, args.yes)


def _list_pins() -> None:
    rows = []
    upstream_root = state_root() / "upstreams"
    if upstream_root.is_dir():
        for directory in sorted(upstream_root.iterdir()):
            pin_path = directory / "audit.tool-pins.json"
            if not pin_path.is_file():
                continue
            for server, entry in _load_entries(pin_path).items():
                rows.append(
                    {
                        "state_key": directory.name,
                        "display_name": server,
                        "tool_count": len(entry.get("tools", {})) if isinstance(entry, dict) else 0,
                        "pinned_at": entry.get("pinned_at", "legacy") if isinstance(entry, dict) else "legacy",
                    }
                )
    print(json.dumps(rows, indent=2, sort_keys=True))


def _show_pin(state_key: str) -> None:
    _, pin_path = _state_paths(state_key)
    entries = _load_entries(pin_path)
    rendered = {}
    for server, entry in entries.items():
        if isinstance(entry, str):
            rendered[server] = {"schema_version": 1, "digest": entry}
            continue
        rendered[server] = {
            "schema_version": entry.get("schema_version"),
            "fingerprint": entry.get("fingerprint", ""),
            "command": entry.get("command", ""),
            "pinned_at": entry.get("pinned_at", ""),
            "tools": {
                name: record.get("fields", {})
                for name, record in entry.get("tools", {}).items()
                if isinstance(record, dict)
            },
        }
    print(json.dumps(rendered, indent=2, sort_keys=True))


def _accept_pin(state_key: str, tool_names: list[str] | None, yes: bool) -> None:
    _, pin_path = _state_paths(state_key)
    entries = _load_entries(pin_path, allow_invalid_mac=True)
    if len(entries) != 1:
        raise ToolIntegrityError("pins accept requires exactly one server entry in the state pin file")
    server, entry = next(iter(entries.items()))
    if not isinstance(entry, dict) or entry.get("schema_version") != 2:
        raise ToolIntegrityError("legacy pins must first verify successfully before selective acceptance")
    command = shlex.split(str(entry.get("command", "")))
    if not command:
        raise ToolIntegrityError("pin entry does not contain a launch command")
    cwd = str(entry.get("cwd", "")) or None
    names = tuple(str(name) for name in entry.get("environment_names", []))
    missing = [name for name in names if name not in os.environ]
    if missing:
        raise ToolIntegrityError(
            f"missing environment variables required by pinned upstream: {', '.join(missing)}"
        )
    environment = {name: os.environ[name] for name in names}
    metadata = ToolPinMetadata(
        state_key=state_key,
        fingerprint=str(entry.get("fingerprint", "")),
        command=tuple(command),
        cwd=cwd or "",
        environment_names=names,
    )
    if command[0] == "streamable-http":
        allow_private_network = "--allow-private-network" in command[1:-1]
        client = StreamableHTTPMCPClient(
            server,
            url=command[-1],
            headers=environment,
            allow_private_network=allow_private_network,
        )
    else:
        client = StdioMCPClient(
            server,
            command=command,
            environment=environment,
            cwd=cwd,
            inherit_environment=False,
        )
    try:
        tools = client.list_tools()
    finally:
        client.close()
    store = ToolIntegrityStore(
        pin_path,
        ContentGuard(),
        metadata={server: metadata},
    )
    drift = store.compare(server, tools)
    if drift is None:
        print("No tool-definition drift detected.", file=sys.stderr)
        return
    print(drift, file=sys.stderr)
    if not yes:
        print("Accept this tool-definition change? [y/N]", file=sys.stderr)
        if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
            raise ToolIntegrityError("pin acceptance cancelled")
    report = store.accept(server, tools, tool_names)
    print(json.dumps(accept_summary(report), indent=2, sort_keys=True))


def accept_summary(report: Any) -> dict[str, Any]:
    """CLI output for ``judikt pins accept``.

    ``pinned_count`` and ``pending_count`` describe the stored pin state after
    the call, ``accepted_tools`` lists what this call accepted, and
    ``upstream_tool_count`` is the size of the catalog the upstream advertised.
    """

    return {
        "server": report.server,
        "digest": report.digest,
        "status": report.status,
        "accepted_tools": list(report.accepted_tools or []),
        "pinned_count": report.pinned_count,
        "pending_count": report.pending_count,
        "upstream_tool_count": report.tool_count,
    }


def _state_paths(state_key: str) -> tuple[Path, Path]:
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", state_key):
        raise ToolIntegrityError("state key contains unsupported characters")
    directory = state_root() / "upstreams" / state_key
    pin_path = directory / "audit.tool-pins.json"
    if not pin_path.is_file():
        raise ToolIntegrityError(f"no pin state found for {state_key}")
    return directory, pin_path


def _load_entries(
    path: Path,
    *,
    allow_invalid_mac: bool = False,
) -> dict[str, Any]:
    return ToolIntegrityStore(path, ContentGuard()).entries(
        allow_invalid_mac=allow_invalid_mac
    )
