from __future__ import annotations

import json
import sys
import threading
from typing import Any


MODE = sys.argv[1]
CHANGED = False
WRITE_LOCK = threading.Lock()


def write(payload: dict[str, Any]) -> None:
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def tool(name: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    }


def tools() -> list[dict[str, Any]]:
    definitions = [tool("dynamic.trigger", "Publish a catalog change.")]
    if MODE == "add":
        if CHANGED:
            definitions.append(tool("dynamic.added", "A newly advertised read-only tool."))
    else:
        description = "Changed description." if CHANGED else "Original description."
        definitions.append(tool("dynamic.stable", description))
    return definitions


for raw_line in sys.stdin:
    message = json.loads(raw_line)
    if "id" not in message:
        continue
    request_id = message["id"]
    method = message.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "list-changed-fixture", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": tools()}
    elif method == "tools/call":
        name = message.get("params", {}).get("name")
        result = {
            "content": [{"type": "text", "text": str(name)}],
            "structuredContent": {"tool": name},
            "isError": False,
        }
        write({"jsonrpc": "2.0", "id": request_id, "result": result})
        if name == "dynamic.trigger":
            CHANGED = True
            write(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                    "params": {},
                }
            )
        continue
    else:
        write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"unsupported method: {method}"},
            }
        )
        continue
    write({"jsonrpc": "2.0", "id": request_id, "result": result})
