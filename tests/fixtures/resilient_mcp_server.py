from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any


MODE = sys.argv[1]
STATE_PATH = Path(os.environ["FIXTURE_STATE_PATH"]) if os.getenv("FIXTURE_STATE_PATH") else None
CANCEL_LOG = Path(os.environ["FIXTURE_CANCEL_LOG"]) if os.getenv("FIXTURE_CANCEL_LOG") else None
LIST_LOG = Path(os.environ["FIXTURE_LIST_LOG"]) if os.getenv("FIXTURE_LIST_LOG") else None
WRITE_LOCK = threading.Lock()


def increment_start_count() -> int:
    if STATE_PATH is None:
        return 1
    try:
        current = int(STATE_PATH.read_text())
    except (OSError, ValueError):
        current = 0
    current += 1
    STATE_PATH.write_text(str(current))
    return current


START_COUNT = increment_start_count()


def write(payload: dict[str, Any]) -> None:
    if MODE == "stderr-flood":
        sys.stderr.write("x" * (1024 * 1024) + "\n")
        sys.stderr.flush()
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def result(request_id: Any, value: dict[str, Any]) -> None:
    write({"jsonrpc": "2.0", "id": request_id, "result": value})


def tool_definition() -> dict[str, Any]:
    return {
        "name": "resilient.echo",
        "description": "Return an operator-provided value for transport tests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {"type": "string"},
                "delay": {"type": "number"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    }


def tool_result(arguments: dict[str, Any]) -> dict[str, Any]:
    payload = {"value": arguments.get("value", "ok"), "start_count": START_COUNT}
    return {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "structuredContent": payload,
        "isError": False,
    }


def delayed_result(request_id: Any, arguments: dict[str, Any]) -> None:
    time.sleep(float(arguments.get("delay", 0)))
    result(request_id, tool_result(arguments))


if MODE == "non-json-banner":
    sys.stdout.write("resilient fixture starting\n")
    sys.stdout.flush()
if MODE == "ignore-term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


for raw_line in sys.stdin:
    message = json.loads(raw_line)
    method = message.get("method")
    request_id = message.get("id")
    if method == "notifications/cancelled":
        if CANCEL_LOG is not None:
            CANCEL_LOG.write_text(json.dumps(message))
        continue
    if request_id is None:
        continue
    if method == "initialize":
        if MODE == "hang-initialize":
            continue
        result(
            request_id,
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "resilient-fixture", "version": "1.0.0"},
            },
        )
    elif method == "tools/list":
        if LIST_LOG is not None:
            with LIST_LOG.open("a") as stream:
                stream.write(f"{START_COUNT}\n")
        if MODE == "notification":
            write(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                    "params": {"start_count": START_COUNT},
                }
            )
        result(request_id, {"tools": [tool_definition()]})
    elif method == "tools/call":
        arguments = message.get("params", {}).get("arguments", {})
        if MODE == "hang-call":
            continue
        if MODE in {"crash-once", "oversized-once"} and START_COUNT == 1:
            if MODE == "crash-once":
                os._exit(7)
            sys.stdout.buffer.write(b"z" * (1024 * 1024) + b"\n")
            sys.stdout.buffer.flush()
            continue
        if MODE == "restart-loop":
            os._exit(9)
        if MODE == "exit-stderr":
            sys.stderr.write("failure\x1b\x00" + "x" * 300 + "\n")
            sys.stderr.flush()
            os._exit(10)
        if MODE == "concurrent":
            threading.Thread(
                target=delayed_result,
                args=(request_id, arguments),
                daemon=True,
            ).start()
            continue
        result(request_id, tool_result(arguments))
    else:
        write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"unsupported method: {method}"},
            }
        )
