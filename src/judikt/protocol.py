from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import Any

from .models import Tool


class MCPProtocolError(RuntimeError):
    pass


ToolHandler = Callable[[str, dict[str, Any]], Any]
STABLE_PROTOCOL_VERSION = "2025-11-25"
MCP_ERROR_MARKER = "_judikt_mcp_tool_error"
SAFE_ENVIRONMENT_KEYS = (
    "PATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
    "COMSPEC",
)


def serve_stdio(
    name: str,
    tools: list[Tool],
    handler: ToolHandler,
    *,
    accepted_tool_names: set[str] | None = None,
) -> None:
    """Serve the small MCP surface needed by the demo over JSON-RPC stdio."""
    tool_index = accepted_tool_names if accepted_tool_names is not None else {tool.name for tool in tools}
    for raw_line in sys.stdin:
        message: dict[str, Any] = {}
        try:
            message = json.loads(raw_line)
            if "id" not in message:
                continue
            request_id = message["id"]
            method = message.get("method")
            params = message.get("params", {})
            if method == "initialize":
                result = {
                    "protocolVersion": STABLE_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": name, "version": "0.1.0"},
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [tool.as_mcp() for tool in tools]}
            elif method == "tools/call":
                tool_name = params.get("name", "")
                if tool_name not in tool_index:
                    raise MCPProtocolError(f"unknown tool: {tool_name}")
                output = handler(tool_name, params.get("arguments", {}))
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(output, sort_keys=True),
                        }
                    ],
                    "structuredContent": output,
                    "isError": False,
                }
            else:
                raise MCPProtocolError(f"unsupported method: {method}")
            _write({"jsonrpc": "2.0", "id": request_id, "result": result})
        except Exception as exc:  # Keep the MCP server alive for the next request.
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id") if isinstance(message, dict) else None,
                    "error": {"code": -32000, "message": str(exc)},
                }
            )


def _write(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


class StdioMCPClient:
    def __init__(
        self,
        backend: str,
        *,
        command: list[str] | tuple[str, ...] | None = None,
        environment: dict[str, str] | None = None,
        cwd: str | None = None,
        inherit_environment: bool | None = None,
    ) -> None:
        self.backend = backend
        self._lock = threading.Lock()
        self._next_id = 1
        if inherit_environment is None:
            inherit_environment = command is None
        process_environment = (
            os.environ.copy()
            if inherit_environment
            else {key: os.environ[key] for key in SAFE_ENVIRONMENT_KEYS if key in os.environ}
        )
        process_environment.update(environment or {})
        self._process = subprocess.Popen(
            list(command or [sys.executable, "-m", "judikt.cli", "backend", backend]),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=process_environment,
            cwd=cwd,
        )
        self.request(
            "initialize",
            {
                "protocolVersion": STABLE_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "judikt", "version": "0.3.0"},
            },
        )
        self.notify("notifications/initialized", {})

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._process.poll() is not None:
                raise MCPProtocolError(f"MCP backend {self.backend!r} exited unexpectedly")
            request_id = self._next_id
            self._next_id += 1
            self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            assert self._process.stdout is not None
            while True:
                response_line = self._process.stdout.readline()
                if not response_line:
                    error = ""
                    if self._process.stderr is not None:
                        error = self._process.stderr.read()
                    raise MCPProtocolError(f"MCP backend {self.backend!r} stopped: {error}")
                response = json.loads(response_line)
                if response.get("id") != request_id:
                    if "id" in response and "method" in response:
                        self._handle_server_request(response)
                    continue
                if "error" in response:
                    raise MCPProtocolError(response["error"]["message"])
                result = response.get("result")
                if not isinstance(result, dict):
                    raise MCPProtocolError(
                        f"MCP backend {self.backend!r} returned a malformed {method!r} result"
                    )
                return result

    def notify(self, method: str, params: dict[str, Any]) -> None:
        with self._lock:
            self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor = ""
        observed_cursors: set[str] = set()
        for _ in range(100):
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            page = result.get("tools")
            if not isinstance(page, list) or not all(isinstance(tool, dict) for tool in page):
                raise MCPProtocolError(f"MCP backend {self.backend!r} returned an invalid tool catalog")
            tools.extend(page)
            next_cursor = result.get("nextCursor")
            if not next_cursor:
                return tools
            cursor = str(next_cursor)
            if cursor in observed_cursors:
                raise MCPProtocolError(f"MCP backend {self.backend!r} repeated a pagination cursor")
            observed_cursors.add(cursor)
        raise MCPProtocolError(f"MCP backend {self.backend!r} exceeded the tool pagination limit")

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        response = self.request("tools/call", {"name": tool, "arguments": arguments})
        if response.get("isError") is True:
            return {
                MCP_ERROR_MARKER: True,
                "content": response.get("content", []),
                "structuredContent": response.get("structuredContent"),
            }
        if "structuredContent" in response and response["structuredContent"] is not None:
            return response["structuredContent"]
        content = response.get("content")
        if isinstance(content, list):
            return {"content": content}
        raise MCPProtocolError(f"MCP backend {self.backend!r} returned an invalid tool result")

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            if stream is not None:
                stream.close()

    def _send(self, payload: dict[str, Any]) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self._process.stdin.flush()

    def _handle_server_request(self, request: dict[str, Any]) -> None:
        method = request.get("method")
        if method == "roots/list":
            result: dict[str, Any] = {"roots": []}
            self._send({"jsonrpc": "2.0", "id": request["id"], "result": result})
            return
        if method == "ping":
            self._send({"jsonrpc": "2.0", "id": request["id"], "result": {}})
            return
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {"code": -32601, "message": f"unsupported server request: {method}"},
            }
        )


def is_mcp_tool_error(value: Any) -> bool:
    return isinstance(value, dict) and value.get(MCP_ERROR_MARKER) is True
