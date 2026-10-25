"""Minimal newline-delimited JSON-RPC client for driving an MCP stdio process."""

from __future__ import annotations

import json
import queue
import subprocess
import threading
from collections.abc import Mapping
from typing import Any


class StdioClient:
    def __init__(self, argv: list[str], env: Mapping[str, str] | None = None) -> None:
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(env) if env is not None else None,
        )
        self.stderr: list[str] = []
        self._next_id = 0
        self._responses: queue.Queue[dict[str, Any]] = queue.Queue()
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in message and ("result" in message or "error" in message):
                self._responses.put(message)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr.append(line)

    def _send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def rpc(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30) -> dict[str, Any]:
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params or {}})
        try:
            return self._responses.get(timeout=timeout)
        except queue.Empty as error:
            raise TimeoutError(f"{method} timed out; stderr: {''.join(self.stderr)[-800:]}") from error

    def initialize(self) -> dict[str, Any]:
        response = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "judikt-explainer", "version": "1"},
            },
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response

    def call(self, name: str, arguments: dict[str, Any] | None = None, timeout: float = 30) -> dict[str, Any]:
        return self.rpc("tools/call", {"name": name, "arguments": arguments or {}}, timeout)

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def result_text(response: dict[str, Any]) -> str:
    result = response.get("result", response)
    parts = []
    for block in result.get("content", []) or []:
        parts.append(block.get("text") if block.get("type") == "text" else f"<{block.get('type')}>")
    return " | ".join(str(part) for part in parts)
