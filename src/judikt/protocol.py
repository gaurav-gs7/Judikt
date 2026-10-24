from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any

from .diagnostics import safe_rule, strip_control_characters
from .metrics import Metrics
from .models import Tool


class MCPProtocolError(RuntimeError):
    """MCP failure with separate agent-visible and operator-only text.

    ``public_reason`` is fixed, Judikt-authored text that may reach an agent.
    ``diagnostic`` is operator-only detail and may contain upstream-controlled
    text such as stderr or an upstream JSON-RPC error message. ``str(exc)``
    always returns only the public reason, so call sites that forget the
    distinction fail safe.
    """

    def __init__(
        self,
        public_reason: str,
        *,
        code: int = -32000,
        diagnostic: str | None = None,
    ) -> None:
        super().__init__(public_reason)
        self.public_reason = public_reason
        self.code = code
        self.diagnostic = diagnostic if diagnostic is not None else public_reason

    def __str__(self) -> str:
        return self.public_reason


class UpstreamTimeoutError(MCPProtocolError):
    pass


class UpstreamErrorResponse(MCPProtocolError):
    """An upstream answered a request with a JSON-RPC error object.

    ``upstream_message`` is untrusted. It is only ever shown to an agent when the
    operator opted in with ``expose_error_messages`` and the text passed content
    inspection and policy redaction.
    """

    def __init__(
        self,
        public_reason: str,
        *,
        upstream_code: int | None,
        upstream_message: str,
        diagnostic: str,
        exposable: bool = False,
    ) -> None:
        super().__init__(public_reason, diagnostic=diagnostic)
        self.upstream_code = upstream_code
        self.upstream_message = upstream_message
        self.exposable = exposable


class GuardedToolError(MCPProtocolError):
    def __init__(
        self,
        rule: str,
        message: str,
        result: dict[str, Any],
        *,
        operational_failure: bool = False,
        diagnostic: str | None = None,
        trusted: bool = True,
    ) -> None:
        super().__init__(message, code=-32042, diagnostic=diagnostic)
        self.rule = rule
        self.result = result
        self.operational_failure = operational_failure
        # False when the refusal was relayed from an external upstream. The
        # pipeline then inspects ``result`` before an agent can see it.
        self.trusted = trusted

    def as_data(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "result": self.result,
            "operational_failure": self.operational_failure,
        }


class UpstreamExitedError(MCPProtocolError):
    pass


class UpstreamRestartLimitError(MCPProtocolError):
    pass


def upstream_label(server: str) -> str:
    return f"MCP upstream {server!r}"


ToolHandler = Callable[[str, dict[str, Any]], Any]
NotificationHandler = Callable[[dict[str, Any]], None]
RestartHandler = Callable[["StdioMCPClient"], None]
STABLE_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = {
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    STABLE_PROTOCOL_VERSION,
}
MCP_ERROR_MARKER = "_judikt_mcp_tool_error"
DEFAULT_TIMEOUTS = {"initialize": 30.0, "list": 30.0, "call": 120.0}
DEFAULT_LIVENESS_TIMEOUT_SECONDS = 5.0
TERMINATION_GRACE_SECONDS = 2.0
DEFAULT_STDERR_BUFFER_BYTES = 65_536
DEFAULT_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
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
    tools_provider: Callable[[], list[Tool]] | None = None,
    accepted_tool_names_provider: Callable[[], set[str]] | None = None,
    subscribe_list_changed: Callable[[Callable[[], None]], None] | None = None,
) -> None:
    """Serve Judikt's MCP stdio surface without mixing diagnostics into stdout."""
    write_lock = threading.Lock()

    def write(payload: dict[str, Any]) -> None:
        with write_lock:
            sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
            sys.stdout.flush()

    def current_tools() -> list[Tool]:
        return tools_provider() if tools_provider is not None else tools

    def current_tool_names() -> set[str]:
        if accepted_tool_names_provider is not None:
            return accepted_tool_names_provider()
        if accepted_tool_names is not None:
            return accepted_tool_names
        return {tool.name for tool in current_tools()}

    if subscribe_list_changed is not None:
        subscribe_list_changed(
            lambda: write(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                    "params": {},
                }
            )
        )
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
                requested_version = str(params.get("protocolVersion", ""))
                result = {
                    "protocolVersion": (
                        requested_version
                        if requested_version in SUPPORTED_PROTOCOL_VERSIONS
                        else STABLE_PROTOCOL_VERSION
                    ),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": name, "version": "0.1.0"},
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [tool.as_mcp() for tool in current_tools()]}
            elif method == "tools/call":
                tool_name = params.get("name", "")
                if tool_name not in current_tool_names():
                    raise MCPProtocolError(f"unknown tool: {tool_name}", code=-32602)
                output = handler(tool_name, params.get("arguments", {}))
                result = output if _is_mcp_result(output) else _legacy_tool_result(output)
            else:
                raise MCPProtocolError(f"unsupported method: {method}")
            write({"jsonrpc": "2.0", "id": request_id, "result": result})
        except Exception as exc:  # Keep the MCP server alive for the next request.
            error = {
                "code": exc.code if isinstance(exc, MCPProtocolError) else -32000,
                "message": str(exc),
            }
            if isinstance(exc, GuardedToolError):
                error["data"] = exc.as_data()
            write(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id") if isinstance(message, dict) else None,
                    "error": error,
                }
            )


def _is_mcp_result(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("content"), list)
        and isinstance(value.get("isError"), bool)
    )


def _legacy_tool_result(output: Any) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(output, sort_keys=True)}],
        "structuredContent": output,
        "isError": False,
    }


@dataclass(frozen=True)
class _PendingRequest:
    generation: int
    future: Future[dict[str, Any]]


class _DiagnosticRing:
    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self._lines: deque[str] = deque()
        self._size = 0
        self._lock = threading.Lock()

    def append_bytes(self, value: bytes) -> None:
        text = value.decode("utf-8", errors="replace")
        for line in text.splitlines() or [text]:
            self.append(line)

    def append(self, line: str) -> None:
        encoded_size = len(line.encode("utf-8", errors="replace"))
        with self._lock:
            self._lines.append(line)
            self._size += encoded_size
            while self._lines and self._size > self.max_bytes:
                removed = self._lines.popleft()
                self._size -= len(removed.encode("utf-8", errors="replace"))

    def tail(self, count: int = 20) -> list[str]:
        with self._lock:
            lines = list(self._lines)[-count:]
        return [_safe_diagnostic_line(line) for line in lines]


class StdioMCPClient:
    def __init__(
        self,
        backend: str,
        *,
        command: list[str] | tuple[str, ...] | None = None,
        environment: dict[str, str] | None = None,
        cwd: str | None = None,
        inherit_environment: bool | None = None,
        timeouts: dict[str, float] | None = None,
        stderr_buffer_bytes: int | None = None,
        max_message_bytes: int | None = None,
        restart_limit: int = 5,
        restart_window_seconds: float = 300.0,
        restart_backoff_seconds: float = 1.0,
        metrics: Metrics | None = None,
        expose_error_messages: bool = False,
        liveness_timeout_seconds: float | None = None,
    ) -> None:
        self.backend = backend
        self._liveness_timeout = resolve_liveness_timeout(liveness_timeout_seconds)
        self._probe_lock = threading.Lock()
        self._probing_generation: int | None = None
        self._probe_threads: list[threading.Thread] = []
        # Built-in Judikt backends (no explicit command) author their own error
        # text. Every other upstream is untrusted: its error text is diagnostic
        # only unless the operator opts in to inspected exposure.
        self._trusted_error_text = command is None
        self.expose_error_messages = bool(expose_error_messages)
        self._command = tuple(command or [sys.executable, "-m", "judikt.cli", "backend", backend])
        self._cwd = cwd
        self._write_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()
        self._pending_lock = threading.Lock()
        self._handler_lock = threading.Lock()
        self._next_id = 1
        self._pending: dict[int, _PendingRequest] = {}
        self._notification_handlers: dict[str, list[NotificationHandler]] = {}
        self._restart_handlers: list[RestartHandler] = []
        self._closed = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._generation = 0
        self._needs_restart = False
        self._permanent_failure: UpstreamRestartLimitError | None = None
        self._restart_history: deque[float] = deque()
        self._restart_count = 0
        self._non_json_line_count = 0
        self._protocol_violation_count = 0
        self._restart_limit = _positive_int(restart_limit, "restart_limit")
        self._restart_window_seconds = _positive_float(
            restart_window_seconds,
            "restart_window_seconds",
        )
        self._restart_backoff_seconds = _non_negative_float(
            restart_backoff_seconds,
            "restart_backoff_seconds",
        )
        self._metrics = metrics
        self._timeouts = _resolve_timeouts(timeouts)
        self._max_message_bytes = (
            _positive_int(max_message_bytes, "max_message_bytes")
            if max_message_bytes is not None
            else _positive_int_env(
                "JUDIKT_UPSTREAM_MAX_MESSAGE_BYTES",
                DEFAULT_MAX_MESSAGE_BYTES,
            )
        )
        self._stderr = _DiagnosticRing(
            _positive_int(stderr_buffer_bytes, "stderr_buffer_bytes")
            if stderr_buffer_bytes is not None
            else _positive_int_env(
                "JUDIKT_UPSTREAM_STDERR_BUFFER_BYTES",
                DEFAULT_STDERR_BUFFER_BYTES,
            )
        )
        if inherit_environment is None:
            inherit_environment = command is None
        self._process_environment = (
            os.environ.copy()
            if inherit_environment
            else {key: os.environ[key] for key in SAFE_ENVIRONMENT_KEYS if key in os.environ}
        )
        self._process_environment.update(environment or {})
        try:
            with self._lifecycle_lock:
                self._spawn_locked()
                self._initialize_current()
        except BaseException:
            self.close()
            raise

    @property
    def restart_count(self) -> int:
        return self._restart_count

    @property
    def non_json_line_count(self) -> int:
        return self._non_json_line_count

    @property
    def protocol_violation_count(self) -> int:
        return self._protocol_violation_count

    @property
    def stderr_tail(self) -> list[str]:
        return self._stderr.tail()

    def add_notification_handler(self, method: str, handler: NotificationHandler) -> None:
        with self._handler_lock:
            self._notification_handlers.setdefault(method, []).append(handler)

    def add_restart_handler(self, handler: RestartHandler) -> None:
        with self._handler_lock:
            self._restart_handlers.append(handler)

    def request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        self._ensure_process()
        return self._request_current(method, params, timeout=timeout)

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._ensure_process()
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor = ""
        observed_cursors: set[str] = set()
        for _ in range(100):
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            page = result.get("tools")
            if not isinstance(page, list) or not all(isinstance(tool, dict) for tool in page):
                raise MCPProtocolError(
                    f"{upstream_label(self.backend)} returned an invalid tool catalog"
                )
            tools.extend(page)
            next_cursor = result.get("nextCursor")
            if not next_cursor:
                return tools
            cursor = str(next_cursor)
            if cursor in observed_cursors:
                raise MCPProtocolError(
                    f"{upstream_label(self.backend)} repeated a pagination cursor"
                )
            observed_cursors.add(cursor)
        raise MCPProtocolError(
            f"{upstream_label(self.backend)} exceeded the tool pagination limit"
        )

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        response = self.request("tools/call", {"name": tool, "arguments": arguments})
        content = response.get("content")
        if not isinstance(content, list):
            raise MCPProtocolError(
                f"{upstream_label(self.backend)} returned a malformed 'tools/call' result"
            )
        result = {"content": content, "isError": response.get("isError") is True}
        if "structuredContent" in response:
            result["structuredContent"] = response["structuredContent"]
        if "_meta" in response:
            result["_meta"] = response["_meta"]
        return result

    def close(self) -> None:
        if self._closed.is_set():
            return
        started = time.monotonic()
        self._closed.set()
        self._fail_pending(None, MCPProtocolError(f"{upstream_label(self.backend)} was closed"))
        with self._lifecycle_lock:
            process = self._process
            self._process = None
        if process is not None:
            _terminate_process(process, terminate_timeout=2.0, kill_timeout=2.0)
            _close_process_streams(process)
        deadline = started + 5.0
        with self._probe_lock:
            probe_threads = list(self._probe_threads)
        for thread in (self._reader_thread, self._stderr_thread, *probe_threads):
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def _send(self, payload: dict[str, Any]) -> None:
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
        with self._write_lock:
            process = self._process
            if process is None or process.poll() is not None or process.stdin is None:
                raise self._exit_error("is not running")
            try:
                process.stdin.write(encoded)
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                failure = self._exit_error(f"could not accept a request: {exc.__class__.__name__}")
                self._mark_process_failed(self._generation, failure)
                raise failure from None

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

    def _spawn_locked(self) -> None:
        if self._closed.is_set():
            raise MCPProtocolError(f"{upstream_label(self.backend)} was closed")
        self._generation += 1
        generation = self._generation
        process = subprocess.Popen(
            list(self._command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=self._process_environment,
            cwd=self._cwd,
        )
        self._process = process
        self._needs_restart = False
        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            args=(process, generation),
            name=f"judikt-{self.backend}-stdout-{generation}",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._stderr_loop,
            args=(process,),
            name=f"judikt-{self.backend}-stderr-{generation}",
            daemon=True,
        )
        self._reader_thread.start()
        self._stderr_thread.start()

    def _initialize_current(self) -> None:
        self._request_current(
            "initialize",
            {
                "protocolVersion": STABLE_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "judikt", "version": "0.3.0"},
            },
            timeout=self._timeouts["initialize"],
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def _request_current(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
        probe: bool = False,
    ) -> dict[str, Any]:
        configured_timeout = self._timeout_for(method) if timeout is None else timeout
        deadline = _positive_float(configured_timeout, f"timeout for {method}")
        with self._pending_lock:
            request_id = self._next_id
            self._next_id += 1
            future: Future[dict[str, Any]] = Future()
            generation = self._generation
            self._pending[request_id] = _PendingRequest(generation, future)
        try:
            self._send(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            )
        except BaseException:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise
        try:
            response = future.result(timeout=deadline)
        except FutureTimeoutError:
            with self._pending_lock:
                pending = self._pending.pop(request_id, None)
            if pending is None and future.done():
                response = future.result()
            else:
                try:
                    self._send(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/cancelled",
                            "params": {"requestId": request_id, "reason": "timeout"},
                        }
                    )
                except MCPProtocolError:
                    pass
                if not probe:
                    if self._metrics is not None:
                        self._metrics.observe_upstream_timeout(self.backend)
                    if method != "initialize":
                        self._start_liveness_probe(generation)
                public_reason = (
                    f"{upstream_label(self.backend)} timed out during {method!r} "
                    f"after {deadline:g}s"
                )
                raise UpstreamTimeoutError(
                    public_reason,
                    diagnostic=f"{public_reason}{self._diagnostic_suffix()}",
                ) from None
        if "error" in response:
            raise self._error_response(response.get("error"), method)
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError(
                f"{upstream_label(self.backend)} returned a malformed {method!r} result"
            )
        return result

    def _error_response(self, error: Any, method: str) -> MCPProtocolError:
        label = upstream_label(self.backend)
        message = error.get("message") if isinstance(error, dict) else None
        upstream_message = _bounded_upstream_text(message)
        data = error.get("data") if isinstance(error, dict) else None
        raw_code = error.get("code") if isinstance(error, dict) else None
        code = (
            raw_code
            if isinstance(raw_code, int) and not isinstance(raw_code, bool)
            and -(2**31) <= raw_code < 2**31
            else None
        )
        if (
            code == -32042
            and isinstance(data, dict)
            and isinstance(data.get("rule"), str)
            and isinstance(data.get("result"), dict)
        ):
            if self._trusted_error_text:
                return GuardedToolError(
                    data["rule"],
                    str(message or "guarded upstream operation was refused"),
                    data["result"],
                    operational_failure=data.get("operational_failure") is True,
                )
            rule = safe_rule(data["rule"])
            public_reason = f"{label} refused the operation (rule: {rule})"
            return GuardedToolError(
                rule,
                public_reason,
                data["result"],
                operational_failure=data.get("operational_failure") is True,
                diagnostic=(
                    f"{public_reason} during {method!r}; upstream message: "
                    f"{upstream_message!r}"
                ),
                trusted=False,
            )
        if self._trusted_error_text:
            return MCPProtocolError(str(message or "upstream returned a JSON-RPC error"))
        public_reason = (
            f"{label} returned an error (code {code})"
            if code is not None
            else f"{label} returned an error"
        )
        return UpstreamErrorResponse(
            public_reason,
            upstream_code=code,
            upstream_message=upstream_message,
            diagnostic=(
                f"{public_reason} during {method!r}; upstream message: "
                f"{upstream_message!r}{self._diagnostic_suffix()}"
            ),
            exposable=self.expose_error_messages,
        )

    def _start_liveness_probe(self, generation: int) -> None:
        """Probe a timed-out upstream off the request thread.

        A slow but healthy upstream answers ``ping`` and keeps running. One
        that does not answer within the liveness deadline is hung: it is
        terminated (SIGTERM, then SIGKILL after a grace period) and the next
        request restarts it through the normal backoff and restart budget,
        which re-verifies tool pins.
        """

        with self._probe_lock:
            if self._closed.is_set() or self._probing_generation == generation:
                return
            self._probing_generation = generation
            thread = threading.Thread(
                target=self._liveness_probe,
                args=(generation,),
                name=f"judikt-{self.backend}-liveness-{generation}",
                daemon=True,
            )
            self._probe_threads = [
                existing for existing in self._probe_threads if existing.is_alive()
            ]
            self._probe_threads.append(thread)
        thread.start()

    def _liveness_probe(self, generation: int) -> None:
        try:
            if self._closed.is_set() or generation != self._generation:
                return
            if self._metrics is not None:
                self._metrics.observe_upstream_liveness_probe(self.backend)
            try:
                self._request_current(
                    "ping",
                    {},
                    timeout=self._liveness_timeout,
                    probe=True,
                )
                return
            except UpstreamTimeoutError:
                pass
            except MCPProtocolError:
                # An error response is still a response; an exit is handled by
                # the reader thread.
                return
            if self._closed.is_set() or generation != self._generation:
                return
            if self._metrics is not None:
                self._metrics.observe_upstream_liveness_failure(self.backend)
            self._stderr.append(
                f"[judikt] liveness ping timed out after {self._liveness_timeout:g}s; "
                "terminating the upstream"
            )
            public_reason = (
                f"{upstream_label(self.backend)} stopped responding and was terminated"
            )
            failure = UpstreamExitedError(
                public_reason,
                diagnostic=f"{public_reason}{self._diagnostic_suffix()}",
            )
            with self._lifecycle_lock:
                process = self._process if generation == self._generation else None
            self._mark_process_failed(generation, failure, terminate=True)
            if process is not None:
                _terminate_process(
                    process,
                    terminate_timeout=TERMINATION_GRACE_SECONDS,
                    kill_timeout=TERMINATION_GRACE_SECONDS,
                )
        finally:
            with self._probe_lock:
                if self._probing_generation == generation:
                    self._probing_generation = None

    def _ensure_process(self) -> None:
        with self._lifecycle_lock:
            if self._closed.is_set():
                raise MCPProtocolError(f"{upstream_label(self.backend)} was closed")
            if self._permanent_failure is not None:
                raise self._permanent_failure
            process = self._process
            if process is not None and process.poll() is None and not self._needs_restart:
                return
            now = time.monotonic()
            while self._restart_history and now - self._restart_history[0] > self._restart_window_seconds:
                self._restart_history.popleft()
            if len(self._restart_history) >= self._restart_limit:
                public_reason = (
                    f"{upstream_label(self.backend)} exhausted its restart budget "
                    f"({self._restart_limit} restarts in {self._restart_window_seconds:g}s)"
                )
                self._permanent_failure = UpstreamRestartLimitError(
                    public_reason,
                    diagnostic=f"{public_reason}{self._diagnostic_suffix()}",
                )
                raise self._permanent_failure
            delay = min(
                self._restart_backoff_seconds * (2 ** len(self._restart_history)),
                30.0,
            )
            if delay and self._closed.wait(delay):
                raise MCPProtocolError(f"{upstream_label(self.backend)} was closed")
            if process is not None:
                previous_threads = (self._reader_thread, self._stderr_thread)
                _terminate_process(process, terminate_timeout=0.2, kill_timeout=0.2)
                _close_process_streams(process)
                for thread in previous_threads:
                    if thread is not None and thread is not threading.current_thread():
                        thread.join(timeout=0.2)
            self._restart_history.append(time.monotonic())
            self._restart_count += 1
            if self._metrics is not None:
                self._metrics.observe_upstream_restart(self.backend)
            self._spawn_locked()
            try:
                self._initialize_current()
                with self._handler_lock:
                    handlers = list(self._restart_handlers)
                for handler in handlers:
                    handler(self)
            except BaseException as exc:
                self._mark_process_failed(self._generation, exc, terminate=True)
                raise

    def _timeout_for(self, method: str) -> float:
        if method == "initialize":
            return self._timeouts["initialize"]
        if method == "tools/list":
            return self._timeouts["list"]
        if method == "tools/call":
            return self._timeouts["call"]
        return self._timeouts["list"]

    def _reader_loop(self, process: subprocess.Popen[bytes], generation: int) -> None:
        assert process.stdout is not None
        while not self._closed.is_set():
            try:
                line = process.stdout.readline(self._max_message_bytes + 1)
            except (OSError, ValueError):
                line = b""
            if not line:
                if not self._closed.is_set() and generation == self._generation:
                    stderr_thread = self._stderr_thread
                    if stderr_thread is not None and stderr_thread is not threading.current_thread():
                        stderr_thread.join(timeout=0.1)
                    self._mark_process_failed(
                        generation,
                        self._exit_error("exited unexpectedly"),
                    )
                return
            if len(line) > self._max_message_bytes:
                self._record_protocol_violation(
                    "stdout message exceeded max_message_bytes"
                )
                failure = MCPProtocolError(
                    f"{upstream_label(self.backend)} exceeded the "
                    f"{self._max_message_bytes}-byte stdout message limit"
                )
                self._mark_process_failed(generation, failure, terminate=True)
                return
            try:
                message = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._non_json_line_count += 1
                digest = hashlib.sha256(line).hexdigest()
                self._stderr.append(
                    f"[judikt] skipped non-JSON stdout line sha256={digest}"
                )
                self._record_protocol_violation("non-JSON stdout line")
                continue
            if not isinstance(message, dict):
                self._non_json_line_count += 1
                self._stderr.append("[judikt] skipped non-object JSON stdout message")
                self._record_protocol_violation("non-object JSON stdout message")
                continue
            if "id" in message and "method" in message:
                try:
                    self._handle_server_request(message)
                except MCPProtocolError as exc:
                    self._stderr.append(
                        f"[judikt] server-request response failed: {exc.diagnostic}"
                    )
                continue
            if "id" in message:
                with self._pending_lock:
                    pending = self._pending.pop(message["id"], None)
                if pending is not None and pending.generation == generation:
                    pending.future.set_result(message)
                continue
            method = message.get("method")
            if isinstance(method, str):
                self._dispatch_notification(method, message)

    def _stderr_loop(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stderr is not None
        while not self._closed.is_set():
            try:
                chunk = process.stderr.readline(4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            self._stderr.append_bytes(chunk)

    def _dispatch_notification(self, method: str, message: dict[str, Any]) -> None:
        with self._handler_lock:
            handlers = list(self._notification_handlers.get(method, []))
        for handler in handlers:
            thread = threading.Thread(
                target=self._run_notification_handler,
                args=(handler, message),
                name=f"judikt-{self.backend}-notification",
                daemon=True,
            )
            thread.start()

    def _run_notification_handler(
        self,
        handler: NotificationHandler,
        message: dict[str, Any],
    ) -> None:
        try:
            handler(message)
        except Exception as exc:
            self._stderr.append(
                f"[judikt] notification handler failed: {exc.__class__.__name__}"
            )

    def _mark_process_failed(
        self,
        generation: int,
        failure: BaseException,
        *,
        terminate: bool = False,
    ) -> None:
        if generation != self._generation or self._closed.is_set():
            return
        # Wake request threads before taking the lifecycle lock. Restart and
        # initialisation hold that lock while waiting for their own response.
        self._fail_pending(generation, failure)
        process: subprocess.Popen[bytes] | None = None
        with self._lifecycle_lock:
            if generation != self._generation or self._closed.is_set():
                return
            self._needs_restart = True
            process = self._process
        if terminate and process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

    def _fail_pending(self, generation: int | None, failure: BaseException) -> None:
        with self._pending_lock:
            selected = [
                (request_id, pending)
                for request_id, pending in self._pending.items()
                if generation is None or pending.generation == generation
            ]
            for request_id, _ in selected:
                self._pending.pop(request_id, None)
        for _, pending in selected:
            if not pending.future.done():
                pending.future.set_exception(failure)

    def _record_protocol_violation(self, marker: str) -> None:
        self._protocol_violation_count += 1
        if self._metrics is not None:
            self._metrics.observe_upstream_protocol_violation(self.backend)
        self._stderr.append(f"[judikt] protocol violation: {marker}")

    def _exit_error(self, reason: str) -> UpstreamExitedError:
        public_reason = f"{upstream_label(self.backend)} {reason}"
        return UpstreamExitedError(
            public_reason,
            diagnostic=f"{public_reason}{self._diagnostic_suffix()}",
        )

    def _diagnostic_suffix(self) -> str:
        lines = [line for line in self._stderr.tail() if line]
        return f"; recent stderr: {' | '.join(lines)}" if lines else ""


def resolve_liveness_timeout(configured: float | None = None) -> float:
    if configured is not None:
        return _positive_float(configured, "liveness_timeout_seconds")
    raw = os.getenv("JUDIKT_UPSTREAM_LIVENESS_TIMEOUT_SECONDS", "").strip()
    if raw:
        return _positive_float(raw, "JUDIKT_UPSTREAM_LIVENESS_TIMEOUT_SECONDS")
    return DEFAULT_LIVENESS_TIMEOUT_SECONDS


def _resolve_timeouts(configured: dict[str, float] | None) -> dict[str, float]:
    resolved = dict(DEFAULT_TIMEOUTS)
    global_value = os.getenv("JUDIKT_UPSTREAM_TIMEOUT_SECONDS", "").strip()
    if global_value:
        timeout = _positive_float(global_value, "JUDIKT_UPSTREAM_TIMEOUT_SECONDS")
        resolved = {name: timeout for name in resolved}
    for name, value in (configured or {}).items():
        if name not in resolved:
            raise ValueError(f"unknown upstream timeout: {name}")
        resolved[name] = _positive_float(value, f"upstream timeout {name}")
    return resolved


def _positive_float(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{name} must be a positive number")
    return parsed


def _non_negative_float(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a non-negative number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a non-negative number") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{name} must be a non-negative number")
    return parsed


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if parsed <= 0 or parsed != float(value):
        raise ValueError(f"{name} must be a positive integer")
    return parsed


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    return _positive_int(raw, name) if raw else default


def _bounded_upstream_text(value: Any, limit: int = 2000) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return strip_control_characters(text)[:limit]


def _safe_diagnostic_line(line: str) -> str:
    cleaned = "".join(
        character
        for character in line
        if character == "\t" or (ord(character) >= 32 and ord(character) != 127)
    )
    return cleaned[:200]


def _terminate_process(
    process: subprocess.Popen[bytes],
    *,
    terminate_timeout: float,
    kill_timeout: float,
) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=terminate_timeout)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=kill_timeout)
            except subprocess.TimeoutExpired:
                pass


def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def is_mcp_tool_error(value: Any) -> bool:
    return isinstance(value, dict) and (
        value.get("isError") is True or value.get(MCP_ERROR_MARKER) is True
    )
