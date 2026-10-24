from __future__ import annotations

import asyncio
import json
import math
import os
import threading
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any, Coroutine

from .metrics import Metrics
from .protocol import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_TIMEOUTS,
    MCPProtocolError,
    NotificationHandler,
    RestartHandler,
    UpstreamTimeoutError,
)
from .upstreams import UpstreamConfigError, validate_remote_url


class StreamableHTTPMCPClient:
    """Synchronous facade over one official MCP Streamable HTTP client session."""

    def __init__(
        self,
        backend: str,
        *,
        url: str,
        headers: dict[str, str] | None = None,
        allow_private_network: bool = False,
        timeouts: dict[str, float] | None = None,
        max_message_bytes: int | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.backend = backend
        self.url = url
        self._headers = dict(headers or {})
        self._allow_private_network = allow_private_network
        self._timeouts = _resolve_timeouts(timeouts)
        self._max_message_bytes = _positive_int(
            max_message_bytes
            if max_message_bytes is not None
            else os.getenv("JUDIKT_UPSTREAM_MAX_MESSAGE_BYTES", DEFAULT_MAX_MESSAGE_BYTES),
            "max_message_bytes",
        )
        self._metrics = metrics
        self._handlers: dict[str, list[NotificationHandler]] = {}
        self._restart_handlers: list[RestartHandler] = []
        self._handler_lock = threading.Lock()
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._startup_error: BaseException | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._session: Any | None = None
        validate_remote_url(url, allow_private_network)
        self._thread = threading.Thread(
            target=self._thread_main,
            name=f"judikt-{backend}-streamable-http",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(self._timeouts["initialize"] + 1.0):
            self.close()
            self._observe_timeout()
            raise UpstreamTimeoutError(
                f"MCP backend {backend!r} timed out during 'initialize' "
                f"after {self._timeouts['initialize']:g}s"
            )
        if self._startup_error is not None:
            self.close()
            raise _protocol_error(backend, "initialize", self._startup_error)

    def add_notification_handler(self, method: str, handler: NotificationHandler) -> None:
        with self._handler_lock:
            self._handlers.setdefault(method, []).append(handler)

    def add_restart_handler(self, handler: RestartHandler) -> None:
        with self._handler_lock:
            self._restart_handlers.append(handler)

    def list_tools(self) -> list[dict[str, Any]]:
        self._validate_destination()
        return self._submit(self._list_tools(), "tools/list", self._timeouts["list"])

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._validate_destination()
        return self._submit(
            self._call_tool(tool, arguments),
            "tools/call",
            self._timeouts["call"],
        )

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        loop = self._loop
        stop = self._stop
        if loop is not None and stop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(stop.set)
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=5.0)

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._run())
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()

    async def _run(self) -> None:
        try:
            import httpx
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
        except ImportError as exc:  # pragma: no cover - optional dependency path
            raise MCPProtocolError(
                "remote upstreams require the optional mcp dependencies"
            ) from exc

        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        transport = _bounded_transport(httpx, self._max_message_bytes)

        async def reject_redirects_and_large_responses(response: Any) -> None:
            if response.is_redirect:
                raise MCPProtocolError("remote upstream redirects are refused")
            length = response.headers.get("content-length")
            if length is not None and int(length) > self._max_message_bytes:
                raise MCPProtocolError(
                    f"MCP backend {self.backend!r} exceeded the "
                    f"{self._max_message_bytes}-byte HTTP response limit"
                )

        async with httpx.AsyncClient(
            headers=self._headers,
            timeout=None,
            follow_redirects=False,
            transport=transport,
            event_hooks={"response": [reject_redirects_and_large_responses]},
        ) as http_client:
            async with streamable_http_client(
                self.url,
                http_client=http_client,
            ) as streams:
                read_stream, write_stream, _ = streams
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=None,
                    message_handler=self._handle_message,
                ) as session:
                    self._session = session
                    await asyncio.wait_for(
                        session.initialize(),
                        timeout=self._timeouts["initialize"],
                    )
                    self._ready.set()
                    await self._stop.wait()
        self._session = None

    async def _list_tools(self) -> list[dict[str, Any]]:
        session = self._require_session()
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        observed: set[str] = set()
        for _ in range(100):
            page = await self._cancellable_request(
                session,
                session.list_tools(cursor=cursor),
            )
            rendered = [
                tool.model_dump(by_alias=True, exclude_none=True, mode="json")
                for tool in page.tools
            ]
            self._check_size(rendered, "tool catalog")
            tools.extend(rendered)
            cursor = page.nextCursor
            if not cursor:
                self._check_size(tools, "tool catalog")
                return tools
            if cursor in observed:
                raise MCPProtocolError(
                    f"MCP backend {self.backend!r} repeated a pagination cursor"
                )
            observed.add(cursor)
        raise MCPProtocolError(
            f"MCP backend {self.backend!r} exceeded the tool pagination limit"
        )

    async def _call_tool(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session()
        response = await self._cancellable_request(
            session,
            session.call_tool(tool, arguments),
        )
        result = response.model_dump(by_alias=True, exclude_none=True, mode="json")
        self._check_size(result, "tool result")
        return result

    async def _cancellable_request(
        self,
        session: Any,
        request: Coroutine[Any, Any, Any],
    ) -> Any:
        request_id = session._request_id
        try:
            return await request
        except asyncio.CancelledError:
            from mcp import types

            notification = types.ClientNotification(
                types.CancelledNotification(
                    params=types.CancelledNotificationParams(
                        requestId=request_id,
                        reason="Judikt upstream deadline exceeded",
                    )
                )
            )
            try:
                await asyncio.shield(session.send_notification(notification))
            except BaseException:
                pass
            raise

    async def _handle_message(self, message: Any) -> None:
        notification = getattr(message, "root", message)
        method = getattr(notification, "method", "")
        if not isinstance(method, str) or not method:
            return
        rendered = notification.model_dump(
            by_alias=True,
            exclude_none=True,
            mode="json",
        )
        with self._handler_lock:
            handlers = list(self._handlers.get(method, ()))
        for handler in handlers:
            threading.Thread(
                target=_run_handler,
                args=(handler, rendered),
                name=f"judikt-{self.backend}-notification",
                daemon=True,
            ).start()

    def _submit(self, request: Coroutine[Any, Any, Any], method: str, timeout: float) -> Any:
        if self._closed.is_set() or self._loop is None:
            request.close()
            raise MCPProtocolError(f"MCP backend {self.backend!r} was closed")
        future = asyncio.run_coroutine_threadsafe(request, self._loop)
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError:
            future.cancel()
            self._observe_timeout()
            raise UpstreamTimeoutError(
                f"MCP backend {self.backend!r} timed out during {method!r} "
                f"after {timeout:g}s"
            ) from None
        except MCPProtocolError:
            raise
        except BaseException as exc:
            raise _protocol_error(self.backend, method, exc) from None

    def _validate_destination(self) -> None:
        try:
            validate_remote_url(self.url, self._allow_private_network)
        except UpstreamConfigError as exc:
            raise MCPProtocolError(str(exc)) from None

    def _require_session(self) -> Any:
        if self._session is None:
            raise MCPProtocolError(f"MCP backend {self.backend!r} is not connected")
        return self._session

    def _check_size(self, value: Any, label: str) -> None:
        size = len(json.dumps(value, separators=(",", ":")).encode())
        if size > self._max_message_bytes:
            if self._metrics is not None:
                self._metrics.observe_upstream_protocol_violation(self.backend)
            raise MCPProtocolError(
                f"MCP backend {self.backend!r} {label} exceeded the "
                f"{self._max_message_bytes}-byte response limit"
            )

    def _observe_timeout(self) -> None:
        if self._metrics is not None:
            self._metrics.observe_upstream_timeout(self.backend)


def _bounded_transport(httpx: Any, limit: int) -> Any:
    class BoundedStream(httpx.AsyncByteStream):
        def __init__(self, stream: Any) -> None:
            self._stream = stream
            self._received = 0

        async def __aiter__(self) -> Any:
            async for chunk in self._stream:
                self._received += len(chunk)
                if self._received > limit:
                    raise MCPProtocolError(
                        f"remote upstream exceeded the {limit}-byte HTTP response limit"
                    )
                yield chunk

        async def aclose(self) -> None:
            await self._stream.aclose()

    class BoundedTransport(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self._transport = httpx.AsyncHTTPTransport()

        async def handle_async_request(self, request: Any) -> Any:
            response = await self._transport.handle_async_request(request)
            response.stream = BoundedStream(response.stream)
            return response

        async def aclose(self) -> None:
            await self._transport.aclose()

    return BoundedTransport()


def _run_handler(handler: NotificationHandler, message: dict[str, Any]) -> None:
    try:
        handler(message)
    except Exception:
        return


def _resolve_timeouts(configured: dict[str, float] | None) -> dict[str, float]:
    result = dict(DEFAULT_TIMEOUTS)
    global_value = os.getenv("JUDIKT_UPSTREAM_TIMEOUT_SECONDS", "").strip()
    if global_value:
        timeout = _positive_float(global_value, "JUDIKT_UPSTREAM_TIMEOUT_SECONDS")
        result = {name: timeout for name in result}
    for name, value in (configured or {}).items():
        if name not in result:
            raise ValueError(f"unknown upstream timeout: {name}")
        result[name] = _positive_float(value, f"upstream timeout {name}")
    return result


def _positive_float(value: Any, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if isinstance(value, bool) or not math.isfinite(result) or result <= 0:
        raise ValueError(f"{name} must be a positive number")
    return result


def _positive_int(value: Any, name: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if isinstance(value, bool) or result <= 0 or result != float(value):
        raise ValueError(f"{name} must be a positive integer")
    return result


def _protocol_error(backend: str, method: str, exc: BaseException) -> MCPProtocolError:
    if isinstance(exc, MCPProtocolError):
        return exc
    return MCPProtocolError(
        f"MCP backend {backend!r} failed during {method!r}: {exc.__class__.__name__}"
    )
