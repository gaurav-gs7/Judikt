from __future__ import annotations

import asyncio
import json
import math
import os
import threading
from concurrent.futures import TimeoutError as FutureTimeoutError
from collections.abc import Callable
from typing import Any, Coroutine

from .diagnostics import strip_control_characters
from .metrics import Metrics
from .protocol import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_TIMEOUTS,
    MCPProtocolError,
    NotificationHandler,
    RestartHandler,
    UpstreamErrorResponse,
    UpstreamTimeoutError,
    resolve_liveness_timeout,
)
from .upstreams import UpstreamConfigError, validate_remote_url


class _Connection:
    """State for one Streamable HTTP session running on its own event loop."""

    def __init__(self) -> None:
        self.ready = threading.Event()
        self.startup_error: BaseException | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.stop: asyncio.Event | None = None
        self.session: Any | None = None
        self.thread: threading.Thread | None = None


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
        expose_error_messages: bool = False,
        liveness_timeout_seconds: float | None = None,
    ) -> None:
        self.backend = backend
        self.expose_error_messages = bool(expose_error_messages)
        self.url = url
        self._headers = dict(headers or {})
        self._allow_private_network = allow_private_network
        self._timeouts = _resolve_timeouts(timeouts)
        self._liveness_timeout = resolve_liveness_timeout(liveness_timeout_seconds)
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
        self._lifecycle_lock = threading.RLock()
        self._probe_lock = threading.Lock()
        self._probing: _Connection | None = None
        self._closed = threading.Event()
        self._connection = _Connection()
        self.reconnect_count = 0
        validate_remote_url(url, allow_private_network)
        self._connection = self._connect()

    def add_notification_handler(self, method: str, handler: NotificationHandler) -> None:
        with self._handler_lock:
            self._handlers.setdefault(method, []).append(handler)

    def add_restart_handler(self, handler: RestartHandler) -> None:
        with self._handler_lock:
            self._restart_handlers.append(handler)

    def list_tools(self) -> list[dict[str, Any]]:
        self._validate_destination()
        return self._submit(
            lambda session: self._list_tools(session),
            "tools/list",
            self._timeouts["list"],
        )

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._validate_destination()
        return self._submit(
            lambda session: self._call_tool(session, tool, arguments),
            "tools/call",
            self._timeouts["call"],
        )

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._disconnect(self._connection)

    def _connect(self) -> _Connection:
        connection = _Connection()
        connection.thread = threading.Thread(
            target=self._thread_main,
            args=(connection,),
            name=f"judikt-{self.backend}-streamable-http",
            daemon=True,
        )
        connection.thread.start()
        if not connection.ready.wait(self._timeouts["initialize"] + 1.0):
            self._disconnect(connection)
            self._observe_timeout()
            raise UpstreamTimeoutError(
                f"remote MCP upstream {self.backend!r} timed out during 'initialize' "
                f"after {self._timeouts['initialize']:g}s"
            )
        if connection.startup_error is not None:
            self._disconnect(connection)
            raise _protocol_error(
                self.backend,
                "initialize",
                connection.startup_error,
                exposable=self.expose_error_messages,
            )
        return connection

    @staticmethod
    def _disconnect(connection: _Connection) -> None:
        loop = connection.loop
        stop = connection.stop
        if loop is not None and stop is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(stop.set)
            except RuntimeError:
                pass
        thread = connection.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)

    def _thread_main(self, connection: _Connection) -> None:
        try:
            asyncio.run(self._run(connection))
        except BaseException as exc:
            connection.startup_error = exc
            connection.ready.set()

    async def _run(self, connection: _Connection) -> None:
        try:
            import httpx
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
        except ImportError as exc:  # pragma: no cover - optional dependency path
            raise MCPProtocolError(
                "remote upstreams require the optional mcp dependencies"
            ) from exc

        connection.loop = asyncio.get_running_loop()
        connection.stop = asyncio.Event()
        transport = _bounded_transport(httpx, self._max_message_bytes)

        async def reject_redirects_and_large_responses(response: Any) -> None:
            if response.is_redirect:
                raise MCPProtocolError("remote upstream redirects are refused")
            length = response.headers.get("content-length")
            if length is not None and int(length) > self._max_message_bytes:
                raise MCPProtocolError(
                    f"remote MCP upstream {self.backend!r} exceeded the "
                    f"{self._max_message_bytes}-byte HTTP response limit"
                )

        async with httpx.AsyncClient(
            headers=self._headers,
            timeout=_http_timeout(httpx, self._timeouts),
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
                    connection.session = session
                    await asyncio.wait_for(
                        session.initialize(),
                        timeout=self._timeouts["initialize"],
                    )
                    connection.ready.set()
                    await connection.stop.wait()
        connection.session = None

    async def _list_tools(self, session: Any) -> list[dict[str, Any]]:
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
                    f"remote MCP upstream {self.backend!r} repeated a pagination cursor"
                )
            observed.add(cursor)
        raise MCPProtocolError(
            f"remote MCP upstream {self.backend!r} exceeded the tool pagination limit"
        )

    async def _call_tool(
        self,
        session: Any,
        tool: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
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

    def _submit(
        self,
        build: Callable[[Any], Coroutine[Any, Any, Any]],
        method: str,
        timeout: float,
    ) -> Any:
        if self._closed.is_set():
            raise MCPProtocolError(f"remote MCP upstream {self.backend!r} was closed")
        with self._lifecycle_lock:
            connection = self._connection
        if connection.loop is None or connection.session is None:
            self._reconnect(connection)
            with self._lifecycle_lock:
                connection = self._connection
            if connection.loop is None or connection.session is None:
                raise MCPProtocolError(
                    f"remote MCP upstream {self.backend!r} is not connected"
                )
        future = asyncio.run_coroutine_threadsafe(
            build(connection.session), connection.loop
        )
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError:
            future.cancel()
            self._observe_timeout()
            self._start_liveness_probe(connection)
            raise UpstreamTimeoutError(
                f"remote MCP upstream {self.backend!r} timed out during {method!r} "
                f"after {timeout:g}s"
            ) from None
        except BaseException as exc:
            raise _protocol_error(
                self.backend,
                method,
                exc,
                exposable=self.expose_error_messages,
            ) from None

    def _validate_destination(self) -> None:
        try:
            validate_remote_url(self.url, self._allow_private_network)
        except UpstreamConfigError as exc:
            public_reason = (
                f"remote MCP upstream {self.backend!r} request failed "
                "(destination refused)"
            )
            raise MCPProtocolError(
                public_reason,
                diagnostic=f"{public_reason}: {exc}",
            ) from None

    def _start_liveness_probe(self, connection: _Connection) -> None:
        """Ping a timed-out remote session off the request thread.

        There is no process to kill: a session that does not answer ``ping``
        within the liveness deadline is closed and recreated, and restart
        handlers re-verify tool pins.
        """

        with self._probe_lock:
            if self._closed.is_set() or self._probing is connection:
                return
            self._probing = connection
        threading.Thread(
            target=self._liveness_probe,
            args=(connection,),
            name=f"judikt-{self.backend}-liveness",
            daemon=True,
        ).start()

    def _liveness_probe(self, connection: _Connection) -> None:
        try:
            if self._metrics is not None:
                self._metrics.observe_upstream_liveness_probe(self.backend)
            session = connection.session
            loop = connection.loop
            if session is None or loop is None or self._closed.is_set():
                return
            future = asyncio.run_coroutine_threadsafe(session.send_ping(), loop)
            try:
                future.result(timeout=self._liveness_timeout)
                return
            except FutureTimeoutError:
                future.cancel()
            except Exception:
                pass
            if self._metrics is not None:
                self._metrics.observe_upstream_liveness_failure(self.backend)
            self._reconnect(connection)
        finally:
            with self._probe_lock:
                if self._probing is connection:
                    self._probing = None

    def _reconnect(self, failed: _Connection) -> None:
        with self._lifecycle_lock:
            if self._closed.is_set() or self._connection is not failed:
                return
            self._disconnect(failed)
            try:
                self._connection = self._connect()
            except MCPProtocolError:
                # Keep failing closed: requests see "not connected" until a
                # later probe or restart succeeds.
                self._connection = _Connection()
                return
            self.reconnect_count += 1
            if self._metrics is not None:
                self._metrics.observe_upstream_restart(self.backend)
        with self._handler_lock:
            handlers = list(self._restart_handlers)
        for handler in handlers:
            try:
                handler(self)  # type: ignore[arg-type]
            except Exception:
                continue

    def _check_size(self, value: Any, label: str) -> None:
        size = len(json.dumps(value, separators=(",", ":")).encode())
        if size > self._max_message_bytes:
            if self._metrics is not None:
                self._metrics.observe_upstream_protocol_violation(self.backend)
            raise MCPProtocolError(
                f"remote MCP upstream {self.backend!r} {label} exceeded the "
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


def _http_timeout(httpx: Any, timeouts: dict[str, float]) -> Any:
    return httpx.Timeout(
        None,
        connect=timeouts["initialize"],
        write=max(timeouts.values()),
        pool=timeouts["initialize"],
    )


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


def _protocol_error(
    backend: str,
    method: str,
    exc: BaseException,
    *,
    exposable: bool = False,
) -> MCPProtocolError:
    """Map a transport or SDK exception to a fixed public category.

    Exception text from httpx or the MCP SDK can contain URLs (including
    userinfo), response fragments or server-supplied messages, so it is only
    ever used as an operator diagnostic.
    """

    leaf = _leaf_exception(exc)
    label = f"remote MCP upstream {backend!r}"
    detail = _exception_detail(exc)
    if isinstance(leaf, MCPProtocolError):
        if leaf.__class__ is MCPProtocolError and leaf.public_reason.startswith(
            ("remote upstream", "remote MCP upstream")
        ):
            return leaf
        if not isinstance(leaf, UpstreamTimeoutError | UpstreamErrorResponse):
            public_reason = f"{label} request failed (protocol error)"
            return MCPProtocolError(public_reason, diagnostic=f"{public_reason}: {detail}")
        return leaf
    error_data = getattr(leaf, "error", None)
    if error_data is not None and hasattr(error_data, "code") and hasattr(error_data, "message"):
        code = error_data.code if isinstance(error_data.code, int) else None
        message = strip_control_characters(str(error_data.message or ""))[:2000]
        public_reason = (
            f"{label} returned an error (code {code})"
            if code is not None
            else f"{label} returned an error"
        )
        return UpstreamErrorResponse(
            public_reason,
            upstream_code=code,
            upstream_message=message,
            diagnostic=f"{public_reason} during {method!r}; upstream message: {message!r}",
            exposable=exposable,
        )
    category = _transport_category(leaf)
    public_reason = f"{label} request failed ({category})"
    return MCPProtocolError(
        public_reason,
        diagnostic=f"{public_reason} during {method!r}: {detail}",
    )


def _leaf_exception(exc: BaseException) -> BaseException:
    current = exc
    for _ in range(10):
        nested = getattr(current, "exceptions", None)
        if isinstance(current, BaseExceptionGroup) and nested:
            current = nested[0]
            continue
        break
    return current


def _exception_detail(exc: BaseException) -> str:
    parts = []
    current: BaseException | None = exc
    for _ in range(5):
        if current is None:
            break
        if isinstance(current, BaseExceptionGroup):
            current = current.exceptions[0] if current.exceptions else None
            continue
        parts.append(f"{current.__class__.__name__}: {current}")
        current = current.__cause__ or current.__context__
    return " <- ".join(parts)


def _transport_category(exc: BaseException) -> str:
    import ssl

    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(chain) < 10:
        chain.append(current)
        current = current.__cause__ or current.__context__
    names = {item.__class__.__name__ for item in chain}
    if any(isinstance(item, ssl.SSLError) for item in chain) or any(
        "SSL" in name or "TLS" in name or "Certificate" in name for name in names
    ):
        return "TLS error"
    try:
        import httpx
    except ImportError:  # pragma: no cover - optional dependency path
        httpx = None  # type: ignore[assignment]
    if httpx is not None:
        if any(isinstance(item, httpx.TimeoutException) for item in chain):
            return "network timeout"
        if any(isinstance(item, httpx.HTTPStatusError) for item in chain):
            status = next(
                item.response.status_code
                for item in chain
                if isinstance(item, httpx.HTTPStatusError)
            )
            return f"HTTP status {int(status)}"
        if any(isinstance(item, httpx.ConnectError) for item in chain):
            return "connection error"
        if any(isinstance(item, (httpx.RemoteProtocolError, httpx.DecodingError)) for item in chain):
            return "protocol error"
        if any(isinstance(item, httpx.HTTPError) for item in chain):
            return "HTTP error"
    if any(isinstance(item, ConnectionError | OSError) for item in chain):
        return "connection error"
    if any(isinstance(item, ValueError | TypeError) for item in chain):
        return "malformed response"
    return "unexpected error"
