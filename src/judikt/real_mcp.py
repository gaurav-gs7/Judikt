from __future__ import annotations

import argparse
import asyncio
import dataclasses
import os
import sys
import threading
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority
from .auth import AuthError, Authenticator
from .catalog import ToolCatalog, gateway_result
from .ops_runtime import JudiktOpsRuntime
from .request_context import (
    bind_authenticated_subject,
    authenticated_subject,
    can_execute_control_plane_tool,
    is_control_plane_admin,
    reset_authenticated_subject,
)
from .slack_approval import SlackApprovalError


def build_runtime(
    policy_path: Path,
    audit_path: Path,
    approval_authority: ApprovalAuthority | None = None,
    *,
    remote_mode: bool = False,
) -> JudiktOpsRuntime:
    return JudiktOpsRuntime(
        policy_path,
        audit_path,
        include_demo_servers=_enabled("JUDIKT_DEMO_MODE"),
        circuit_failure_threshold=int(os.getenv("JUDIKT_CIRCUIT_FAILURE_THRESHOLD", "3")),
        circuit_cooldown_seconds=int(os.getenv("JUDIKT_CIRCUIT_COOLDOWN_SECONDS", "300")),
        approval_authority=approval_authority,
        remote_mode=remote_mode,
    )


def serve_real_mcp(args: argparse.Namespace) -> None:
    try:
        from mcp.server.fastmcp import FastMCP
        from starlette.requests import Request
        from starlette.responses import JSONResponse, PlainTextResponse
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on optional profile
        raise RuntimeError(
            "The real MCP server requires the optional MCP dependencies. "
            "Install them with: python3 -m pip install -e '.[mcp]'"
        ) from exc

    authenticator = Authenticator.from_env()
    remote_bind = args.host not in {"127.0.0.1", "localhost", "::1"}
    allow_unauthenticated_remote = os.getenv(
        "JUDIKT_ALLOW_UNAUTHENTICATED_REMOTE", ""
    ).lower() in {"1", "true", "yes"}
    if (
        remote_bind
        and (authenticator.config.jwt_hs256_secret or authenticator.config.jwt_jwks_url)
        and "JUDIKT_RESOURCE_URI" not in os.environ
    ):
        raise AuthError("remote JWT mode requires an explicit JUDIKT_RESOURCE_URI")
    if "JUDIKT_RESOURCE_URI" not in os.environ:
        advertised_host = args.host if args.host not in {"0.0.0.0", "::"} else "127.0.0.1"
        authenticator.config = dataclasses.replace(
            authenticator.config,
            resource_uri=f"http://{advertised_host}:{args.port}{args.mcp_path}",
        )
    authenticator.config.validate_for_remote_server(
        require_auth=remote_bind and not allow_unauthenticated_remote
    )
    _warn_for_static_admin(authenticator.config)
    approval_authority = ApprovalAuthority(require_configured=remote_bind)
    runtime = build_runtime(
        args.policy,
        args.audit_db,
        approval_authority,
        remote_mode=remote_bind,
    )
    mcp = FastMCP(
        "Judikt Production Ops",
        instructions=(
            "Use these tools for guarded production operations. Destructive actions "
            "require signed approval tokens. Secrets are redacted and all calls are audited."
        ),
        host=args.host,
        port=args.port,
        streamable_http_path=args.mcp_path,
        json_response=True,
        stateless_http=False,
    )

    register_tools(mcp, runtime)
    register_native_tools(mcp, runtime, ToolCatalog(runtime))
    app = mcp.streamable_http_app()

    app.add_middleware(
        _AuthMiddleware,
        authenticator=authenticator,
        exempt_paths={
            "/healthz",
            "/.well-known/oauth-protected-resource",
            "/integrations/slack/actions",
        },
    )

    async def health(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "server": "judikt",
                "mcp_path": args.mcp_path,
                "auth": authenticator.config.mode,
            }
        )

    async def metrics(_: Request) -> PlainTextResponse:
        return PlainTextResponse(runtime.render_metrics(), media_type="text/plain; version=0.0.4")

    async def protected_resource(_: Request) -> JSONResponse:
        return JSONResponse(authenticator.config.protected_resource_metadata())

    async def slack_actions(request: Request) -> JSONResponse:
        body = (await request.body()).decode()
        headers = {key.lower(): value for key, value in request.headers.items()}
        try:
            response = runtime.slack_approvals.handle_action(headers, body)
        except SlackApprovalError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse(response)

    app.add_route("/healthz", health, methods=["GET"])
    app.add_route("/metrics", metrics, methods=["GET"])
    app.add_route("/.well-known/oauth-protected-resource", protected_resource, methods=["GET"])
    app.add_route("/integrations/slack/actions", slack_actions, methods=["POST"])

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


def _warn_for_static_admin(config: Any) -> None:
    if config.bearer_token and config.bearer_role == "admin":
        print(
            "WARNING: JUDIKT_HTTP_BEARER_ROLE=admin grants full control-plane access "
            "to the shared static bearer token",
            file=sys.stderr,
            flush=True,
        )


class _AuthMiddleware:
    def __init__(self, app: Any, authenticator: Authenticator, exempt_paths: set[str]) -> None:
        self.app = app
        self.authenticator = authenticator
        self.exempt_paths = exempt_paths

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") in self.exempt_paths:
            await self.app(scope, receive, send)
            return
        headers = {key.decode().lower(): value.decode() for key, value in scope.get("headers", [])}
        origin = headers.get("origin")
        if origin is not None and not self.authenticator.config.origin_allowed(origin):
            from starlette.responses import JSONResponse

            response = JSONResponse({"error": "invalid_origin"}, status_code=403)
            await response(scope, receive, send)
            return
        try:
            auth_result = self.authenticator.authenticate(headers.get("authorization", ""))
        except AuthError:
            from starlette.responses import JSONResponse

            metadata_url = self.authenticator.config.protected_resource_metadata_url()
            response = JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={
                    "WWW-Authenticate": self.authenticator.config.bearer_challenge(metadata_url),
                },
            )
            await response(scope, receive, send)
            return
        scope["judikt.auth"] = {"subject": auth_result.subject, "claims": auth_result.claims}
        static_bearer = auth_result.claims.get("auth_type") == "static_bearer"
        # A shared static bearer token is not a user identity. It maps to a policy
        # identity only when the operator binds one with JUDIKT_HTTP_BEARER_SUBJECT;
        # otherwise the caller is evaluated as "anonymous".
        subject = (
            auth_result.subject
            if not static_bearer or auth_result.claims.get("subject_bound") is True
            else ""
        )
        context_token = bind_authenticated_subject(subject, auth_result.claims)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_authenticated_subject(context_token)


def register_tools(mcp: Any, runtime: JudiktOpsRuntime) -> None:
    legacy_tool = (
        mcp.tool
        if runtime.policy.config.get("http", {}).get("legacy_call_upstream", False)
        else _skip_tool_registration
    )

    @legacy_tool(
        name="judikt.call_upstream",
        description=(
            "Deprecated compatibility tool. Prefer the natively advertised upstream "
            "tools, which preserve their schemas and annotations."
        ),
    )
    def guard_call_upstream(server: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if server not in runtime.external_clients:
            return {
                "allowed": False,
                "rule": "unknown_external_server",
                "reason": f"external MCP server is not configured: {server}",
            }
        return runtime.call_tool(server, tool, arguments).as_dict()

    demo_tool = mcp.tool if runtime.demo_servers_enabled else _skip_tool_registration

    @demo_tool(
        name="platform.health",
        description="Inspect service status, release, replica health, error rate, and latency.",
    )
    def platform_health(service: str) -> dict[str, Any]:
        return runtime.call_tool("platform-ops", "platform.health", {"service": service}).as_dict()

    @demo_tool(
        name="platform.read_config",
        description="Read sanitized runtime configuration for a service. Secrets are redacted.",
    )
    def platform_read_config(service: str) -> dict[str, Any]:
        return runtime.call_tool("platform-ops", "platform.read_config", {"service": service}).as_dict()

    @demo_tool(
        name="platform.read_logs",
        description="Read recent service logs with a query and bounded result limit.",
    )
    def platform_read_logs(service: str, query: str, limit: int = 10) -> dict[str, Any]:
        return runtime.call_tool(
            "platform-ops",
            "platform.read_logs",
            {"service": service, "query": query, "limit": limit},
        ).as_dict()

    @demo_tool(
        name="platform.run_diagnostic",
        description="Run an allowlisted diagnostic command such as dependency-health, error-rate, or latency-summary.",
    )
    def platform_run_diagnostic(service: str, command: str) -> dict[str, Any]:
        return runtime.call_tool(
            "platform-ops",
            "platform.run_diagnostic",
            {"service": service, "command": command},
        ).as_dict()

    @demo_tool(
        name="platform.restart_deployment",
        description="Perform a guarded rolling restart. Requires actor, rollback plan, and a signed approval token in production.",
    )
    def platform_restart_deployment(
        service: str,
        actor: str,
        rollback_plan: str,
        environment: str = "production",
        approval_token: str = "",
        dry_run: bool = False,
        shadow_mode: bool = False,
        incident_id: str = "",
        auto_create_incident: bool = False,
    ) -> dict[str, Any]:
        return runtime.call_tool(
            "platform-ops",
            "platform.restart_deployment",
            _operation_arguments(
                {
                "service": service,
                "actor": actor,
                "environment": environment,
                "rollback_plan": rollback_plan,
                },
                approval_token=approval_token,
                dry_run=dry_run,
                shadow_mode=shadow_mode,
                incident_id=incident_id,
                auto_create_incident=auto_create_incident,
            ),
        ).as_dict()

    @demo_tool(
        name="platform.rollback_deployment",
        description="Roll a service back to a known release. Requires actor, rollback plan, and a signed approval token in production.",
    )
    def platform_rollback_deployment(
        service: str,
        version: str,
        actor: str,
        rollback_plan: str,
        environment: str = "production",
        approval_token: str = "",
        dry_run: bool = False,
        shadow_mode: bool = False,
        incident_id: str = "",
        auto_create_incident: bool = False,
    ) -> dict[str, Any]:
        return runtime.call_tool(
            "platform-ops",
            "platform.rollback_deployment",
            _operation_arguments(
                {
                "service": service,
                "version": version,
                "actor": actor,
                "environment": environment,
                "rollback_plan": rollback_plan,
                },
                approval_token=approval_token,
                dry_run=dry_run,
                shadow_mode=shadow_mode,
                incident_id=incident_id,
                auto_create_incident=auto_create_incident,
            ),
        ).as_dict()

    @demo_tool(name="kubernetes.get_pod", description="Read Kubernetes pod status through Judikt.")
    def kubernetes_get_pod(namespace: str, pod: str) -> dict[str, Any]:
        return runtime.call_tool(
            "kubernetes",
            "kubernetes.get_pod",
            {"namespace": namespace, "pod": pod},
        ).as_dict()

    @demo_tool(
        name="kubernetes.restart_pod",
        description="Restart a Kubernetes pod through guarded policy. Requires actor, rollback plan, and approval in production.",
    )
    def kubernetes_restart_pod(
        namespace: str,
        pod: str,
        actor: str,
        rollback_plan: str,
        idempotency_key: str = "",
        allow_downtime: bool = False,
        environment: str = "production",
        approval_token: str = "",
        dry_run: bool = False,
        shadow_mode: bool = False,
        incident_id: str = "",
        auto_create_incident: bool = False,
    ) -> dict[str, Any]:
        return runtime.call_tool(
            "kubernetes",
            "kubernetes.restart_pod",
            _operation_arguments(
                {
                "namespace": namespace,
                "pod": pod,
                "idempotency_key": idempotency_key,
                "allow_downtime": allow_downtime,
                "actor": actor,
                "environment": environment,
                "rollback_plan": rollback_plan,
                },
                approval_token=approval_token,
                dry_run=dry_run,
                shadow_mode=shadow_mode,
                incident_id=incident_id,
                auto_create_incident=auto_create_incident,
            ),
        ).as_dict()

    @demo_tool(name="kubernetes.rollout_status", description="Read Kubernetes deployment rollout status.")
    def kubernetes_rollout_status(namespace: str, deployment: str) -> dict[str, Any]:
        return runtime.call_tool(
            "kubernetes",
            "kubernetes.rollout_status",
            {"namespace": namespace, "deployment": deployment},
        ).as_dict()

    @demo_tool(name="incident.create", description="Create an operational incident.")
    def incident_create(title: str, severity: str) -> dict[str, Any]:
        return runtime.call_tool(
            "incident",
            "incident.create",
            {"title": title, "severity": severity},
        ).as_dict()

    @demo_tool(name="incident.attach_evidence", description="Attach redacted evidence to an incident timeline.")
    def incident_attach_evidence(incident_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return runtime.call_tool(
            "incident",
            "incident.attach_evidence",
            {"incident_id": incident_id, "evidence": evidence},
        ).as_dict()

    @demo_tool(name="incident.timeline", description="Read an incident timeline.")
    def incident_timeline(incident_id: str) -> dict[str, Any]:
        return runtime.call_tool("incident", "incident.timeline", {"incident_id": incident_id}).as_dict()

    @mcp.tool(
        name="judikt.issue_approval",
        description="Issue a short-lived HMAC approval token bound to exact tool arguments.",
    )
    def guard_issue_approval(
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if not is_control_plane_admin():
            return {
                "allowed": False,
                "rule": "admin_authorization",
                "reason": "control-plane administrator scope or group is required",
            }
        if os.getenv("JUDIKT_ALLOW_DIRECT_APPROVAL", "").lower() not in {"1", "true", "yes"}:
            return {
                "allowed": False,
                "rule": "human_approval_required",
                "reason": "direct approval issuance is disabled; use judikt.request_approval",
            }
        return {
            "approval_token": runtime.issue_approval(
                actor=actor,
                reason=reason,
                server=server,
                tool=tool,
                arguments=arguments,
                ttl_seconds=ttl_seconds,
            ),
            "ttl_seconds": ttl_seconds,
        }

    @mcp.tool(
        name="judikt.request_approval",
        description="Request an exact-argument approval through the configured Slack human workflow.",
    )
    def guard_request_approval(
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        if not can_execute_control_plane_tool():
            return {
                "allowed": False,
                "rule": "execute_authorization",
                "reason": "control-plane execute role is required",
            }
        try:
            return runtime.request_slack_approval(
                actor=actor,
                reason=reason,
                server=server,
                tool=tool,
                arguments=arguments,
                ttl_seconds=ttl_seconds,
            )
        except (PermissionError, SlackApprovalError) as exc:
            return {"status": "ERROR", "reason": str(exc)}

    @mcp.tool(
        name="judikt.approval_status",
        description="Read a Slack approval request and retrieve its token as the authenticated requester.",
    )
    def guard_approval_status(request_id: str, actor: str) -> dict[str, Any]:
        if not can_execute_control_plane_tool():
            return {
                "allowed": False,
                "rule": "execute_authorization",
                "reason": "control-plane execute role is required",
            }
        try:
            return runtime.slack_approval_status(request_id, actor)
        except (PermissionError, SlackApprovalError) as exc:
            return {"status": "ERROR", "reason": str(exc)}

    @mcp.tool(name="judikt.set_tool_enabled", description="Enable or disable a tool kill switch.")
    def guard_set_tool_enabled(
        tool: str,
        enabled: bool,
        reason: str = "MCP admin request",
    ) -> dict[str, Any]:
        if not is_control_plane_admin():
            return {
                "allowed": False,
                "rule": "admin_authorization",
                "reason": "control-plane administrator scope or group is required",
            }
        runtime.set_tool_enabled(tool, enabled, reason)
        return runtime.kill_switches()

    @mcp.tool(name="judikt.set_server_enabled", description="Enable or disable a server kill switch.")
    def guard_set_server_enabled(
        server: str,
        enabled: bool,
        reason: str = "MCP admin request",
    ) -> dict[str, Any]:
        if not is_control_plane_admin():
            return {
                "allowed": False,
                "rule": "admin_authorization",
                "reason": "control-plane administrator scope or group is required",
            }
        runtime.set_server_enabled(server, enabled, reason)
        return runtime.kill_switches()

    @mcp.tool(name="judikt.runtime_state", description="Inspect kill switches, circuit breakers, and recent audit events.")
    def guard_runtime_state(limit: int = 10) -> dict[str, Any]:
        if not is_control_plane_admin():
            return {
                "allowed": False,
                "rule": "admin_authorization",
                "reason": "control-plane administrator scope or group is required",
            }
        return {
            "kill_switches": runtime.kill_switches(),
            "circuit_breakers": runtime.circuit_breakers(),
            "rate_limiter": {"mode": runtime.policy.rate_limiter_mode},
            "tool_integrity": runtime.tool_integrity_reports,
            "audit_integrity": runtime.audit_integrity(),
            "finding_delivery": runtime.finding_delivery(),
            "recent_audit": runtime.recent_audit(limit),
        }


def register_native_tools(
    mcp: Any,
    runtime: JudiktOpsRuntime,
    catalog: ToolCatalog,
) -> None:
    """Expose policy-approved upstream tools with their native MCP definitions."""
    from mcp import types
    from mcp.server.lowlevel.server import NotificationOptions

    original_list_tools = mcp.list_tools
    original_call_tool = mcp.call_tool
    notifier = _HTTPToolListNotifier()

    original_initialization_options = mcp._mcp_server.create_initialization_options

    def initialization_options(
        notification_options: Any = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> Any:
        return original_initialization_options(
            notification_options or NotificationOptions(tools_changed=True),
            experimental_capabilities,
        )

    mcp._mcp_server.create_initialization_options = initialization_options

    @mcp._mcp_server.list_tools()
    async def list_tools() -> list[Any]:
        notifier.track(
            mcp._mcp_server.request_context.session,
            asyncio.get_running_loop(),
        )
        static_tools = await original_list_tools()
        static_names = {tool.name for tool in static_tools}
        native_tools = [
            types.Tool.model_validate(tool.as_mcp())
            for tool in catalog.tools(authenticated_subject())
            if tool.name not in static_names
        ]
        return [*static_tools, *native_tools]

    @mcp._mcp_server.call_tool(validate_input=True)
    async def call_tool(name: str, arguments: dict[str, Any]) -> Any:
        static_names = {tool.name for tool in await original_list_tools()}
        if name in static_names:
            return await original_call_tool(name, arguments)
        server = catalog.server_for(name)
        if server is None:
            raise ValueError(f"unknown proxied tool: {name}")
        guarded = runtime.call_tool(server, name, arguments)
        return types.CallToolResult.model_validate(gateway_result(guarded))

    catalog.subscribe(notifier.emit)


class _HTTPToolListNotifier:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[int, tuple[Any, asyncio.AbstractEventLoop]] = {}

    def track(self, session: Any, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._sessions[id(session)] = (session, loop)

    def emit(self) -> None:
        with self._lock:
            sessions = list(self._sessions.items())
        for session_id, (session, loop) in sessions:
            if loop.is_closed():
                self._discard(session_id)
                continue
            future = asyncio.run_coroutine_threadsafe(
                session.send_tool_list_changed(), loop
            )
            future.add_done_callback(
                lambda completed, session_id=session_id: self._complete(
                    session_id, completed
                )
            )

    def _complete(self, session_id: int, completed: Any) -> None:
        try:
            completed.result()
        except Exception:
            self._discard(session_id)

    def _discard(self, session_id: int) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


def _operation_arguments(
    required: dict[str, Any],
    *,
    approval_token: str,
    dry_run: bool,
    shadow_mode: bool,
    incident_id: str,
    auto_create_incident: bool,
) -> dict[str, Any]:
    arguments = dict(required)
    if approval_token:
        arguments["approval_token"] = approval_token
    if dry_run:
        arguments["dry_run"] = True
    if shadow_mode:
        arguments["shadow_mode"] = True
    if incident_id:
        arguments["incident_id"] = incident_id
    if auto_create_incident:
        arguments["auto_create_incident"] = True
    return arguments


def _skip_tool_registration(*_args: Any, **_kwargs: Any) -> Any:
    def decorator(function: Any) -> Any:
        return function

    return decorator


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}
