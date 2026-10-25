from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .approval import ApprovalAuthority, ApprovalConfigurationError
from .approval_replay import ApprovalReplayConfigurationError
from .attackbench import (
    AttackBenchError,
    report_passes as attackbench_report_passes,
    run_attackbench,
)
from .auth import AuthError
from .audit import AuditConfigurationError, AuditStore, load_checkpoint, write_checkpoint
from .backends import run_backend
from .content_guard import ContentGuard
from .content_eval import ContentEvaluationError, run_content_evaluation
from .demo import run_demo
from .evals import print_evals
from .gateway import serve_gateway
from .http_app import serve_dashboard
from .interop import print_interop_profiles
from .kill_switch import KillSwitchStoreError, build_kill_switch_store
from .metrics import Metrics
from .performance import (
    PerformanceBenchmarkError,
    report_passes as performance_report_passes,
    run_gateway_benchmark,
)
from .paths import (
    DEMO_POLICY_PATH,
    DEFAULT_INTEROP_PROFILES_PATH,
    DEFAULT_POLICY_PATH,
    default_audit_path,
    ensure_private_directory,
    upstream_state,
)
from .pins import accept_summary, run_pins_command
from .policy import PolicyConfigurationError, load_policy_config
from .policy_init import (
    STARTER_PROFILES,
    PolicyInitializationError,
    derive_remote_server_name,
    derive_server_name,
    discover_tools,
    initialize_policy,
    initialize_policy_from_tools,
    normalize_server_name,
)
from .diagnostics import redact_diagnostic
from .llm import LLMConfigurationError
from .protocol import MCPProtocolError
from .real_mcp import serve_real_mcp
from .rate_limiter import RateLimiterUnavailable
from .risk import RiskConfigError
from .runtime import JudiktRuntime
from .secrets import SecretBrokerError
from .tool_integrity import ToolIntegrityError, ToolIntegrityStore, ToolPinMetadata
from .upstreams import (
    UpstreamConfigError,
    UpstreamServer,
    create_upstream_client,
)


# Errors that mean the operator's configuration cannot start Judikt. The CLI
# reports them as one line instead of a traceback; anything else still raises.
STARTUP_CONFIGURATION_ERRORS: tuple[type[BaseException], ...] = (
    ApprovalConfigurationError,
    ApprovalReplayConfigurationError,
    AuditConfigurationError,
    PolicyConfigurationError,
    RiskConfigError,
    UpstreamConfigError,
    SecretBrokerError,
    KillSwitchStoreError,
    LLMConfigurationError,
    RateLimiterUnavailable,
)


class _PolicyPathAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Path,
        option_string: str | None = None,
    ) -> None:
        setattr(namespace, self.dest, values)
        setattr(namespace, "policy_explicit", True)


class _AuditPathAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Path,
        option_string: str | None = None,
    ) -> None:
        setattr(namespace, self.dest, values)
        setattr(namespace, "audit_explicit", True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Judikt runtime firewall")
    result.add_argument("--version", action="version", version=f"judikt {__version__}")
    result.set_defaults(policy_explicit=False, audit_explicit=False)
    result.add_argument(
        "--policy",
        type=Path,
        action=_PolicyPathAction,
        default=DEFAULT_POLICY_PATH,
    )
    result.add_argument(
        "--audit-db",
        type=Path,
        action=_AuditPathAction,
        default=default_audit_path(),
    )
    subparsers = result.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="run the deterministic local walkthrough")
    _add_runtime_options(demo)
    demo.set_defaults(default_policy=DEMO_POLICY_PATH)
    gateway = subparsers.add_parser("serve-mcp", help="expose Judikt over JSON-RPC stdio")
    _add_runtime_options(gateway)
    dashboard = subparsers.add_parser("dashboard", help="run the local HTTP dashboard")
    _add_runtime_options(dashboard)
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", default=8080, type=int)
    real_mcp = subparsers.add_parser("serve-real-mcp", help="run the official MCP Streamable HTTP server")
    _add_runtime_options(real_mcp)
    real_mcp.add_argument("--host", default="127.0.0.1")
    real_mcp.add_argument("--port", default=8080, type=int)
    real_mcp.add_argument("--mcp-path", default="/mcp")
    real_mcp.add_argument("--log-level", default="info")
    approval = subparsers.add_parser("issue-approval", help="issue a signed approval token")
    _add_runtime_options(approval)
    approval.add_argument("--actor", required=True)
    approval.add_argument("--reason", required=True)
    approval.add_argument("--server", required=True)
    approval.add_argument("--tool", required=True)
    approval.add_argument("--arguments", required=True, help="JSON arguments the token is bound to")
    approval.add_argument("--ttl-seconds", type=int, default=300)
    evals = subparsers.add_parser("eval", help="run adversarial safety evals")
    _add_runtime_options(evals)
    evals.set_defaults(default_policy=DEMO_POLICY_PATH)
    interop = subparsers.add_parser(
        "interop",
        help="verify Judikt against pinned independently built MCP servers",
    )
    interop.add_argument("--policy", type=Path, action=_PolicyPathAction, default=argparse.SUPPRESS)
    interop.add_argument(
        "--profiles",
        type=Path,
        default=DEFAULT_INTEROP_PROFILES_PATH,
    )
    interop.add_argument("--profile", action="append", dest="profiles_selected")
    interop.add_argument("--output", type=Path)
    attackbench = subparsers.add_parser(
        "attackbench",
        help="evaluate deterministic controls against a labeled MCP security dataset",
    )
    attackbench.add_argument("dataset", type=Path)
    attackbench.add_argument("--policy", type=Path, action=_PolicyPathAction, default=argparse.SUPPRESS)
    attackbench.add_argument("--dataset-id", default="")
    attackbench.add_argument("--payload-field", default="")
    attackbench.add_argument("--label-field", default="")
    attackbench.add_argument("--category-field", default="")
    attackbench.add_argument("--surface-field", default="")
    attackbench.add_argument("--expected-samples", type=int)
    attackbench.add_argument("--min-precision", type=float, default=0.0)
    attackbench.add_argument("--min-recall", type=float, default=0.0)
    attackbench.add_argument("--min-f1", type=float, default=0.0)
    attackbench.add_argument("--output", type=Path)
    attackbench.set_defaults(default_policy=DEMO_POLICY_PATH)
    content_eval = subparsers.add_parser(
        "eval-content",
        help="measure content-guard precision and recall on the labeled Judikt corpus",
    )
    content_eval.add_argument("--corpus", type=Path, required=True)
    content_eval.add_argument("--split", choices=("dev", "test"), required=True)
    content_eval.add_argument("--output", type=Path, required=True)
    content_eval.add_argument("--policy", type=Path, action=_PolicyPathAction, default=argparse.SUPPRESS)
    content_eval.set_defaults(default_policy=DEFAULT_POLICY_PATH)
    performance = subparsers.add_parser(
        "performance",
        help="measure full in-process Judikt tool-call overhead and throughput",
    )
    performance.add_argument("--policy", type=Path, action=_PolicyPathAction, default=argparse.SUPPRESS)
    performance.add_argument("--iterations", type=int, default=200)
    performance.add_argument("--warmup", type=int, default=20)
    performance.add_argument("--max-p99-ms", type=float, default=0.0)
    performance.add_argument("--min-throughput", type=float, default=0.0)
    performance.add_argument("--output", type=Path)
    performance.set_defaults(default_policy=DEMO_POLICY_PATH)
    backend = subparsers.add_parser("backend", help=argparse.SUPPRESS)
    backend.add_argument("name", choices=["platform-ops", "incident", "kubernetes"])
    init = subparsers.add_parser(
        "init",
        help="generate a starter policy from an upstream MCP tools/list response",
    )
    init.add_argument("--name", default="")
    init.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "pass this variable from your shell to the stdio upstream; repeatable. "
            "Judikt otherwise starts upstreams with a minimal environment, so use this "
            "for values such as HTTPS_PROXY or NODE_EXTRA_CA_CERTS"
        ),
    )
    init.add_argument("--identity", default="local-operator")
    init.add_argument("--profile", choices=STARTER_PROFILES, default="read-only")
    init.add_argument("--output", type=Path, default=Path("judikt-policy.json"))
    init.add_argument("--force", action="store_true")
    init.add_argument(
        "--accept-pins",
        action="store_true",
        help="after showing the classification, pin every discovered tool definition",
    )
    init.add_argument(
        "--yes",
        action="store_true",
        help="with --accept-pins, skip the confirmation prompt",
    )
    init.add_argument("upstream_command", nargs=argparse.REMAINDER)
    wrap = subparsers.add_parser(
        "wrap",
        help="run an MCP server through Judikt",
    )
    _add_runtime_options(wrap)
    wrap.add_argument("--name", default="")
    wrap.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "pass this variable from your shell to the stdio upstream; repeatable. "
            "Judikt otherwise starts upstreams with a minimal environment, so use this "
            "for values such as HTTPS_PROXY or NODE_EXTRA_CA_CERTS"
        ),
    )
    wrap.add_argument("--identity", default="local-operator")
    wrap.add_argument("--profile", choices=STARTER_PROFILES, default="read-only")
    wrap.add_argument("--url", default="", help="remote Streamable HTTP MCP endpoint")
    wrap.add_argument(
        "--allow-private-network",
        action="store_true",
        help="allow a localhost/private remote endpoint after URL validation",
    )
    wrap.add_argument("upstream_command", nargs=argparse.REMAINDER)
    pins = subparsers.add_parser("pins", help="inspect and explicitly update upstream tool pins")
    pin_commands = pins.add_subparsers(dest="pins_command", required=True)
    pin_commands.add_parser("list", help="list per-upstream pin states")
    pin_show = pin_commands.add_parser("show", help="show one upstream pin state")
    pin_show.add_argument("state_key")
    pin_accept = pin_commands.add_parser("accept", help="accept reviewed tool-definition drift")
    pin_accept.add_argument("state_key")
    pin_accept.add_argument("--tool", action="append", dest="tools")
    pin_accept.add_argument("--yes", action="store_true")
    audit = subparsers.add_parser("audit", help="verify and inspect local audit evidence")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    audit_verify = audit_commands.add_parser("verify", help="verify the audit chain and checkpoints")
    audit_verify.add_argument("--audit-db", type=Path, action=_AuditPathAction, default=argparse.SUPPRESS)
    audit_verify.add_argument("--checkpoint")
    audit_verify.add_argument("--full", action="store_true")
    audit_status = audit_commands.add_parser("status", help="show durable audit delivery state")
    audit_status.add_argument("--audit-db", type=Path, action=_AuditPathAction, default=argparse.SUPPRESS)
    audit_checkpoint = audit_commands.add_parser(
        "checkpoint",
        help="write a signed checkpoint at the current head for external storage",
    )
    audit_checkpoint.add_argument("--audit-db", type=Path, action=_AuditPathAction, default=argparse.SUPPRESS)
    audit_checkpoint.add_argument(
        "--output",
        required=True,
        help="destination file or s3://bucket/key",
    )
    audit_reconcile = audit_commands.add_parser(
        "reconcile", help="retry pending audit sink deliveries now"
    )
    audit_reconcile.add_argument("--audit-db", type=Path, action=_AuditPathAction, default=argparse.SUPPRESS)
    audit_reconcile.add_argument("--limit", type=int, default=1000)
    for command_name, enabled in (("kill", False), ("unkill", True)):
        command = subparsers.add_parser(
            command_name,
            help=f"{'disable' if not enabled else 're-enable'} a shared tool or server",
        )
        command.set_defaults(kill_enabled=enabled)
        targets = command.add_subparsers(dest="kill_scope", required=True)
        for scope in ("tool", "server"):
            target = targets.add_parser(scope)
            target.add_argument("name")
            target.add_argument("--reason", required=True)
            target.add_argument("--actor", default="")
        if command_name == "kill":
            targets.add_parser("status", help="show shared kill-switch state")
    return result


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    args = parser().parse_args(argv)
    # Some commands default to a different bundled policy. argparse applies a
    # subcommand's defaults after the global options, so a subcommand default
    # would overwrite an explicit global --policy. Resolve it here instead: an
    # explicit --policy, wherever it appears, always wins.
    default_policy = getattr(args, "default_policy", None)
    if default_policy is not None and not args.policy_explicit:
        args.policy = default_policy
    return args


def _add_runtime_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--policy",
        type=Path,
        action=_PolicyPathAction,
        default=argparse.SUPPRESS,
    )
    command.add_argument(
        "--audit-db",
        type=Path,
        action=_AuditPathAction,
        default=argparse.SUPPRESS,
    )


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}


def main() -> None:
    args = parse_arguments()
    if args.command == "init":
        upstream_command = list(args.upstream_command)
        if upstream_command and upstream_command[0] == "--":
            upstream_command = upstream_command[1:]
        try:
            environment = _passthrough_environment(args.env)
            server_name = normalize_server_name(
                args.name or derive_server_name(upstream_command)
            )
            if args.accept_pins:
                tools = discover_tools(upstream_command, server_name, environment)
                report = initialize_policy_from_tools(
                    tools,
                    server_name=server_name,
                    output_path=args.output,
                    identity=args.identity,
                    profile=args.profile,
                    force=args.force,
                )
            else:
                report = initialize_policy(
                    upstream_command,
                    server_name=server_name,
                    output_path=args.output,
                    identity=args.identity,
                    profile=args.profile,
                    force=args.force,
                    environment=environment,
                )
            _print_classification_summary(report)
            if args.accept_pins:
                report["accepted_pins"] = _accept_initial_pins(
                    tools,
                    server_name=server_name,
                    upstream_command=upstream_command,
                    environment_names=tuple(environment),
                    policy_path=args.output,
                    assume_yes=args.yes,
                )
        except ToolIntegrityError as exc:
            _exit_tool_integrity("init", exc)
        except (
            PolicyInitializationError,
            PolicyConfigurationError,
            MCPProtocolError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            raise SystemExit(f"init: {_operator_error(exc)}") from None
        print(json.dumps(report, indent=2))
        return
    if args.command == "wrap":
        _run_wrap(args)
        return
    if args.command == "pins":
        try:
            run_pins_command(args)
        except (
            ToolIntegrityError,
            MCPProtocolError,
            PolicyConfigurationError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            print(f"pins: {_operator_error(exc)}", file=sys.stderr)
            raise SystemExit(3) from None
        return
    if args.command == "audit":
        try:
            store = AuditStore(args.audit_db)
            try:
                if args.audit_command == "verify":
                    checkpoint = load_checkpoint(args.checkpoint) if args.checkpoint else None
                    report = store.verify_chain(checkpoint, full=args.full)
                elif args.audit_command == "status":
                    report = store.outbox_status()
                elif args.audit_command == "checkpoint":
                    checkpoint = store.checkpoint_now()
                    write_checkpoint(checkpoint, args.output)
                    report = {
                        key: checkpoint[key] for key in ("chain_id", "seq", "head_hash")
                    }
                else:
                    report = store.reconcile(args.limit)
            finally:
                store.close()
        except (AuditConfigurationError, RuntimeError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"audit {args.audit_command}: {exc}") from None
        print(json.dumps(report, indent=2))
        if args.audit_command == "verify":
            raise SystemExit(0 if report["valid"] else 1)
        return
    if args.command in {"kill", "unkill"}:
        try:
            policy_config = load_policy_config(args.policy)
            metrics = Metrics()
            audit_store = AuditStore(args.audit_db, metrics=metrics)
            store = build_kill_switch_store(
                policy_config,
                metrics=metrics,
                audit=audit_store,
                production=_enabled("JUDIKT_PRODUCTION"),
            )
            try:
                if args.kill_scope != "status":
                    actor = args.actor or str(
                        policy_config.get("local_stdio_identity", "local-operator")
                    )
                    store.set(
                        args.kill_scope,
                        args.name,
                        args.kill_enabled,
                        actor,
                        args.reason,
                    )
                state = store.get_state()
                report = {
                    "disabled_tools": sorted(state["tools"]),
                    "disabled_servers": sorted(state["servers"]),
                    "version": state["version"],
                }
            finally:
                store.close()
                audit_store.close()
        except (KillSwitchStoreError, OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"{args.command}: {exc}") from None
        print(json.dumps(report, indent=2))
        return
    demo_mode = args.command == "demo" or _enabled("JUDIKT_DEMO_MODE")
    if demo_mode and args.policy == DEFAULT_POLICY_PATH:
        args.policy = DEMO_POLICY_PATH
    if args.command == "backend":
        run_backend(args.name)
        return
    if args.command == "eval":
        try:
            status = print_evals(args.policy)
        except (PolicyConfigurationError, OSError) as exc:
            raise SystemExit(f"eval: {exc}") from None
        raise SystemExit(status)
    if args.command == "interop":
        try:
            status = print_interop_profiles(
                args.profiles,
                args.policy,
                args.profiles_selected,
                args.output,
            )
        except (PolicyConfigurationError, OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"interop: {exc}") from None
        raise SystemExit(status)
    if args.command == "attackbench":
        try:
            report = run_attackbench(
                args.dataset,
                args.policy,
                dataset_id=args.dataset_id,
                payload_field=args.payload_field,
                label_field=args.label_field,
                category_field=args.category_field,
                surface_field=args.surface_field,
                expected_samples=args.expected_samples,
            )
        except (AttackBenchError, PolicyConfigurationError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"attackbench: {exc}") from None
        rendered = json.dumps(report, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n")
        print(rendered)
        try:
            passed = attackbench_report_passes(
                report,
                min_precision=args.min_precision,
                min_recall=args.min_recall,
                min_f1=args.min_f1,
            )
        except AttackBenchError as exc:
            raise SystemExit(f"attackbench: {exc}") from exc
        raise SystemExit(0 if passed else 1)
    if args.command == "eval-content":
        try:
            report = run_content_evaluation(
                args.corpus,
                args.policy,
                split=args.split,
            )
        except (ContentEvaluationError, PolicyConfigurationError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"eval-content: {exc}") from None
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(report, indent=2)
        args.output.write_text(rendered + "\n")
        print(rendered)
        return
    if args.command == "performance":
        try:
            report = run_gateway_benchmark(
                args.policy,
                iterations=args.iterations,
                warmup=args.warmup,
            )
            passed = performance_report_passes(
                report,
                max_p99_ms=args.max_p99_ms,
                min_throughput=args.min_throughput,
            )
        except (PerformanceBenchmarkError, PolicyConfigurationError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"performance: {exc}") from None
        rendered = json.dumps(report, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n")
        print(rendered)
        raise SystemExit(0 if passed else 1)
    if args.command == "serve-real-mcp":
        try:
            serve_real_mcp(args)
        except (AuthError, *STARTUP_CONFIGURATION_ERRORS) as exc:
            raise SystemExit(f"serve-real-mcp: {_operator_error(exc)}") from None
        except OSError as exc:
            raise SystemExit(f"serve-real-mcp: {_os_error(exc)}") from None
        except ToolIntegrityError as exc:
            _exit_tool_integrity("serve-real-mcp", exc)
        return
    try:
        runtime = JudiktRuntime(
            args.policy,
            args.audit_db,
            include_demo_servers=demo_mode,
            approval_authority=(
                ApprovalAuthority(secrets.token_urlsafe(48))
                if args.command == "demo"
                else None
            ),
        )
    except ToolIntegrityError as exc:
        _exit_tool_integrity(args.command, exc)
    except STARTUP_CONFIGURATION_ERRORS as exc:
        raise SystemExit(f"{args.command}: {_operator_error(exc)}") from None
    except OSError as exc:
        raise SystemExit(f"{args.command}: {_os_error(exc)}") from None
    except MCPProtocolError as exc:
        raise SystemExit(f"{args.command}: {_operator_error(exc)}") from None
    if args.command == "demo":
        try:
            run_demo(runtime)
        finally:
            runtime.close()
    elif args.command == "serve-mcp":
        serve_gateway(runtime)
    elif args.command == "dashboard":
        serve_dashboard(runtime, args.host, args.port, os.getenv("JUDIKT_API_TOKEN"))
    elif args.command == "issue-approval":
        try:
            try:
                arguments = json.loads(args.arguments)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"issue-approval: --arguments is not valid JSON: {exc.msg}"
                ) from None
            if not isinstance(arguments, dict):
                raise SystemExit("issue-approval: --arguments must decode to a JSON object")
            token = runtime.policy.issue_approval(
                actor=args.actor,
                reason=args.reason,
                server=args.server,
                tool=args.tool,
                arguments=arguments,
                ttl_seconds=args.ttl_seconds,
            )
            print(token)
        finally:
            runtime.close()


def _os_error(exc: OSError) -> str:
    detail = exc.strerror or str(exc)
    return f"{detail}: {exc.filename}" if exc.filename else detail


def _run_wrap(args: argparse.Namespace) -> None:
    upstream_command = list(args.upstream_command)
    if upstream_command and upstream_command[0] == "--":
        upstream_command = upstream_command[1:]
    try:
        remote_url = str(getattr(args, "url", "")).strip()
        if remote_url and upstream_command:
            raise PolicyInitializationError("configure either --url or an upstream command, not both")
        if not remote_url and not upstream_command:
            raise PolicyInitializationError(
                "an upstream command is required unless --url is provided"
            )
        if remote_url and getattr(args, "env", None):
            raise PolicyInitializationError("--env applies to stdio upstreams, not --url")
        environment = _passthrough_environment(getattr(args, "env", []))
        default_name = (
            derive_remote_server_name(remote_url)
            if remote_url
            else derive_server_name(upstream_command)
        )
        server_name = normalize_server_name(args.name or default_name)
        state_command = (
            (
                "streamable-http",
                *(("--allow-private-network",) if getattr(args, "allow_private_network", False) else ()),
                remote_url,
            )
            if remote_url
            else tuple(upstream_command)
        )
        state = upstream_state(
            server_name, state_command, environment_names=tuple(environment)
        )
        audit_path = args.audit_db
        if not getattr(args, "audit_explicit", False) and not os.getenv("JUDIKT_AUDIT_DB"):
            ensure_private_directory(state.directory)
            audit_path = state.audit_path
        upstream = UpstreamServer(
            name=server_name,
            command=state.command if not remote_url else (),
            environment=environment,
            cwd=str(state.cwd) if not remote_url else None,
            state_key=state.state_key,
            fingerprint=state.fingerprint,
            url=remote_url,
            allow_private_network=bool(
                getattr(args, "allow_private_network", False)
            ),
        )
        if args.policy_explicit:
            runtime = JudiktRuntime(
                args.policy,
                audit_path,
                upstream_servers=[upstream],
            )
            _warn_unmatched_policy_server(runtime, server_name, args.policy)
            _print_hidden_gated_tools(runtime, server_name, state.state_key)
            serve_gateway(runtime)
            return
        with tempfile.TemporaryDirectory(prefix="judikt-wrap-") as directory:
            policy_path = Path(directory) / "policy.json"
            if remote_url:
                client = create_upstream_client(upstream)
                try:
                    report = initialize_policy_from_tools(
                        client.list_tools(),
                        server_name=server_name,
                        output_path=policy_path,
                        identity=args.identity,
                        profile=args.profile,
                    )
                finally:
                    client.close()
            else:
                report = initialize_policy(
                    upstream_command,
                    server_name=server_name,
                    output_path=policy_path,
                    identity=args.identity,
                    profile=args.profile,
                    environment=environment,
                )
            _print_classification_summary(report)
            runtime = JudiktRuntime(
                policy_path,
                audit_path,
                upstream_servers=[upstream],
            )
            _print_hidden_gated_tools(runtime, server_name, state.state_key)
            serve_gateway(runtime)
    except ToolIntegrityError as exc:
        _exit_tool_integrity("wrap", exc)
    except STARTUP_CONFIGURATION_ERRORS as exc:
        raise SystemExit(f"wrap: {_operator_error(exc)}") from None
    except (
        PolicyInitializationError,
        UpstreamConfigError,
        MCPProtocolError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise SystemExit(f"wrap: {_operator_error(exc)}") from None


def _warn_unmatched_policy_server(runtime: Any, server: str, policy_path: Path) -> None:
    """Say why every tool is hidden when an explicit policy names another server.

    ``judikt init --name X`` keys the allowlist to ``X``, while ``wrap`` without
    ``--name`` derives the server name from the command. The gateway then fails
    closed and exposes nothing, which looks like a broken server.
    """

    config = getattr(runtime.policy, "config", None)
    allowed = config.get("allowed_tools") if isinstance(config, dict) else None
    if not isinstance(allowed, dict) or server in allowed:
        return
    listed = sorted(name for name, tools in allowed.items() if tools)
    if not listed:
        return
    hint = f" Pass --name {shlex.quote(listed[0])} to use it." if len(listed) == 1 else " Pass --name to match one."
    print(
        f"wrap: {policy_path} allows no tools for server '{server}' "
        f"(it allowlists: {', '.join(listed)}), so every tool is hidden.{hint}",
        file=sys.stderr,
    )


def _print_hidden_gated_tools(runtime: Any, server: str, state_key: str) -> None:
    """Explain why approval-gated tools are missing on a first run.

    Approval-gated (write and destructive) tools start pin-pending and stay
    unadvertised until their definitions are accepted once; every call then
    still needs its own approval token.
    """

    config = getattr(runtime.policy, "config", None)
    gated = config.get("approval_required", []) if isinstance(config, dict) else []
    pending = runtime.tool_integrity.pending_tools(server)
    if not isinstance(gated, list) or not isinstance(pending, list):
        return
    hidden = [tool for tool in pending if tool in set(gated)]
    if not hidden:
        return
    selection = " ".join(f"--tool {shlex.quote(tool)}" for tool in hidden)
    print(
        f"{len(hidden)} approval-gated tools are hidden until their definitions are "
        f"accepted: judikt pins accept {shlex.quote(state_key)} {selection}",
        file=sys.stderr,
    )


_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _passthrough_environment(names: list[str] | None) -> dict[str, str]:
    """Resolve ``--env NAME`` options against the operator's shell."""

    environment: dict[str, str] = {}
    for name in names or []:
        if not _ENVIRONMENT_NAME.fullmatch(name):
            raise PolicyInitializationError(f"--env {name!r} is not a valid variable name")
        if name not in os.environ:
            raise PolicyInitializationError(f"--env {name} is not set in this shell")
        environment[name] = os.environ[name]
    return environment


def _accept_initial_pins(
    tools: list[dict[str, Any]],
    *,
    server_name: str,
    upstream_command: list[str],
    policy_path: Path,
    assume_yes: bool,
    environment_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Pin every discovered definition into the state judikt wrap will use."""

    state = upstream_state(
        server_name, tuple(upstream_command), environment_names=environment_names
    )
    explicit_pins = os.getenv("JUDIKT_TOOL_PIN_PATH")
    explicit_audit = os.getenv("JUDIKT_AUDIT_DB")
    if explicit_pins:
        pin_path = Path(explicit_pins)
    elif explicit_audit:
        pin_path = Path(explicit_audit).expanduser().with_suffix(".tool-pins.json")
    else:
        ensure_private_directory(state.directory)
        pin_path = state.pin_path
    names = sorted(str(tool.get("name", "")) for tool in tools if tool.get("name"))
    print(
        f"Pin {len(names)} tool definitions for {server_name} ({state.state_key}) "
        f"in {pin_path}: {', '.join(names) or 'none'}",
        file=sys.stderr,
    )
    if not assume_yes:
        print("Accept these tool definitions? [y/N]", file=sys.stderr)
        if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
            raise ToolIntegrityError("pin acceptance cancelled")
    policy = load_policy_config(policy_path)
    store = ToolIntegrityStore(
        pin_path,
        ContentGuard.from_policy(policy),
        metadata={
            server_name: ToolPinMetadata(
                state_key=state.state_key,
                fingerprint=state.fingerprint,
                command=state.command,
                cwd=str(state.cwd),
                environment_names=state.environment_names,
            )
        },
        policy=policy,
    )
    return accept_summary(store.accept(server_name, tools))


def _operator_error(exc: BaseException) -> str:
    """Render a CLI error for the operator's terminal.

    Upstream failures carry a fixed public reason for agents and a separate
    diagnostic. The operator is the reader here, so show the diagnostic, but
    redact secrets first because terminals are often captured in logs.
    """

    if isinstance(exc, MCPProtocolError):
        return redact_diagnostic(exc.diagnostic)
    return str(exc)


def _exit_tool_integrity(command: str, exc: ToolIntegrityError) -> None:
    print(f"{command}: {exc}", file=sys.stderr)
    raise SystemExit(3)


def _print_classification_summary(report: dict[str, object]) -> None:
    summary = report.get("classification_summary")
    if not isinstance(summary, dict):
        return
    profile = str(summary["profile"])
    counts = summary["counts"]
    assert isinstance(counts, dict)
    print(
        f"Judikt starter policy ({profile}): "
        f"read={counts['read']} write={counts['write']} "
        f"destructive={counts['destructive']}",
        file=sys.stderr,
    )
    for label, key in (
        ("Excluded tools", "excluded_tools"),
        ("Approval-gated tools", "approval_gated_tools"),
        ("Annotation/name conflicts", "conflicts"),
    ):
        values = summary[key]
        assert isinstance(values, list)
        print(f"{label}: {', '.join(str(value) for value in values) or 'none'}", file=sys.stderr)
    if profile == "permissive":
        print(
            "WARNING: permissive profile allows every discovered tool without generated approval gates.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
