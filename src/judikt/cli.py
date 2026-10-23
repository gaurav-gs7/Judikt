from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

from .approval import ApprovalAuthority, ApprovalConfigurationError
from .attackbench import (
    AttackBenchError,
    report_passes as attackbench_report_passes,
    run_attackbench,
)
from .auth import AuthError
from .backends import run_backend
from .demo import run_demo
from .evals import print_evals
from .gateway import serve_gateway
from .http_app import serve_dashboard
from .interop import print_interop_profiles
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
from .pins import run_pins_command
from .policy_init import (
    STARTER_PROFILES,
    PolicyInitializationError,
    derive_server_name,
    initialize_policy,
    normalize_server_name,
)
from .protocol import MCPProtocolError
from .real_mcp import serve_real_mcp
from .runtime import JudiktRuntime
from .tool_integrity import ToolIntegrityError
from .upstreams import UpstreamServer


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
    demo.set_defaults(policy=DEMO_POLICY_PATH)
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
    evals.set_defaults(policy=DEMO_POLICY_PATH)
    interop = subparsers.add_parser(
        "interop",
        help="verify Judikt against pinned independently built MCP servers",
    )
    interop.add_argument("--policy", type=Path, default=argparse.SUPPRESS)
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
    attackbench.add_argument("--policy", type=Path, default=argparse.SUPPRESS)
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
    attackbench.set_defaults(policy=DEMO_POLICY_PATH)
    performance = subparsers.add_parser(
        "performance",
        help="measure full in-process Judikt tool-call overhead and throughput",
    )
    performance.add_argument("--policy", type=Path, default=argparse.SUPPRESS)
    performance.add_argument("--iterations", type=int, default=200)
    performance.add_argument("--warmup", type=int, default=20)
    performance.add_argument("--max-p99-ms", type=float, default=0.0)
    performance.add_argument("--min-throughput", type=float, default=0.0)
    performance.add_argument("--output", type=Path)
    performance.set_defaults(policy=DEMO_POLICY_PATH)
    backend = subparsers.add_parser("backend", help=argparse.SUPPRESS)
    backend.add_argument("name", choices=["platform-ops", "incident", "kubernetes"])
    init = subparsers.add_parser(
        "init",
        help="generate a starter policy from an upstream MCP tools/list response",
    )
    init.add_argument("--name", default="")
    init.add_argument("--identity", default="local-operator")
    init.add_argument("--profile", choices=STARTER_PROFILES, default="read-only")
    init.add_argument("--output", type=Path, default=Path("judikt-policy.json"))
    init.add_argument("--force", action="store_true")
    init.add_argument("upstream_command", nargs=argparse.REMAINDER)
    wrap = subparsers.add_parser(
        "wrap",
        help="run a stdio MCP server through Judikt",
    )
    _add_runtime_options(wrap)
    wrap.add_argument("--name", default="")
    wrap.add_argument("--identity", default="local-operator")
    wrap.add_argument("--profile", choices=STARTER_PROFILES, default="read-only")
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
    return result


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
    args = parser().parse_args()
    if args.command == "init":
        upstream_command = list(args.upstream_command)
        if upstream_command and upstream_command[0] == "--":
            upstream_command = upstream_command[1:]
        try:
            report = initialize_policy(
                upstream_command,
                server_name=args.name or derive_server_name(upstream_command),
                output_path=args.output,
                identity=args.identity,
                profile=args.profile,
                force=args.force,
            )
        except (PolicyInitializationError, MCPProtocolError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"init: {exc}") from None
        _print_classification_summary(report)
        print(json.dumps(report, indent=2))
        return
    if args.command == "wrap":
        _run_wrap(args)
        return
    if args.command == "pins":
        try:
            run_pins_command(args)
        except (ToolIntegrityError, MCPProtocolError, OSError, json.JSONDecodeError) as exc:
            print(f"pins: {exc}", file=sys.stderr)
            raise SystemExit(3) from None
        return
    demo_mode = args.command == "demo" or _enabled("JUDIKT_DEMO_MODE")
    if demo_mode and args.policy == DEFAULT_POLICY_PATH:
        args.policy = DEMO_POLICY_PATH
    if args.command == "backend":
        run_backend(args.name)
        return
    if args.command == "eval":
        raise SystemExit(print_evals(args.policy))
    if args.command == "interop":
        raise SystemExit(
            print_interop_profiles(
                args.profiles,
                args.policy,
                args.profiles_selected,
                args.output,
            )
        )
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
        except (AttackBenchError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"attackbench: {exc}") from exc
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
        except (PerformanceBenchmarkError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"performance: {exc}") from exc
        rendered = json.dumps(report, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n")
        print(rendered)
        raise SystemExit(0 if passed else 1)
    if args.command == "serve-real-mcp":
        try:
            serve_real_mcp(args)
        except (AuthError, ApprovalConfigurationError) as exc:
            raise SystemExit(f"serve-real-mcp: {exc}") from None
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
    except ApprovalConfigurationError as exc:
        raise SystemExit(f"{args.command}: {exc}") from None
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
            arguments = json.loads(args.arguments)
            if not isinstance(arguments, dict):
                raise ValueError("--arguments must decode to a JSON object")
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


def _run_wrap(args: argparse.Namespace) -> None:
    upstream_command = list(args.upstream_command)
    if upstream_command and upstream_command[0] == "--":
        upstream_command = upstream_command[1:]
    try:
        server_name = normalize_server_name(args.name or derive_server_name(upstream_command))
        state = upstream_state(server_name, upstream_command)
        audit_path = args.audit_db
        if not getattr(args, "audit_explicit", False) and not os.getenv("JUDIKT_AUDIT_DB"):
            ensure_private_directory(state.directory)
            audit_path = state.audit_path
        upstream = UpstreamServer(
            name=server_name,
            command=state.command,
            environment={},
            cwd=str(state.cwd),
            state_key=state.state_key,
            fingerprint=state.fingerprint,
        )
        if args.policy_explicit:
            runtime = JudiktRuntime(
                args.policy,
                audit_path,
                upstream_servers=[upstream],
            )
            serve_gateway(runtime)
            return
        with tempfile.TemporaryDirectory(prefix="judikt-wrap-") as directory:
            policy_path = Path(directory) / "policy.json"
            report = initialize_policy(
                upstream_command,
                server_name=server_name,
                output_path=policy_path,
                identity=args.identity,
                profile=args.profile,
            )
            _print_classification_summary(report)
            runtime = JudiktRuntime(
                policy_path,
                audit_path,
                upstream_servers=[upstream],
            )
            serve_gateway(runtime)
    except ToolIntegrityError as exc:
        _exit_tool_integrity("wrap", exc)
    except ApprovalConfigurationError as exc:
        raise SystemExit(f"wrap: {exc}") from None
    except (PolicyInitializationError, MCPProtocolError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"wrap: {exc}") from None


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
