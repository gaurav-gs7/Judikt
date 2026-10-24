from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .content_guard import ContentGuard
from .ops_runtime import JudiktOpsRuntime
from .protocol import StdioMCPClient
from .tool_integrity import ToolIntegrityStore, verify_unique_tool_names
from .upstreams import resolve_operator_environment


@dataclass(frozen=True)
class InteropProfile:
    name: str
    implementation: str
    version: str
    source_url: str
    command: tuple[str, ...]
    environment: dict[str, Any]
    expected_tools: tuple[str, ...]
    safe_call: dict[str, Any]
    ci: bool


def run_interop_profiles(
    config_path: Path,
    policy_path: Path,
    selected_profiles: list[str] | None = None,
) -> dict[str, Any]:
    profiles = load_interop_profiles(config_path)
    selected = selected_profiles or [name for name, profile in profiles.items() if profile.ci]
    unknown = sorted(set(selected) - set(profiles))
    if unknown:
        raise ValueError(f"unknown interoperability profile(s): {', '.join(unknown)}")

    started = time.perf_counter()
    results = []
    for name in selected:
        profile = profiles[name]
        try:
            results.append(_run_profile(profile, policy_path))
        except Exception as exc:
            encoded_error = f"{type(exc).__name__}:{exc}".encode(errors="replace")
            results.append(
                {
                    "profile": profile.name,
                    "implementation": profile.implementation,
                    "version": profile.version,
                    "source_url": profile.source_url,
                    "transport": "stdio",
                    "passed": False,
                    "error_type": type(exc).__name__,
                    "error_hash": hashlib.sha256(encoded_error).hexdigest(),
                    "error": "profile verification failed; raw upstream output was not retained",
                }
            )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "passed": all(result["passed"] for result in results),
        "profile_count": len(results),
        "passed_count": sum(result["passed"] for result in results),
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "results": results,
    }


def print_interop_profiles(
    config_path: Path,
    policy_path: Path,
    selected_profiles: list[str] | None = None,
    output_path: Path | None = None,
) -> int:
    report = run_interop_profiles(config_path, policy_path, selected_profiles)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered)
    print(rendered, end="")
    return 0 if report["passed"] else 1


def load_interop_profiles(config_path: Path) -> dict[str, InteropProfile]:
    document = json.loads(config_path.read_text())
    if document.get("schema_version") != 1 or not isinstance(document.get("profiles"), dict):
        raise ValueError("interop profile file must use schema_version 1 and contain profiles")
    profiles: dict[str, InteropProfile] = {}
    for name, raw in document["profiles"].items():
        if not isinstance(raw, dict):
            raise ValueError(f"interop profile {name!r} must be an object")
        command = raw.get("command")
        expected_tools = raw.get("expected_tools")
        safe_call = raw.get("safe_call")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
            raise ValueError(f"interop profile {name!r} requires a string command array")
        if not isinstance(expected_tools, list) or not expected_tools:
            raise ValueError(f"interop profile {name!r} requires expected_tools")
        if not isinstance(safe_call, dict) or not isinstance(safe_call.get("tool"), str):
            raise ValueError(f"interop profile {name!r} requires a safe_call")
        profiles[name] = InteropProfile(
            name=name,
            implementation=str(raw["implementation"]),
            version=str(raw["version"]),
            source_url=str(raw["source_url"]),
            command=tuple(command),
            environment=dict(raw.get("env", {})),
            expected_tools=tuple(str(tool) for tool in expected_tools),
            safe_call=safe_call,
            ci=bool(raw.get("ci", False)),
        )
    return profiles


NETWORK_ENVIRONMENT = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
)


def with_network_passthrough(raw_environment: dict[str, Any]) -> dict[str, Any]:
    """Forward the operator's proxy and CA settings to an interop profile.

    Community servers are fetched with npx at run time. Behind a proxy
    (corporate networks, sandboxed CI) npm needs these settings, which
    Judikt's minimal upstream environment otherwise drops. Only the names in
    NETWORK_ENVIRONMENT are forwarded, only when set, and never over a value
    the profile defines itself.
    """
    merged = dict(raw_environment)
    for name in NETWORK_ENVIRONMENT:
        if name in os.environ and name not in merged:
            merged[name] = {"from_env": name}
    return merged

def _run_profile(profile: InteropProfile, policy_path: Path) -> dict[str, Any]:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix=f"judikt-{profile.name}-") as directory:
        sandbox = Path(directory)
        fixture_path = sandbox / "interop-fixture.txt"
        fixture_path.write_text("Judikt community interoperability fixture.\n")
        replacements = {"${SANDBOX}": str(sandbox)}
        command = tuple(_replace(part, replacements) for part in profile.command)
        raw_environment = _replace_value(profile.environment, replacements)
        raw_environment = with_network_passthrough(raw_environment)
        environment = resolve_operator_environment(profile.name, raw_environment)
        safe_call = _replace_value(profile.safe_call, replacements)
        pin_path = sandbox / "tool-pins.json"
        policy_document = json.loads(policy_path.read_text())
        content_guard = ContentGuard.from_policy(policy_document)

        client = StdioMCPClient(
            profile.name,
            command=command,
            environment=environment,
            inherit_environment=False,
        )
        try:
            tools = client.list_tools()
            verify_unique_tool_names({profile.name: tools})
            pin_store = ToolIntegrityStore(
                pin_path,
                content_guard,
                policy=policy_document,
            )
            first_pin = pin_store.verify(profile.name, tools)
            second_tools = client.list_tools()
            second_pin = pin_store.verify(profile.name, second_tools)
        finally:
            client.close()

        names = {str(tool.get("name", "")) for tool in tools}
        missing = sorted(set(profile.expected_tools) - names)
        if missing:
            raise RuntimeError(f"missing expected tools: {', '.join(missing)}")

        upstream_path = sandbox / "upstreams.json"
        upstream_path.write_text(
            json.dumps(
                {
                    "servers": {
                        profile.name: {
                            "command": list(command),
                            "env": raw_environment,
                        }
                    }
                }
            )
        )
        call_tool = str(safe_call["tool"])
        policy_document["allowed_tools"][profile.name] = [call_tool]
        policy_document["actor_permissions"]["anonymous"].append(call_tool)
        profile_policy_path = sandbox / "policy.json"
        profile_policy_path.write_text(json.dumps(policy_document))

        overrides = {
            "JUDIKT_UPSTREAM_CONFIG": str(upstream_path),
            "JUDIKT_TOOL_PIN_PATH": str(pin_path),
            "JUDIKT_TOOL_PIN_MODE": "enforce",
            "JUDIKT_REDIS_URL": None,
            "JUDIKT_REDIS_REQUIRED": None,
        }
        with _temporary_environment(overrides):
            runtime = JudiktOpsRuntime(profile_policy_path, sandbox / "audit.db")
            try:
                definitions = runtime.list_tools()[profile.name]
                call = runtime.call_tool(
                    profile.name,
                    call_tool,
                    dict(safe_call.get("arguments", {})),
                )
                audit_integrity = runtime.audit_integrity()
                pin_report = runtime.tool_integrity_reports[profile.name]
            finally:
                runtime.close()

        response_hash = hashlib.sha256(
            json.dumps(call.result, sort_keys=True, default=str, separators=(",", ":")).encode()
        ).hexdigest()
        stable_pin_states = bool(
            first_pin.status in {"pinned", "pending"}
            and second_pin.status in {"verified", "pending"}
            and pin_report["status"] in {"verified", "pending"}
            and first_pin.digest == second_pin.digest == pin_report["digest"]
            and first_pin.pending_count
            == second_pin.pending_count
            == pin_report["pending_count"]
        )
        passed = bool(
            not missing
            and stable_pin_states
            and call.allowed
            and audit_integrity["valid"]
        )
        return {
            "profile": profile.name,
            "implementation": profile.implementation,
            "version": profile.version,
            "source_url": profile.source_url,
            "transport": "stdio",
            "passed": passed,
            "tool_count": len(definitions),
            "expected_tools": list(profile.expected_tools),
            "metadata_first_check": first_pin.status,
            "metadata_reconnect_check": pin_report["status"],
            "metadata_pending_count": pin_report["pending_count"],
            "safe_call": call_tool,
            "safe_call_allowed": call.allowed,
            "safe_call_rule": call.rule,
            "response_hash": response_hash,
            "audit_chain_valid": audit_integrity["valid"],
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        }


def _replace(value: str, replacements: dict[str, str]) -> str:
    for marker, replacement in replacements.items():
        value = value.replace(marker, replacement)
    return value


def _replace_value(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _replace(value, replacements)
    if isinstance(value, list):
        return [_replace_value(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _replace_value(item, replacements) for key, item in value.items()}
    return value


@contextlib.contextmanager
def _temporary_environment(overrides: dict[str, str | None]) -> Iterator[None]:
    original = {key: os.environ.get(key) for key in overrides}
    try:
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
