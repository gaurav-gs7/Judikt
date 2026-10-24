from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import shlex
import stat
import sys
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .content_guard import ContentGuard
from .paths import ensure_private_directory
from .policy_init import classify_tool
from .secrets import resolve_configured_secret


PIN_FIELDS = ("description", "inputSchema", "annotations", "outputSchema")
DEFAULT_FIRST_USE = {
    "read": "auto",
    "write": "require_approval",
    "destructive": "require_approval",
}


class ToolIntegrityError(RuntimeError):
    pass


class ToolPinPendingError(ToolIntegrityError):
    def __init__(self, server: str, state_key: str, tool: str) -> None:
        self.server = server
        self.state_key = state_key
        self.tool = tool
        super().__init__(
            f"tool {_safe_name(tool)!r} is pending first-use approval; accept with: "
            f"judikt pins accept {shlex.quote(state_key)} --tool {shlex.quote(tool)} --yes"
        )


class ToolDriftError(ToolIntegrityError):
    def __init__(
        self,
        *,
        server: str,
        state_key: str,
        pin_path: Path,
        added_tools: list[str],
        removed_tools: list[str],
        changed_tools: dict[str, list[str]],
        legacy: bool = False,
        integrity_failed: bool = False,
        pending_tools: list[str] | None = None,
    ) -> None:
        self.server = server
        self.state_key = state_key
        self.pin_path = pin_path
        self.added_tools = added_tools
        self.removed_tools = removed_tools
        self.changed_tools = changed_tools
        # Tools already recorded as awaiting first-use approval. They are not
        # "added": the operator has seen them before and they stay hidden
        # until accepted.
        self.pending_tools = list(pending_tools or [])
        self.legacy = legacy
        self.integrity_failed = integrity_failed
        super().__init__(self.format_message())

    @property
    def accept_command(self) -> str:
        return f"judikt pins accept {shlex.quote(self.state_key)} --yes"

    def one_line(self) -> str:
        if self.integrity_failed:
            details = "pin file integrity check failed"
        elif self.legacy:
            details = "legacy pin; per-tool diff unavailable"
        else:
            parts = []
            if self.added_tools:
                parts.append(f"added: {_safe_names(self.added_tools)}")
            if self.removed_tools:
                parts.append(f"removed: {_safe_names(self.removed_tools)}")
            if self.changed_tools:
                changed = ", ".join(
                    f"{_safe_name(name)} ({', '.join(fields)})"
                    for name, fields in self.changed_tools.items()
                )
                parts.append(f"changed: {changed}")
            if self.pending_tools:
                parts.append(f"pending approval: {_safe_names(self.pending_tools)}")
            details = "; ".join(parts) or "catalog digest changed"
        return (
            f"tool definition drift detected for {_safe_name(self.server)}: {details}; "
            f"accept with: {self.accept_command}"
        )

    def format_message(self) -> str:
        lines = [
            f"Tool definition drift detected for {_safe_name(self.server)}.",
            f"State key: {self.state_key}",
            f"Pin file: {self.pin_path}",
        ]
        if self.integrity_failed:
            lines.append("Changes: pin file integrity check failed")
        elif self.legacy:
            lines.append("Changes: legacy pin; per-tool diff unavailable")
        else:
            lines.extend(
                [
                    f"Added tools: {_safe_names(self.added_tools) if self.added_tools else 'none'}",
                    f"Removed tools: {_safe_names(self.removed_tools) if self.removed_tools else 'none'}",
                    "Changed tools: "
                    + (
                        ", ".join(
                            f"{_safe_name(name)} ({', '.join(fields)})"
                            for name, fields in self.changed_tools.items()
                        )
                        if self.changed_tools
                        else "none"
                    ),
                ]
            )
            if self.pending_tools:
                lines.append(f"Pending approval: {_safe_names(self.pending_tools)}")
        lines.extend(
            [
                f"Review: judikt pins show {shlex.quote(self.state_key)}",
                f"Accept: {self.accept_command}",
            ]
        )
        return "\n".join(lines)


@dataclass(frozen=True)
class ToolPinMetadata:
    state_key: str
    fingerprint: str = ""
    command: tuple[str, ...] = ()
    cwd: str = ""
    environment_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolIntegrityReport:
    server: str
    digest: str
    status: str
    tool_count: int
    pending_count: int = 0
    integrity_status: str = "verified"
    pinned_count: int | None = None
    accepted_tools: list[str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class _PinMACError(RuntimeError):
    def __init__(self, server: str) -> None:
        self.server = server
        super().__init__("pin file integrity check failed")


class ToolIntegrityStore:
    """Signed, process-safe tool pins with tier-aware first-use approval."""

    def __init__(
        self,
        path: Path,
        content_guard: ContentGuard,
        mode: str | None = None,
        metadata: dict[str, ToolPinMetadata] | None = None,
        policy: dict[str, Any] | None = None,
    ) -> None:
        self.path = path
        self.content_guard = content_guard
        self.mode = mode or os.getenv("JUDIKT_TOOL_PIN_MODE", "enforce")
        if self.mode not in {"enforce", "refresh", "disabled"}:
            raise ValueError("tool pin mode must be enforce, refresh, or disabled")
        if self.mode == "refresh":
            print(
                "WARNING: JUDIKT_TOOL_PIN_MODE=refresh re-trusts every MCP server in this pin file.",
                file=sys.stderr,
            )
        self.metadata = metadata or {}
        self.policy = policy or {}
        self._lock = threading.Lock()
        self._warned_unsigned: set[str] = set()
        self._secret: bytes | None = None

    def verify(self, server: str, tools: list[dict[str, Any]]) -> ToolIntegrityReport:
        self._inspect(server, tools)
        digest = _tool_digest(tools)
        if self.mode == "disabled":
            return ToolIntegrityReport(server, digest, "disabled", len(tools))
        with self._lock, self._file_lock():
            try:
                pins, unsigned = self._read_unlocked()
            except _PinMACError as exc:
                raise self._integrity_drift(exc.server, tools) from None
            observed = pins.get(server)
            current = self._records(server, tools)
            if observed is None or self.mode == "refresh":
                accepted, pending = self._split_first_use(server, current)
                pins[server] = self._entry_from_records(
                    server,
                    accepted,
                    observed,
                    pending=pending,
                )
                self._write_unlocked(pins)
                return self._report(
                    server,
                    digest,
                    "pending" if pending else ("pinned" if observed is None else "refreshed"),
                    len(tools),
                    pending,
                )
            if isinstance(observed, str):
                if observed != _legacy_tool_digest(tools):
                    raise self._drift(server, {}, tools, legacy=True)
                self._warn_unsigned(server)
                pins[server] = self._entry_from_records(server, current, observed)
                self._write_unlocked(pins)
                return ToolIntegrityReport(
                    server,
                    digest,
                    "upgraded",
                    len(tools),
                    integrity_status="upgraded",
                )

            pinned = _pinned_tools(observed)
            pending = _pending_tools(observed)
            drift = self._drift(server, pinned, tools, pending=pending)
            if drift.removed_tools or drift.changed_tools:
                raise drift

            current_names = set(current)
            pending = {name: value for name, value in pending.items() if name in current_names}
            for name in set(current) & set(pending):
                pending[name] = current[name]
            new_records = {
                name: record
                for name, record in current.items()
                if name not in pinned and name not in pending
            }
            auto, newly_pending = self._split_first_use(server, new_records)
            pinned.update(auto)
            pending.update(newly_pending)
            needs_write = bool(auto or newly_pending or unsigned)
            if needs_write:
                pins[server] = self._entry_from_records(
                    server,
                    pinned,
                    observed,
                    pending=pending,
                )
                self._write_unlocked(pins)
            status = "pending" if pending else ("upgraded" if unsigned else "verified")
            return self._report(server, digest, status, len(tools), pending)

    def compare(self, server: str, tools: list[dict[str, Any]]) -> ToolDriftError | None:
        self._inspect(server, tools)
        with self._lock, self._file_lock():
            try:
                pins, _ = self._read_unlocked()
            except _PinMACError as exc:
                return self._integrity_drift(exc.server, tools)
            observed = pins.get(server)
            if observed is None:
                return self._drift(server, {}, tools)
            if isinstance(observed, str):
                return None if observed == _legacy_tool_digest(tools) else self._drift(
                    server, {}, tools, legacy=True
                )
            drift = self._drift(
                server,
                _pinned_tools(observed),
                tools,
                pending=_pending_tools(observed),
            )
            changed = (
                drift.added_tools
                or drift.removed_tools
                or drift.changed_tools
                or drift.pending_tools
            )
            return drift if changed else None

    def accept(
        self,
        server: str,
        tools: list[dict[str, Any]],
        tool_names: list[str] | None = None,
    ) -> ToolIntegrityReport:
        """Pin the selected tools (or the whole current catalog).

        The report's ``pinned_count`` and ``pending_count`` describe the stored
        state after this call, and ``accepted_tools`` lists what this call
        accepted.
        """
        self._inspect(server, tools)
        with self._lock, self._file_lock():
            pins, _ = self._read_unlocked(allow_invalid_mac=True)
            observed = pins.get(server)
            current = self._records(server, tools)
            if tool_names:
                pinned = {} if isinstance(observed, str) else dict(_pinned_tools(observed or {}))
                pending = {} if isinstance(observed, str) else dict(_pending_tools(observed or {}))
                known = set(pinned) | set(pending) | set(current)
                unknown = sorted(set(tool_names) - known)
                if unknown:
                    raise ToolIntegrityError(
                        f"unknown tool selection: {', '.join(unknown)}"
                    )
                for name in tool_names:
                    pending.pop(name, None)
                    if name in current:
                        pinned[name] = current[name]
                    else:
                        pinned.pop(name, None)
                pins[server] = self._entry_from_records(
                    server,
                    pinned,
                    observed,
                    pending=pending,
                )
                accepted = sorted(set(tool_names))
            else:
                pinned = dict(current)
                pending = {}
                pins[server] = self._entry_from_records(server, current, observed)
                accepted = sorted(current)
            self._write_unlocked(pins)
        return ToolIntegrityReport(
            server,
            _tool_digest(tools),
            "accepted",
            len(tools),
            pending_count=len(pending),
            pinned_count=len(pinned),
            accepted_tools=accepted,
        )

    def entries(self, *, allow_invalid_mac: bool = False) -> dict[str, Any]:
        with self._lock, self._file_lock():
            try:
                pins, _ = self._read_unlocked(allow_invalid_mac=allow_invalid_mac)
            except _PinMACError as exc:
                raise ToolIntegrityError(
                    f"pin file integrity check failed for {_safe_name(exc.server)}"
                ) from None
            return pins

    def pending_tools(self, server: str) -> list[str]:
        with self._lock, self._file_lock():
            try:
                pins, _ = self._read_unlocked()
            except _PinMACError as exc:
                raise self._integrity_drift(exc.server, []) from None
            observed = pins.get(server, {})
            return sorted(_pending_tools(observed)) if isinstance(observed, dict) else []

    def is_pending(self, server: str, tool: str) -> bool:
        return tool in self.pending_tools(server)

    def pending_error(self, server: str, tool: str) -> ToolPinPendingError:
        metadata = self.metadata.get(server, ToolPinMetadata(server))
        return ToolPinPendingError(server, metadata.state_key, tool)

    def _inspect(self, server: str, tools: list[dict[str, Any]]) -> None:
        inspection = self.content_guard.inspect(tools, surface="tool_description")
        if not inspection.allowed:
            rules = sorted({finding.rule for finding in inspection.findings})
            raise ToolIntegrityError(
                f"tool metadata from {server!r} was quarantined: {', '.join(rules)}"
            )

    def _records(
        self,
        server: str,
        tools: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        records = _tool_records(tools)
        classifications = self.policy.get("tool_classification", {})
        for tool in tools:
            name = str(tool.get("name", ""))
            configured = classifications.get(name, {}) if isinstance(classifications, dict) else {}
            tier = configured.get("tier") if isinstance(configured, dict) else None
            records[name]["tier"] = tier or classify_tool(name, tool)["tier"]
        return records

    def _split_first_use(
        self,
        server: str,
        records: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        accepted: dict[str, dict[str, Any]] = {}
        pending: dict[str, dict[str, Any]] = {}
        for name, record in records.items():
            target = pending if self._first_use_mode(str(record["tier"])) == "require_approval" else accepted
            target[name] = record
        return accepted, pending

    def _first_use_mode(self, tier: str) -> str:
        pinning = self.policy.get("tool_pinning", {})
        if not isinstance(pinning, dict):
            raise ToolIntegrityError("tool_pinning must be an object")
        configured = pinning.get("first_use", DEFAULT_FIRST_USE)
        if isinstance(configured, str):
            values = {"read": configured, "write": configured, "destructive": configured}
        elif isinstance(configured, dict):
            values = {**DEFAULT_FIRST_USE, **configured}
        else:
            raise ToolIntegrityError("tool_pinning.first_use must be a string or object")
        for key, value in values.items():
            if key not in DEFAULT_FIRST_USE or value not in {"auto", "require_approval"}:
                raise ToolIntegrityError(
                    "tool_pinning.first_use supports read, write, and destructive values of auto or require_approval"
                )
        return str(values.get(tier, "require_approval"))

    def _entry_from_records(
        self,
        server: str,
        records: dict[str, dict[str, Any]],
        previous: Any = None,
        *,
        pending: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        metadata = self.metadata.get(server, ToolPinMetadata(server))
        previous_entry = previous if isinstance(previous, dict) else {}
        command = (
            shlex.join(metadata.command)
            if metadata.command
            else previous_entry.get("command", "")
        )
        entry = {
            "schema_version": 2,
            "digest": _records_digest(records),
            "fingerprint": metadata.fingerprint or previous_entry.get("fingerprint", ""),
            "command": command,
            "cwd": metadata.cwd or previous_entry.get("cwd", ""),
            "environment_names": list(
                metadata.environment_names
                or previous_entry.get("environment_names", [])
            ),
            "pinned_at": datetime.now(UTC).isoformat(),
            "tools": records,
            "pending_tools": pending or {},
        }
        entry["mac"] = self._entry_mac(entry)
        return entry

    def _drift(
        self,
        server: str,
        pinned: dict[str, dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        legacy: bool = False,
        pending: dict[str, Any] | None = None,
    ) -> ToolDriftError:
        current = _tool_records(tools)
        pending = pending or {}
        pending_names = sorted(set(pending) & set(current))
        added = sorted(set(current) - set(pinned) - set(pending_names))
        removed = sorted(set(pinned) - set(current))
        changed = {}
        # A pending tool is compared against its first-observed record too:
        # an upstream that swaps a tool's definition while it still awaits
        # first-use approval must surface as drift, not be accepted silently
        # into the stored pending snapshot.
        baseline = {**pending, **pinned}
        for name in sorted((set(pinned) | set(pending_names)) & set(current)):
            reference = baseline[name]
            if reference.get("digest") == current[name]["digest"]:
                continue
            old_fields = reference.get("fields", {})
            fields = [
                field
                for field in PIN_FIELDS
                if old_fields.get(field) != current[name]["fields"][field]
            ]
            changed[name] = fields or ["definition"]
        metadata = self.metadata.get(server, ToolPinMetadata(server))
        return ToolDriftError(
            server=server,
            state_key=metadata.state_key,
            pin_path=self.path,
            added_tools=added,
            removed_tools=removed,
            changed_tools=changed,
            legacy=legacy,
            pending_tools=pending_names,
        )

    def _integrity_drift(
        self,
        server: str,
        tools: list[dict[str, Any]],
    ) -> ToolDriftError:
        metadata = self.metadata.get(server, ToolPinMetadata(server))
        names = sorted(str(tool.get("name", "")) for tool in tools if tool.get("name"))
        return ToolDriftError(
            server=server,
            state_key=metadata.state_key,
            pin_path=self.path,
            added_tools=[],
            removed_tools=[],
            changed_tools={name: ["integrity"] for name in names},
            integrity_failed=True,
        )

    def _report(
        self,
        server: str,
        digest: str,
        status: str,
        count: int,
        pending: dict[str, dict[str, Any]],
    ) -> ToolIntegrityReport:
        return ToolIntegrityReport(
            server,
            digest,
            status,
            count,
            pending_count=len(pending),
            integrity_status="verified",
        )

    def _read_unlocked(
        self,
        *,
        allow_invalid_mac: bool = False,
    ) -> tuple[dict[str, Any], set[str]]:
        if not self.path.exists():
            return {}, set()
        self._validate_owned_private_file(self.path, writable_only=True)
        try:
            parsed = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolIntegrityError(f"cannot read pin file {self.path}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ToolIntegrityError("tool pin file must contain a JSON object")
        unsigned: set[str] = set()
        for server, entry in parsed.items():
            if not isinstance(entry, dict):
                unsigned.add(str(server))
                self._warn_unsigned(str(server))
                continue
            mac = entry.get("mac")
            if not isinstance(mac, str):
                unsigned.add(str(server))
                self._warn_unsigned(str(server))
                continue
            if not hmac.compare_digest(mac, self._entry_mac(entry)) and not allow_invalid_mac:
                raise _PinMACError(str(server))
        return parsed, unsigned

    def _write_unlocked(self, pins: dict[str, Any]) -> None:
        signed = {
            server: self._sign_existing_entry(entry)
            for server, entry in pins.items()
        }
        temporary = self.path.with_name(
            f".{self.path.name}.tmp.{os.getpid()}.{threading.get_ident()}"
        )
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(json.dumps(signed, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.path)
            self.path.chmod(0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _sign_existing_entry(self, entry: Any) -> Any:
        if not isinstance(entry, dict):
            return entry
        signed = dict(entry)
        signed["mac"] = self._entry_mac(signed)
        return signed

    def _entry_mac(self, entry: dict[str, Any]) -> str:
        payload = {key: value for key, value in entry.items() if key != "mac"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._pin_secret(), canonical, hashlib.sha256).hexdigest()

    def _pin_secret(self) -> bytes:
        if self._secret is not None:
            return self._secret
        configured = resolve_configured_secret(
            direct_env="JUDIKT_PINS_HMAC_SECRET",
            aws_secret_env="JUDIKT_PINS_HMAC_SECRET_ARN",
            vault_path_env="JUDIKT_PINS_HMAC_SECRET_VAULT_PATH",
            json_key_env="JUDIKT_PINS_HMAC_SECRET_JSON_KEY",
            description="tool-pin HMAC secret",
        )
        value = configured or self._read_or_create_key()
        if len(value.encode()) < 32:
            raise ToolIntegrityError("tool-pin HMAC secret must be at least 32 bytes")
        self._secret = value.encode()
        return self._secret

    def _read_or_create_key(self) -> str:
        path = self.path.parent / "pins.key"
        ensure_private_directory(path.parent)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            self._validate_owned_private_file(path)
            return path.read_text().strip()
        value = secrets.token_urlsafe(48)
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(value + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return value

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        ensure_private_directory(self.path.parent)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            self._validate_owned_private_file(lock_path)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _validate_owned_private_file(path: Path, *, writable_only: bool = False) -> None:
        metadata = path.stat()
        if metadata.st_uid != os.getuid():
            raise ToolIntegrityError(
                f"tool pin file {path} is not owned by the current user"
            )
        forbidden = 0o022 if writable_only else 0o077
        if stat.S_IMODE(metadata.st_mode) & forbidden:
            requirement = "group- or world-writable" if writable_only else "group- or world-accessible"
            raise ToolIntegrityError(
                f"tool pin file {path} must not be {requirement}; run: chmod 600 {path}"
            )

    def _warn_unsigned(self, server: str) -> None:
        if server in self._warned_unsigned:
            return
        print(
            f"WARNING: legacy unsigned tool pin for {_safe_name(server)} will be signed after successful verification",
            file=sys.stderr,
        )
        self._warned_unsigned.add(server)


def _pinned_tools(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if entry.get("schema_version") != 2 or not isinstance(entry.get("tools"), dict):
        raise ToolIntegrityError("tool pin entry must use schema_version 2")
    return entry["tools"]


def _pending_tools(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    pending = entry.get("pending_tools", {})
    if not isinstance(pending, dict):
        raise ToolIntegrityError("tool pin pending_tools must be an object")
    return pending


def _tool_records(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    records = {}
    for tool in tools:
        name = str(tool.get("name", ""))
        records[name] = {
            "digest": _canonical_digest(tool),
            "fields": {
                field: _canonical_digest(tool.get(field)) for field in PIN_FIELDS
            },
        }
    return records


def _tool_digest(tools: list[dict[str, Any]]) -> str:
    return _records_digest(_tool_records(tools))


def _records_digest(records: dict[str, dict[str, Any]]) -> str:
    return _canonical_digest(
        {name: record["digest"] for name, record in sorted(records.items())}
    )


def _legacy_tool_digest(tools: list[dict[str, Any]]) -> str:
    return _canonical_digest(tools)


def _canonical_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _safe_name(value: str) -> str:
    clean = "".join(character for character in str(value) if character.isprintable())
    return clean[:80]


def _safe_names(values: list[str]) -> str:
    return ", ".join(_safe_name(value) for value in values)


def verify_unique_tool_names(definitions: dict[str, list[dict[str, Any]]]) -> None:
    owners: dict[str, str] = {}
    for server, tools in definitions.items():
        for tool in tools:
            name = str(tool.get("name", ""))
            if not name:
                raise ToolIntegrityError(
                    f"MCP server {server!r} advertised a tool without a name"
                )
            previous = owners.get(name)
            if previous is not None:
                raise ToolIntegrityError(
                    f"cross-server tool shadowing detected: {name!r} is advertised by {previous!r} and {server!r}"
                )
            owners[name] = server
