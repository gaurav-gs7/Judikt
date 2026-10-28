"""Held calls waiting for a human, approved with ``judikt approve <id>``.

When a call needs approval, the local gateway records it here and tells the
agent the id. A human reviews it in a terminal with ``judikt approve``, which
signs an ordinary single-use approval token bound to that exact call. When the
agent retries the same call unchanged, the gateway attaches the token itself,
so nobody has to copy JSON or tokens around.

Entries live in a private directory under Judikt's state root, expire after
``ttl_seconds`` and are deleted when used, denied or expired. They hold the
call's exact arguments, because the token must be bound to them; treat the
directory like ``approval.key``. Production mode does not use this store:
remote deployments approve through their configured workflow.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .approval import arguments_hash
from .models import strip_control_arguments
from .paths import ensure_private_directory, state_root

DEFAULT_TTL_SECONDS = 900
APPROVED_TTL_SECONDS = 300
MAX_PENDING = 256
_ID = re.compile(r"^[0-9a-f]{8}$")


@dataclass
class PendingApproval:
    id: str
    actor: str
    server: str
    tool: str
    arguments: dict[str, Any]
    arguments_sha256: str
    rule: str
    reason: str
    created_at: float
    expires_at: float
    approved_token: str = ""
    approved_by: str = ""

    @property
    def approved(self) -> bool:
        return bool(self.approved_token)


def default_directory() -> Path:
    return state_root() / "pending-approvals"


def enabled() -> bool:
    production = os.getenv("JUDIKT_PRODUCTION", "").lower() in {"1", "true", "yes"}
    return not production and os.getenv("JUDIKT_PENDING_APPROVALS", "").lower() not in {"0", "off", "false", "no"}


class PendingApprovalStore:
    def __init__(self, directory: Path | None = None, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.directory = directory or default_directory()
        self.ttl_seconds = ttl_seconds

    def _path(self, approval_id: str) -> Path:
        if not _ID.match(approval_id):
            raise ValueError(f"not a pending approval id: {approval_id!r}")
        return self.directory / f"{approval_id}.json"

    def _write(self, entry: PendingApproval) -> None:
        ensure_private_directory(self.directory)
        target = self._path(entry.id)
        temporary = target.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(asdict(entry), stream, sort_keys=True)
        os.replace(temporary, target)

    def _read(self, path: Path) -> PendingApproval | None:
        try:
            entry = PendingApproval(**json.loads(path.read_text()))
        except (OSError, ValueError, TypeError):
            return None
        if entry.expires_at < time.time():
            path.unlink(missing_ok=True)
            return None
        return entry

    def entries(self) -> list[PendingApproval]:
        if not self.directory.is_dir():
            return []
        found = [self._read(path) for path in sorted(self.directory.glob("*.json"))]
        return sorted((entry for entry in found if entry is not None), key=lambda entry: entry.created_at)

    def get(self, approval_id: str) -> PendingApproval | None:
        path = self._path(approval_id)
        return self._read(path) if path.exists() else None

    def hold(
        self, *, actor: str, server: str, tool: str, arguments: dict[str, Any], rule: str, reason: str
    ) -> str:
        """Record a held call, reusing the id of an identical call already waiting."""

        clean = strip_control_arguments(arguments)
        digest = arguments_hash(clean)
        current = self.entries()
        for entry in current:
            if (entry.actor, entry.server, entry.tool, entry.arguments_sha256) == (actor, server, tool, digest):
                if not entry.approved:
                    entry.rule, entry.reason = rule, reason
                    self._write(entry)
                return entry.id
        for stale in current[: max(0, len(current) - MAX_PENDING + 1)]:
            self.discard(stale.id)
        now = time.time()
        entry = PendingApproval(
            id=secrets.token_hex(4),
            actor=actor,
            server=server,
            tool=tool,
            arguments=clean,
            arguments_sha256=digest,
            rule=rule,
            reason=reason,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        self._write(entry)
        return entry.id

    def approve(self, approval_id: str, token: str, approver: str) -> PendingApproval:
        entry = self.get(approval_id)
        if entry is None:
            raise KeyError(approval_id)
        entry.approved_token = token
        entry.approved_by = approver
        entry.expires_at = min(entry.expires_at, time.time() + APPROVED_TTL_SECONDS)
        self._write(entry)
        return entry

    def discard(self, approval_id: str) -> None:
        self._path(approval_id).unlink(missing_ok=True)

    def take_approved(self, *, actor: str, server: str, tool: str, arguments: dict[str, Any]) -> str | None:
        """The approved token for this exact call, removed from the store."""

        digest = arguments_hash(arguments)
        for entry in self.entries():
            if entry.approved and (entry.actor, entry.server, entry.tool, entry.arguments_sha256) == (
                actor,
                server,
                tool,
                digest,
            ):
                self.discard(entry.id)
                return entry.approved_token
        return None
