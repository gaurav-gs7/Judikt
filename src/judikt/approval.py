from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import ensure_private_directory, state_root
from .secrets import resolve_configured_secret


TOKEN_VERSION = "judikt-approval-v2"
REVOKED_DEV_SECRET = "local-dev-approval-secret-change-me"
MINIMUM_SECRET_BYTES = 32


@dataclass(frozen=True)
class ApprovalClaims:
    actor: str
    reason: str
    server: str
    tool: str
    arguments_hash: str
    jti: str
    issued_at: int
    expires_at: int


class ApprovalTokenError(ValueError):
    pass


class ApprovalConfigurationError(RuntimeError):
    pass


class ApprovalAuthority:
    """Issues and verifies HMAC approval tokens for destructive tool calls."""

    def __init__(
        self,
        secret: str | None = None,
        *,
        state_directory: Path | None = None,
        require_configured: bool = False,
    ) -> None:
        self.secret = resolve_approval_secret(
            secret,
            state_directory=state_directory,
            require_configured=require_configured,
        ).encode()

    def issue(
        self,
        *,
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 300,
    ) -> str:
        return self.issue_digest(
            actor=actor,
            reason=reason,
            server=server,
            tool=tool,
            arguments_hash=arguments_hash(arguments),
            ttl_seconds=ttl_seconds,
        )

    def issue_digest(
        self,
        *,
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments_hash: str,
        ttl_seconds: int = 300,
    ) -> str:
        now = int(time.time())
        claims = {
            "version": TOKEN_VERSION,
            "actor": actor,
            "reason": reason,
            "server": server,
            "tool": tool,
            "arguments_hash": arguments_hash,
            "jti": secrets.token_urlsafe(16),
            "issued_at": now,
            "expires_at": now + ttl_seconds,
        }
        payload = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{signature}"

    def verify(
        self,
        *,
        token: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> ApprovalClaims:
        try:
            payload, signature = token.split(".", 1)
        except ValueError as exc:
            raise ApprovalTokenError("approval token is malformed") from exc
        expected = _b64(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ApprovalTokenError("approval token signature is invalid")
        try:
            raw_claims = json.loads(_unb64(payload))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ApprovalTokenError("approval token payload is invalid") from exc
        if raw_claims.get("version") != TOKEN_VERSION:
            raise ApprovalTokenError("approval token version is unsupported; re-issue")
        try:
            claims = ApprovalClaims(
                actor=str(raw_claims["actor"]),
                reason=str(raw_claims["reason"]),
                server=str(raw_claims["server"]),
                tool=str(raw_claims["tool"]),
                arguments_hash=str(raw_claims["arguments_hash"]),
                jti=str(raw_claims["jti"]),
                issued_at=int(raw_claims["issued_at"]),
                expires_at=int(raw_claims["expires_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApprovalTokenError("approval token claims are invalid") from exc
        if not claims.jti or claims.issued_at > claims.expires_at:
            raise ApprovalTokenError("approval token claims are invalid")
        if claims.expires_at < int(time.time()):
            raise ApprovalTokenError("approval token is expired")
        if claims.server != server or claims.tool != tool:
            raise ApprovalTokenError("approval token is bound to a different tool")
        if claims.arguments_hash != arguments_hash(arguments):
            raise ApprovalTokenError("approval token is bound to different arguments")
        return claims


def arguments_hash(arguments: dict[str, Any]) -> str:
    canonical = {
        key: value
        for key, value in arguments.items()
        if key not in {"approved", "approval_token"}
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def resolve_approval_secret(
    explicit: str | None = None,
    *,
    state_directory: Path | None = None,
    require_configured: bool = False,
) -> str:
    configured = ""
    if explicit is None:
        configured = resolve_configured_secret(
            direct_env="JUDIKT_APPROVAL_SECRET",
            aws_secret_env="JUDIKT_APPROVAL_SECRET_ARN",
            vault_path_env="JUDIKT_APPROVAL_SECRET_VAULT_PATH",
            json_key_env="JUDIKT_APPROVAL_SECRET_JSON_KEY",
            description="approval signing secret",
        )
    value = explicit if explicit is not None else configured
    requires_shared = require_configured or _enabled("JUDIKT_PRODUCTION")
    if not value and requires_shared:
        raise ApprovalConfigurationError(
            "remote or production mode requires a configured shared approval secret via "
            "JUDIKT_APPROVAL_SECRET, JUDIKT_APPROVAL_SECRET_ARN, or "
            "JUDIKT_APPROVAL_SECRET_VAULT_PATH"
        )
    if not value:
        value = _read_or_create_install_key(state_directory or state_root())
    _validate_secret(value)
    return value


def _read_or_create_install_key(directory: Path) -> str:
    ensure_private_directory(directory)
    path = directory / "approval.key"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _read_install_key(path)
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


def _read_install_key(path: Path) -> str:
    for _ in range(100):
        metadata = path.stat()
        mode = stat.S_IMODE(metadata.st_mode)
        expected_owner = os.getuid()
        if metadata.st_uid != expected_owner:
            raise ApprovalConfigurationError(
                f"approval key {path} is not owned by the current user; fix ownership and run: chmod 600 {path}"
            )
        if mode & 0o077:
            raise ApprovalConfigurationError(
                f"approval key {path} must not be group- or world-readable; run: chmod 600 {path}"
            )
        value = path.read_text().strip()
        if value:
            return value
        time.sleep(0.01)
    raise ApprovalConfigurationError(f"approval key {path} was created but remained empty")


def _validate_secret(value: str) -> None:
    if value == REVOKED_DEV_SECRET:
        raise ApprovalConfigurationError(
            "the retired public development approval secret is forbidden; configure a new random secret"
        )
    if len(value.encode()) < MINIMUM_SECRET_BYTES:
        raise ApprovalConfigurationError(
            f"approval signing secret must be at least {MINIMUM_SECRET_BYTES} bytes"
        )


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
