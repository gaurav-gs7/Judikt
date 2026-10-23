from __future__ import annotations

from contextvars import ContextVar, Token
import os
from typing import Any


_AUTHENTICATED_SUBJECT: ContextVar[str] = ContextVar("judikt_authenticated_subject", default="")
_AUTHENTICATED_CLAIMS: ContextVar[dict[str, Any]] = ContextVar(
    "judikt_authenticated_claims", default={}
)


def authenticated_subject() -> str:
    return _AUTHENTICATED_SUBJECT.get()


def bind_authenticated_subject(
    subject: str,
    claims: dict[str, Any] | None = None,
) -> tuple[Token[str], Token[dict[str, Any]]]:
    return _AUTHENTICATED_SUBJECT.set(subject), _AUTHENTICATED_CLAIMS.set(claims or {})


def reset_authenticated_subject(tokens: tuple[Token[str], Token[dict[str, Any]]]) -> None:
    subject_token, claims_token = tokens
    _AUTHENTICATED_CLAIMS.reset(claims_token)
    _AUTHENTICATED_SUBJECT.reset(subject_token)


def is_control_plane_admin() -> bool:
    return has_control_plane_role("admin")


def can_execute_control_plane_tool() -> bool:
    return has_control_plane_role("execute")


def has_control_plane_role(role: str) -> bool:
    if role not in {"read", "execute", "approve", "admin"}:
        raise ValueError(f"unknown control-plane role: {role}")
    claims = _AUTHENTICATED_CLAIMS.get()
    if not claims:
        return role in {"read", "execute"}
    if claims.get("auth_type") == "static_bearer":
        granted = str(claims.get("role", "execute"))
        return role in _ROLE_IMPLICATIONS.get(granted, set())
    if claims.get("auth_type") == "demo":
        granted = {str(value) for value in claims.get("roles", [])}
        return any(role in _ROLE_IMPLICATIONS.get(value, set()) for value in granted)
    presented = claims.get("scope", claims.get("scp", []))
    scopes = presented.split() if isinstance(presented, str) else list(presented or [])
    scope_names = {
        "read": os.getenv("JUDIKT_READ_SCOPE", "mcp:read"),
        "execute": os.getenv("JUDIKT_EXECUTE_SCOPE", "mcp:execute"),
        "approve": os.getenv("JUDIKT_APPROVE_SCOPE", "mcp:approve"),
        "admin": os.getenv("JUDIKT_ADMIN_SCOPE", "mcp:admin"),
    }
    groups = claims.get("cognito:groups") or claims.get("groups") or []
    groups = [groups] if isinstance(groups, str) else list(groups)
    group_names = {
        "read": os.getenv("JUDIKT_READ_GROUP", "mcp-read"),
        "execute": os.getenv("JUDIKT_EXECUTE_GROUP", "mcp-execute"),
        "approve": os.getenv("JUDIKT_APPROVE_GROUP", "mcp-approve"),
        "admin": os.getenv("JUDIKT_ADMIN_GROUP", "mcp-admin"),
    }
    granted = {
        name
        for name in _ROLE_IMPLICATIONS
        if scope_names[name] in scopes or group_names[name] in groups
    }
    return any(role in _ROLE_IMPLICATIONS[name] for name in granted)


_ROLE_IMPLICATIONS = {
    "read": {"read"},
    "execute": {"read", "execute"},
    "approve": {"read", "approve"},
    "admin": {"read", "execute", "approve", "admin"},
}
