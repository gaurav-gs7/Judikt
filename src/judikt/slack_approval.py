from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import sqlite3
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority, arguments_hash
from .paths import connect_private_sqlite
from .secrets import resolve_configured_secret


class SlackApprovalError(RuntimeError):
    pass


class SlackApprovalWorkflow:
    """Durable, signature-verified Slack approval workflow for exact tool arguments."""

    def __init__(self, path: Path, authority: ApprovalAuthority) -> None:
        webhook_url = resolve_configured_secret(
            direct_env="JUDIKT_SLACK_WEBHOOK_URL",
            aws_secret_env="JUDIKT_SLACK_WEBHOOK_SECRET_ARN",
            vault_path_env="JUDIKT_SLACK_WEBHOOK_VAULT_PATH",
            json_key_env="JUDIKT_SLACK_WEBHOOK_SECRET_JSON_KEY",
            description="Slack webhook URL",
        )
        self.webhook_url = _slack_webhook_url(webhook_url) if webhook_url else ""
        self.signing_secret = resolve_configured_secret(
            direct_env="JUDIKT_SLACK_SIGNING_SECRET",
            aws_secret_env="JUDIKT_SLACK_SIGNING_SECRET_ARN",
            vault_path_env="JUDIKT_SLACK_SIGNING_SECRET_VAULT_PATH",
            json_key_env="JUDIKT_SLACK_SIGNING_SECRET_JSON_KEY",
            description="Slack signing secret",
        )
        self.approvers = {
            value.strip()
            for value in os.getenv("JUDIKT_SLACK_APPROVER_IDS", "").split(",")
            if value.strip()
        }
        self.max_pending_per_requester = _bounded_int_env(
            "JUDIKT_SLACK_MAX_PENDING_PER_REQUESTER", 5, minimum=1, maximum=100
        )
        self._timeout_seconds = _positive_float_env("JUDIKT_SLACK_TIMEOUT_SECONDS", 5.0)
        self.authority = authority
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = connect_private_sqlite(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_requests (
                request_id TEXT PRIMARY KEY,
                requester TEXT NOT NULL,
                reason TEXT NOT NULL,
                server TEXT NOT NULL,
                tool TEXT NOT NULL,
                arguments_hash TEXT NOT NULL,
                safe_arguments_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                approver TEXT NOT NULL DEFAULT '',
                approval_token TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._connection.commit()
        try:
            path.chmod(0o600)
        except OSError:
            pass

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url and self.signing_secret and self.approvers)

    def request(
        self,
        *,
        requester: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        safe_arguments: dict[str, Any],
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        if not self.enabled:
            raise SlackApprovalError(
                "Slack approvals require JUDIKT_SLACK_WEBHOOK_URL, "
                "JUDIKT_SLACK_SIGNING_SECRET, and JUDIKT_SLACK_APPROVER_IDS"
            )
        for name, value in (
            ("requester", requester),
            ("reason", reason),
            ("server", server),
            ("tool", tool),
        ):
            if not value.strip():
                raise SlackApprovalError(f"Slack approval {name} must not be empty")
        if ttl_seconds < 60 or ttl_seconds > 3600:
            raise SlackApprovalError("Slack approval TTL must be between 60 and 3600 seconds")
        now = int(time.time())
        request_id = str(uuid.uuid4())
        digest = arguments_hash(arguments)
        with self._lock:
            duplicate = self._connection.execute(
                """
                SELECT request_id, expires_at FROM approval_requests
                WHERE requester = ? AND server = ? AND tool = ? AND arguments_hash = ?
                  AND status = 'PENDING' AND expires_at >= ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (requester, server, tool, digest, now),
            ).fetchone()
            if duplicate is not None:
                return {
                    "request_id": duplicate["request_id"],
                    "status": "PENDING",
                    "expires_at": duplicate["expires_at"],
                    "deduplicated": True,
                }
            pending = self._connection.execute(
                """
                SELECT COUNT(*) AS count FROM approval_requests
                WHERE requester = ? AND status = 'PENDING' AND expires_at >= ?
                """,
                (requester, now),
            ).fetchone()["count"]
            if int(pending) >= self.max_pending_per_requester:
                raise SlackApprovalError("requester has reached the pending Slack approval limit")
            self._connection.execute(
                """
                INSERT INTO approval_requests (
                    request_id, requester, reason, server, tool, arguments_hash,
                    safe_arguments_json, created_at, expires_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
                """,
                (
                    request_id,
                    requester,
                    reason,
                    server,
                    tool,
                    digest,
                    json.dumps(safe_arguments, sort_keys=True),
                    now,
                    now + ttl_seconds,
                ),
            )
            self._connection.commit()
        try:
            self._notify(request_id, requester, reason, server, tool, safe_arguments)
        except Exception:
            with self._lock:
                self._connection.execute(
                    "DELETE FROM approval_requests WHERE request_id = ? AND status = 'PENDING'",
                    (request_id,),
                )
                self._connection.commit()
            raise
        return {"request_id": request_id, "status": "PENDING", "expires_at": now + ttl_seconds}

    def status(self, request_id: str, requester: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise SlackApprovalError("approval request was not found")
            if row["requester"] != requester:
                raise SlackApprovalError("approval request belongs to a different authenticated subject")
            status = str(row["status"])
            if status == "PENDING" and int(row["expires_at"]) < int(time.time()):
                status = "EXPIRED"
                self._connection.execute(
                    "UPDATE approval_requests SET status = 'EXPIRED' WHERE request_id = ?",
                    (request_id,),
                )
                self._connection.commit()
        result = {
            "request_id": request_id,
            "status": status,
            "server": row["server"],
            "tool": row["tool"],
            "approver": row["approver"],
        }
        if status == "APPROVED":
            result["approval_token"] = row["approval_token"]
        return result

    def handle_action(self, headers: dict[str, str], body: str) -> dict[str, Any]:
        if not self.enabled:
            raise SlackApprovalError(
                "Slack approvals require a webhook, signing secret, and approver IDs"
            )
        self._verify_signature(headers, body)
        try:
            encoded_payload = urllib.parse.parse_qs(body)["payload"][0]
            payload = json.loads(encoded_payload)
            approver = str(payload["user"]["id"])
            action = payload["actions"][0]
            value = json.loads(action["value"])
            request_id = str(value["request_id"])
            decision = str(value["decision"])
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise SlackApprovalError("Slack action payload is invalid") from exc
        if approver not in self.approvers:
            raise SlackApprovalError("Slack user is not an authorized approver")
        if decision not in {"approve", "deny"}:
            raise SlackApprovalError("Slack approval decision is invalid")

        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise SlackApprovalError("approval request was not found")
            if row["status"] != "PENDING":
                raise SlackApprovalError(f"approval request is already {row['status']}")
            if int(row["expires_at"]) < int(time.time()):
                self._connection.execute(
                    "UPDATE approval_requests SET status = 'EXPIRED' WHERE request_id = ?",
                    (request_id,),
                )
                self._connection.commit()
                raise SlackApprovalError("approval request has expired")
            token = ""
            status = "DENIED"
            if decision == "approve":
                status = "APPROVED"
                token = self.authority.issue_digest(
                    actor=row["requester"],
                    reason=f"{row['reason']} (approved in Slack by {approver})",
                    server=row["server"],
                    tool=row["tool"],
                    arguments_hash=row["arguments_hash"],
                    ttl_seconds=300,
                )
            self._connection.execute(
                """
                UPDATE approval_requests
                SET status = ?, approver = ?, approval_token = ?
                WHERE request_id = ?
                """,
                (status, approver, token, request_id),
            )
            self._connection.commit()
        return {
            "response_type": "ephemeral",
            "replace_original": False,
            "text": f"Request {request_id} is {status.lower()} by {approver}.",
        }

    def close(self) -> None:
        self._connection.close()

    def _verify_signature(self, headers: dict[str, str], body: str) -> None:
        timestamp = headers.get("x-slack-request-timestamp", "")
        observed = headers.get("x-slack-signature", "")
        try:
            parsed_timestamp = int(timestamp)
        except ValueError as exc:
            raise SlackApprovalError("Slack request timestamp is invalid") from exc
        if abs(int(time.time()) - parsed_timestamp) > 300:
            raise SlackApprovalError("Slack request timestamp is outside the replay window")
        base = f"v0:{timestamp}:{body}".encode()
        expected = "v0=" + hmac.new(self.signing_secret.encode(), base, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(observed, expected):
            raise SlackApprovalError("Slack request signature is invalid")

    def _notify(
        self,
        request_id: str,
        requester: str,
        reason: str,
        server: str,
        tool: str,
        safe_arguments: dict[str, Any],
    ) -> None:
        summary = _slack_escape(json.dumps(safe_arguments, sort_keys=True)[:1800])
        safe_requester = _slack_escape(requester)
        safe_reason = _slack_escape(reason)
        safe_server = _slack_escape(server)
        safe_tool = _slack_escape(tool)
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*MCP tool approval requested*\n*Requester:* `{safe_requester}`\n"
                        f"*Tool:* `{safe_server}/{safe_tool}`\n*Reason:* {safe_reason}\n"
                        f"*Arguments:* `{summary}`"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": "judikt_approve",
                        "value": json.dumps({"request_id": request_id, "decision": "approve"}),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "action_id": "judikt_deny",
                        "value": json.dumps({"request_id": request_id, "decision": "deny"}),
                    },
                ],
            },
        ]
        request = urllib.request.Request(
            self.webhook_url,
            data=json.dumps({"blocks": blocks}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                if response.status >= 300:
                    raise SlackApprovalError(f"Slack webhook returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise SlackApprovalError(f"Slack webhook returned HTTP {code}") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise SlackApprovalError("Slack approval notification endpoint is unavailable") from exc


def _slack_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _slack_webhook_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SlackApprovalError("Slack webhook URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SlackApprovalError(
            "Slack webhook URL must not contain credentials, query, or fragment"
        )
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    allow_http = os.getenv("JUDIKT_SLACK_ALLOW_INSECURE_HTTP", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if parsed.scheme == "http" and not loopback and not allow_http:
        raise SlackApprovalError("non-loopback Slack webhook integration requires HTTPS")
    return url


def _bounded_int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise SlackApprovalError(
            f"{name} must be an integer between {minimum} and {maximum}"
        ) from exc
    if value < minimum or value > maximum:
        raise SlackApprovalError(
            f"{name} must be an integer between {minimum} and {maximum}"
        )
    return value


def _positive_float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise SlackApprovalError(f"{name} must be a positive finite number") from exc
    if not math.isfinite(value) or value <= 0:
        raise SlackApprovalError(f"{name} must be a positive finite number")
    return value
