from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from .secrets import SecretBrokerError, read_aws_secret, resolve_configured_secret


DEFAULT_FINDING_RULES = {
    "allowlist",
    "authz",
    "blocked_pattern",
    "circuit_breaker",
    "direct_prompt_injection",
    "identity_mismatch",
    "inbound_prompt_injection",
    "kill_switch",
    "rate_limit",
    "restart_failed",
    "restart_verification_timeout",
    "token_passthrough",
    "tool_integrity",
}


class FindingSink(Protocol):
    name: str

    def send(self, event: dict[str, Any]) -> None:
        ...


class ArgusAlertmanagerSink:
    name = "argus-alertmanager"

    def __init__(self, base_url: str, token: str, timeout_seconds: float, hmac_secret: str) -> None:
        self.endpoint = _argus_endpoint(base_url)
        self._token = token
        self._timeout_seconds = _positive_number(timeout_seconds, "JUDIKT_ARGUS_TIMEOUT_SECONDS")
        self._hmac_secret = hmac_secret

    def send(self, event: dict[str, Any]) -> None:
        payload = _argus_payload(event)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "judikt/1",
            "X-Judikt-Event-ID": event["finding_id"],
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if self._hmac_secret:
            headers["X-Judikt-Signature-256"] = "sha256=" + hmac.new(
                self._hmac_secret.encode(), body, hashlib.sha256
            ).hexdigest()
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"Argus returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise RuntimeError(f"Argus returned HTTP {code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("Argus finding endpoint is unavailable") from exc


class FindingDispatcher:
    """Durable, deduplicated outbox for security findings."""

    def __init__(self, path: Path, sink: FindingSink | None = None) -> None:
        self._sink = sink or _sink_from_env()
        self._retry_interval = 5.0
        self._retry_base = 1.0
        self._lock = threading.Lock()
        self._connection: sqlite3.Connection | None = None
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        if self._sink is None:
            return
        self._retry_interval = _positive_float_env(
            "JUDIKT_FINDING_RETRY_INTERVAL_SECONDS", 5.0, minimum=0.1
        )
        self._retry_base = _positive_float_env(
            "JUDIKT_FINDING_RETRY_BASE_SECONDS", 1.0, minimum=0.01
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_outbox (
                finding_id TEXT PRIMARY KEY,
                dedupe_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at REAL NOT NULL DEFAULT 0,
                delivered_at TEXT,
                last_error_hash TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_finding_delivery ON finding_outbox(delivered_at, next_attempt_at)"
        )
        self._connection.commit()
        self._worker = threading.Thread(
            target=self._retry_loop,
            name="judikt-finding-outbox",
            daemon=True,
        )
        self._worker.start()

    @property
    def enabled(self) -> bool:
        return self._sink is not None

    def dispatch(self, event: dict[str, Any]) -> str:
        if self._connection is None:
            return "disabled"
        with self._lock:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO finding_outbox (
                    finding_id, dedupe_key, created_at, payload_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    event["finding_id"],
                    event["dedupe_key"],
                    event["created_at"],
                    json.dumps(event, sort_keys=True, separators=(",", ":")),
                ),
            )
            self._connection.commit()
        if cursor.rowcount == 0:
            return "deduplicated"
        delivered = self.flush(limit=1, finding_id=event["finding_id"])
        return "delivered" if delivered else "pending"

    def flush(self, limit: int = 20, finding_id: str = "") -> int:
        if self._connection is None or self._sink is None or limit <= 0:
            return 0
        now = time.time()
        query = (
            "SELECT * FROM finding_outbox WHERE delivered_at IS NULL "
            "AND next_attempt_at <= ?"
        )
        parameters: list[Any] = [now]
        if finding_id:
            query += " AND finding_id = ?"
            parameters.append(finding_id)
        query += " ORDER BY created_at ASC LIMIT ?"
        parameters.append(limit)
        delivered = 0
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
            for row in rows:
                try:
                    self._sink.send(json.loads(row["payload_json"]))
                except Exception as exc:
                    attempts = int(row["attempts"]) + 1
                    retry_at = now + min(
                        300, self._retry_base * (2 ** min(attempts - 1, 8))
                    )
                    error_hash = hashlib.sha256(
                        f"{exc.__class__.__name__}:{exc}".encode()
                    ).hexdigest()
                    self._connection.execute(
                        """
                        UPDATE finding_outbox
                        SET attempts = ?, next_attempt_at = ?, last_error_hash = ?
                        WHERE finding_id = ?
                        """,
                        (attempts, retry_at, error_hash, row["finding_id"]),
                    )
                else:
                    self._connection.execute(
                        """
                        UPDATE finding_outbox
                        SET attempts = attempts + 1, delivered_at = ?, last_error_hash = ''
                        WHERE finding_id = ?
                        """,
                        (dt.datetime.now(dt.UTC).isoformat(), row["finding_id"]),
                    )
                    delivered += 1
            self._connection.commit()
        return delivered

    def status(self) -> dict[str, Any]:
        if self._connection is None or self._sink is None:
            return {
                "enabled": False,
                "sink": "none",
                "pending": 0,
                "delivered": 0,
                "retrying": 0,
            }
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    SUM(CASE WHEN delivered_at IS NULL THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN delivered_at IS NOT NULL THEN 1 ELSE 0 END) AS delivered,
                    SUM(CASE WHEN delivered_at IS NULL AND attempts > 0 THEN 1 ELSE 0 END) AS retrying
                FROM finding_outbox
                """
            ).fetchone()
        return {
            "enabled": True,
            "sink": self._sink.name,
            "pending": int(row["pending"] or 0),
            "delivered": int(row["delivered"] or 0),
            "retrying": int(row["retrying"] or 0),
        }

    def close(self) -> None:
        if self._connection is None:
            return
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=5)
        self.flush()
        self._connection.close()
        self._connection = None

    def _retry_loop(self) -> None:
        while not self._stop.wait(self._retry_interval):
            self.flush()


def should_emit_finding(rule: str, risk_level: str, allowed: bool) -> bool:
    configured = os.getenv("JUDIKT_FINDING_RULES", "")
    rules = {item.strip() for item in configured.split(",") if item.strip()} or DEFAULT_FINDING_RULES
    include_allowed_critical = os.getenv(
        "JUDIKT_FINDING_INCLUDE_ALLOWED_CRITICAL", ""
    ).lower() in {"1", "true", "yes"}
    return (not allowed and rule in rules) or (
        allowed and risk_level == "critical" and include_allowed_critical
    )


def build_finding_event(
    *,
    correlation_id: str,
    server: str,
    tool: str,
    allowed: bool,
    rule: str,
    action: str,
    reason: str,
    risk_score: int,
    risk_level: str,
    arguments: Any,
    result: Any,
) -> dict[str, Any]:
    created_at = dt.datetime.now(dt.UTC).isoformat()
    dedupe_window = max(
        60, _positive_int_env("JUDIKT_FINDING_DEDUPE_WINDOW_SECONDS", 300)
    )
    dedupe_bucket = int(time.time() // dedupe_window)
    dedupe_key = _sha256(f"{server}:{tool}:{rule}:{dedupe_bucket}")
    return {
        "schema_version": 1,
        "event_type": "judikt.mcp.security_finding",
        "finding_id": str(uuid.uuid5(uuid.NAMESPACE_URL, dedupe_key)),
        "dedupe_key": dedupe_key,
        "created_at": created_at,
        "correlation_id": _label(correlation_id),
        "correlation_id_hash": _sha256(correlation_id),
        "server": _label(server),
        "tool": _label(tool),
        "allowed": allowed,
        "rule": _label(rule),
        "action": _label(action),
        "risk_score": risk_score,
        "risk_level": _label(risk_level),
        "reason_hash": _sha256(reason),
        "arguments_hash": _sha256(_canonical(arguments)),
        "result_hash": _sha256(_canonical(result)),
    }


def _sink_from_env() -> FindingSink | None:
    base_url = os.getenv("JUDIKT_ARGUS_URL", "").strip()
    if not base_url:
        return None
    token = resolve_configured_secret(
        direct_env="JUDIKT_ARGUS_API_TOKEN",
        aws_secret_env="JUDIKT_ARGUS_TOKEN_SECRET_ARN",
        vault_path_env="JUDIKT_ARGUS_TOKEN_VAULT_PATH",
        json_key_env="JUDIKT_ARGUS_TOKEN_SECRET_JSON_KEY",
        description="Argus operator-owned API token",
    )
    if not token:
        raise RuntimeError(
            "JUDIKT_ARGUS_URL requires an operator-owned JUDIKT_ARGUS_API_TOKEN "
            "or a configured AWS/Vault secret source"
        )
    hmac_secret = resolve_configured_secret(
        direct_env="JUDIKT_ARGUS_HMAC_SECRET",
        aws_secret_env="JUDIKT_ARGUS_HMAC_SECRET_ARN",
        vault_path_env="JUDIKT_ARGUS_HMAC_SECRET_VAULT_PATH",
        json_key_env="JUDIKT_ARGUS_HMAC_SECRET_JSON_KEY",
        description="Argus HMAC secret",
    )
    return ArgusAlertmanagerSink(
        base_url,
        token,
        _positive_float_env("JUDIKT_ARGUS_TIMEOUT_SECONDS", 2.0),
        hmac_secret,
    )


def _argus_endpoint(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("JUDIKT_ARGUS_URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("JUDIKT_ARGUS_URL must not contain credentials, query, or fragment")
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    allow_http = os.getenv("JUDIKT_ARGUS_ALLOW_INSECURE_HTTP", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if parsed.scheme == "http" and not loopback and not allow_http:
        raise ValueError(
            "non-loopback Argus integration requires HTTPS or JUDIKT_ARGUS_ALLOW_INSECURE_HTTP=true"
        )
    if parsed.path.rstrip("/").endswith("/v1/alerts/alertmanager"):
        return base_url.rstrip("/")
    return base_url.rstrip("/") + "/v1/alerts/alertmanager"


def _argus_payload(event: dict[str, Any]) -> dict[str, Any]:
    server = _label(event["server"])
    tool = _label(event["tool"])
    rule = _label(event["rule"])
    severity = {"critical": "sev1", "high": "sev2", "medium": "sev3"}.get(
        event["risk_level"], "sev4"
    )
    outcome = "flagged" if event["allowed"] else "blocked"
    summary = f"Judikt security finding: {tool} {outcome} by {rule}"
    labels = {
        "alertname": "JudiktMCPSecurityFinding",
        "service": f"mcp-{server}"[:63],
        "environment": _label(os.getenv("JUDIKT_ENVIRONMENT", "production"))[:63],
        "severity": severity,
        "source": "judikt",
        "rule": rule[:63],
    }
    annotations = {
        "summary": summary[:200],
        "correlation_id": event["correlation_id"],
        "tool": tool,
        "risk_score": str(event["risk_score"]),
        "action": event["action"],
        "arguments_hash": event["arguments_hash"],
        "result_hash": event["result_hash"],
    }
    alert = {
        "status": "firing",
        "labels": labels,
        "annotations": annotations,
        "startsAt": event["created_at"],
        "fingerprint": event["dedupe_key"],
        "generatorURL": "",
    }
    return {
        "status": "firing",
        "receiver": "judikt",
        "groupLabels": {"alertname": labels["alertname"], "service": labels["service"]},
        "commonLabels": labels,
        "commonAnnotations": {"summary": annotations["summary"]},
        "alerts": [alert],
    }


def _aws_secret(secret_id: str) -> str:
    if not secret_id:
        return ""
    try:
        return read_aws_secret(secret_id)
    except SecretBrokerError as exc:
        raise RuntimeError(str(exc)) from exc


def _label(value: Any) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", str(value)).strip("_")
    return normalized[:128] or "unknown"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _positive_number(value: float, name: str, *, minimum: float = 0.0) -> float:
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return max(minimum, value)


def _positive_float_env(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive finite number") from exc
    return _positive_number(value, name, minimum=minimum)


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value
