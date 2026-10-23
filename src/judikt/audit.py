from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .audit_sink import build_audit_sink
from .paths import ensure_private_directory, state_root
from .secrets import resolve_configured_secret


MINIMUM_AUDIT_SECRET_BYTES = 32
CHECKPOINT_LIMITATION = (
    "Local checkpoints detect accidental loss, but a local attacker can truncate both "
    "audit events and checkpoints. Tamper-evidence against a local attacker requires an "
    "external checkpoint destination such as S3 Object Lock or a SIEM."
)


class AuditConfigurationError(RuntimeError):
    pass


class AuditStore:
    def __init__(self, path: Path, *, require_configured_key: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._signing_secret = resolve_audit_secret(
            require_configured=require_configured_key,
        )
        self._signature_required = True
        self._checkpoint_events = _positive_int_env("JUDIKT_AUDIT_CHECKPOINT_EVENTS", 100)
        self._checkpoint_seconds = _positive_float_env("JUDIKT_AUDIT_CHECKPOINT_SECONDS", 60.0)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.Lock()
        self._instance_id = os.getenv("JUDIKT_INSTANCE_ID", "local")
        self._sink_strict = os.getenv("JUDIKT_AUDIT_SINK_STRICT", "").lower() in {"1", "true", "yes"}
        self._sink = build_audit_sink(path.with_suffix(".audit.jsonl"))
        self._initialize_schema()
        if _enabled("JUDIKT_AUDIT_VERIFY_ON_STARTUP"):
            report = self.verify_chain()
            if not report["valid"]:
                self._connection.close()
                raise RuntimeError(
                    "audit integrity verification failed at startup: "
                    + json.dumps(report["errors"], separators=(",", ":"))
                )

    def _ensure_column(self, name: str, ddl: str) -> None:
        columns = {
            row["name"]
            for row in self._connection.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        if name not in columns:
            self._connection.execute(f"ALTER TABLE audit_events ADD COLUMN {name} {ddl}")

    def _initialize_schema(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    server TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    rule TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    result_json TEXT,
                    duration_ms REAL NOT NULL,
                    action TEXT NOT NULL DEFAULT 'ALLOW',
                    previous_hash TEXT NOT NULL DEFAULT '',
                    event_hash TEXT NOT NULL DEFAULT '',
                    signature TEXT NOT NULL DEFAULT '',
                    instance_id TEXT NOT NULL DEFAULT 'local',
                    event_version INTEGER NOT NULL DEFAULT 1,
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    seq INTEGER,
                    chain_id TEXT,
                    hash_version INTEGER
                )
                """
            )
            self._ensure_column("action", "TEXT NOT NULL DEFAULT 'ALLOW'")
            self._ensure_column("previous_hash", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("event_hash", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("signature", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("instance_id", "TEXT NOT NULL DEFAULT 'local'")
            self._ensure_column("event_version", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column("evidence_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column("seq", "INTEGER")
            self._ensure_column("chain_id", "TEXT")
            self._ensure_column("hash_version", "INTEGER")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS audit_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    head_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    UNIQUE(chain_id, seq)
                )
                """
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO audit_meta (key, value) VALUES ('chain_id', ?)",
                (str(uuid.uuid4()),),
            )
            chain_row = self._connection.execute(
                "SELECT value FROM audit_meta WHERE key = 'chain_id'"
            ).fetchone()
            self._chain_id = str(chain_row["value"])
            unmigrated = self._connection.execute(
                "SELECT id FROM audit_events WHERE seq IS NULL ORDER BY id"
            ).fetchall()
            next_seq_row = self._connection.execute(
                "SELECT COALESCE(MAX(seq), 0) AS seq FROM audit_events"
            ).fetchone()
            next_seq = int(next_seq_row["seq"])
            for row in unmigrated:
                next_seq += 1
                self._connection.execute(
                    """
                    UPDATE audit_events
                    SET seq = ?, chain_id = ?, hash_version = 1
                    WHERE id = ?
                    """,
                    (next_seq, self._chain_id, row["id"]),
                )
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS audit_events_seq_uq ON audit_events(seq)"
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def record(
        self,
        *,
        correlation_id: str,
        server: str,
        tool: str,
        allowed: bool,
        rule: str,
        reason: str,
        arguments: Any,
        result: Any,
        duration_ms: float,
        action: str = "ALLOW",
        evidence: list[str] | None = None,
    ) -> None:
        with self._lock:
            created_at = dt.datetime.now(dt.UTC).isoformat()
            rounded_duration = round(float(duration_ms), 3)
            evidence = list(evidence or [])
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                head = self._connection.execute(
                    "SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = int(head["seq"]) + 1 if head else 1
                previous_hash = str(head["event_hash"] or "") if head else ""
                event = {
                    "event_version": 2,
                    "hash_version": 2,
                    "chain_id": self._chain_id,
                    "seq": seq,
                    "created_at": created_at,
                    "correlation_id": correlation_id,
                    "server": server,
                    "tool": tool,
                    "allowed": bool(allowed),
                    "rule": rule,
                    "reason": reason,
                    "arguments": arguments,
                    "result": result,
                    "duration_ms": rounded_duration,
                    "action": action,
                    "evidence": evidence,
                    "instance_id": self._instance_id,
                    "previous_hash": previous_hash,
                }
                event_hash = self._hash_event(event)
                signature = self._sign(event_hash)
                self._connection.execute(
                    """
                    INSERT INTO audit_events (
                        created_at, correlation_id, server, tool, allowed, rule,
                        reason, arguments_json, result_json, duration_ms, action,
                        previous_hash, event_hash, signature, instance_id,
                        event_version, evidence_json, seq, chain_id, hash_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        created_at,
                        correlation_id,
                        server,
                        tool,
                        int(allowed),
                        rule,
                        reason,
                        json.dumps(arguments, sort_keys=True),
                        json.dumps(result, sort_keys=True) if result is not None else None,
                        rounded_duration,
                        action,
                        previous_hash,
                        event_hash,
                        signature,
                        self._instance_id,
                        2,
                        json.dumps(evidence, sort_keys=True),
                        seq,
                        self._chain_id,
                        2,
                    ),
                )
                self._maybe_checkpoint(seq, event_hash, created_at=created_at)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            envelope = {**event, "event_hash": event_hash, "signature": signature}
            try:
                self._sink.write(envelope)
            except Exception:
                if self._sink_strict:
                    raise

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["allowed"] = bool(event["allowed"])
            event["arguments"] = json.loads(event.pop("arguments_json"))
            raw_result = event.pop("result_json")
            event["result"] = json.loads(raw_result) if raw_result is not None else None
            event["evidence"] = json.loads(event.pop("evidence_json"))
            events.append(event)
        return events

    def verify_chain(self, checkpoint: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            rows = self._connection.execute("SELECT * FROM audit_events ORDER BY seq ASC")
            previous_seq = 0
            previous_hash = ""
            checked = 0
            legacy = 0
            errors: list[dict[str, Any]] = []
            for row in rows:
                seq = int(row["seq"])
                if seq != previous_seq + 1:
                    errors.append({"id": row["id"], "seq": seq, "error": "sequence_gap"})
                if str(row["chain_id"] or "") != self._chain_id:
                    errors.append({"id": row["id"], "seq": seq, "error": "chain_id_mismatch"})
                previous_seq = seq
                event_hash = str(row["event_hash"] or "")
                if not event_hash:
                    legacy += 1
                    if self._signature_required:
                        errors.append({"id": row["id"], "seq": seq, "error": "legacy_unsigned_event"})
                    continue
                try:
                    event = self._row_hash_payload(row)
                except (json.JSONDecodeError, TypeError, ValueError):
                    errors.append({"id": row["id"], "seq": seq, "error": "malformed_event_payload"})
                    signature = str(row["signature"] or "")
                    if self._signing_secret and not hmac.compare_digest(
                        self._sign(event_hash), signature
                    ):
                        errors.append({"id": row["id"], "seq": seq, "error": "signature_mismatch"})
                    previous_hash = event_hash
                    checked += 1
                    continue
                if event["previous_hash"] != previous_hash:
                    errors.append({"id": row["id"], "seq": seq, "error": "previous_hash_mismatch"})
                expected = self._hash_event(event)
                if not hmac.compare_digest(expected, event_hash):
                    errors.append({"id": row["id"], "seq": seq, "error": "event_hash_mismatch"})
                signature = str(row["signature"] or "")
                if self._signing_secret and not hmac.compare_digest(self._sign(event_hash), signature):
                    errors.append({"id": row["id"], "seq": seq, "error": "signature_mismatch"})
                previous_hash = event_hash
                checked += 1
            checkpoints = self._load_checkpoints()
            if checkpoint is not None:
                checkpoints.append(checkpoint)
            for item in checkpoints:
                checkpoint_error = self._checkpoint_error(item, previous_seq, previous_hash)
                if checkpoint_error:
                    errors.append(checkpoint_error)
        return {
            "valid": not errors,
            "checked_events": checked,
            "legacy_unsealed_events": legacy,
            "head_hash": previous_hash,
            "head_seq": previous_seq,
            "chain_id": self._chain_id,
            "signed": bool(self._signing_secret),
            "signature_required": self._signature_required,
            "sink": self._sink.name,
            "checkpoints_verified": len(checkpoints),
            "checkpoint_limitation": CHECKPOINT_LIMITATION,
            "errors": errors,
        }

    def latest_checkpoint(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM audit_checkpoints ORDER BY seq DESC, id DESC LIMIT 1"
            ).fetchone()
            return self._checkpoint_from_row(row) if row else None

    def export_checkpoint(self, path: Path) -> dict[str, Any]:
        checkpoint = self.latest_checkpoint()
        if checkpoint is None:
            raise RuntimeError("the audit chain has no checkpoint to export")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n")
        return checkpoint

    def _maybe_checkpoint(
        self,
        seq: int,
        head_hash: str,
        *,
        created_at: str | None = None,
        force: bool = False,
    ) -> dict[str, Any] | None:
        latest = self._connection.execute(
            "SELECT * FROM audit_checkpoints ORDER BY seq DESC, id DESC LIMIT 1"
        ).fetchone()
        now = dt.datetime.now(dt.UTC)
        should_write = force or latest is None
        if latest is not None:
            last_time = dt.datetime.fromisoformat(str(latest["created_at"]))
            should_write = should_write or seq - int(latest["seq"]) >= self._checkpoint_events
            should_write = should_write or (now - last_time).total_seconds() >= self._checkpoint_seconds
        if not should_write:
            return None
        checkpoint = {
            "chain_id": self._chain_id,
            "seq": seq,
            "head_hash": head_hash,
            "created_at": created_at or now.isoformat(),
        }
        checkpoint["signature"] = self._sign_checkpoint(checkpoint)
        self._connection.execute(
            """
            INSERT INTO audit_checkpoints (
                chain_id, seq, head_hash, created_at, signature
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(chain_id, seq) DO NOTHING
            """,
            (
                checkpoint["chain_id"],
                checkpoint["seq"],
                checkpoint["head_hash"],
                checkpoint["created_at"],
                checkpoint["signature"],
            ),
        )
        return checkpoint

    def _load_checkpoints(self) -> list[dict[str, Any]]:
        return [
            self._checkpoint_from_row(row)
            for row in self._connection.execute(
                "SELECT * FROM audit_checkpoints ORDER BY seq ASC, id ASC"
            )
        ]

    @staticmethod
    def _checkpoint_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "chain_id": str(row["chain_id"]),
            "seq": int(row["seq"]),
            "head_hash": str(row["head_hash"]),
            "created_at": str(row["created_at"]),
            "signature": str(row["signature"]),
        }

    def _checkpoint_error(
        self,
        checkpoint: dict[str, Any],
        head_seq: int,
        head_hash: str,
    ) -> dict[str, Any] | None:
        try:
            normalized = {
                "chain_id": str(checkpoint["chain_id"]),
                "seq": int(checkpoint["seq"]),
                "head_hash": str(checkpoint["head_hash"]),
                "created_at": str(checkpoint["created_at"]),
            }
            signature = str(checkpoint["signature"])
        except (KeyError, TypeError, ValueError):
            return {"error": "malformed_checkpoint"}
        if normalized["chain_id"] != self._chain_id:
            return {"seq": normalized["seq"], "error": "checkpoint_chain_id_mismatch"}
        if not hmac.compare_digest(self._sign_checkpoint(normalized), signature):
            return {"seq": normalized["seq"], "error": "checkpoint_signature_mismatch"}
        if head_seq < normalized["seq"]:
            return {
                "seq": normalized["seq"],
                "head_seq": head_seq,
                "error": "truncated",
            }
        if head_seq == normalized["seq"] and head_hash != normalized["head_hash"]:
            return {"seq": normalized["seq"], "error": "checkpoint_head_mismatch"}
        row = self._connection.execute(
            "SELECT event_hash FROM audit_events WHERE seq = ?",
            (normalized["seq"],),
        ).fetchone()
        if row is None:
            return {"seq": normalized["seq"], "error": "truncated"}
        if str(row["event_hash"] or "") != normalized["head_hash"]:
            return {"seq": normalized["seq"], "error": "checkpoint_head_mismatch"}
        return None

    def _row_hash_payload(self, row: sqlite3.Row) -> dict[str, Any]:
        event = {
            "created_at": row["created_at"],
            "correlation_id": row["correlation_id"],
            "server": row["server"],
            "tool": row["tool"],
            "allowed": bool(row["allowed"]),
            "rule": row["rule"],
            "reason": row["reason"],
            "arguments": json.loads(row["arguments_json"]),
            "result": json.loads(row["result_json"]) if row["result_json"] is not None else None,
            "duration_ms": float(row["duration_ms"]),
            "action": row["action"],
            "instance_id": row["instance_id"],
            "previous_hash": row["previous_hash"],
        }
        if int(row["event_version"]) >= 2:
            event["event_version"] = int(row["event_version"])
            event["evidence"] = json.loads(row["evidence_json"])
        if int(row["hash_version"] or 1) >= 2:
            event["hash_version"] = int(row["hash_version"])
            event["chain_id"] = str(row["chain_id"])
            event["seq"] = int(row["seq"])
        return event

    @staticmethod
    def _hash_event(event: dict[str, Any]) -> str:
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _sign(self, event_hash: str) -> str:
        return hmac.new(self._signing_secret.encode(), event_hash.encode(), hashlib.sha256).hexdigest()

    def _sign_checkpoint(self, checkpoint: dict[str, Any]) -> str:
        payload = {
            key: checkpoint[key]
            for key in ("chain_id", "seq", "head_hash", "created_at")
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hmac.new(
            self._signing_secret.encode(), canonical.encode(), hashlib.sha256
        ).hexdigest()

    def close(self) -> None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                head = self._connection.execute(
                    "SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if head is not None:
                    self._maybe_checkpoint(
                        int(head["seq"]),
                        str(head["event_hash"] or ""),
                        force=True,
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            self._connection.close()


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}


def resolve_audit_secret(*, require_configured: bool = False) -> str:
    configured = resolve_configured_secret(
        direct_env="JUDIKT_AUDIT_HMAC_SECRET",
        aws_secret_env="JUDIKT_AUDIT_HMAC_SECRET_ARN",
        vault_path_env="JUDIKT_AUDIT_HMAC_SECRET_VAULT_PATH",
        json_key_env="JUDIKT_AUDIT_HMAC_SECRET_JSON_KEY",
        description="audit HMAC secret",
    )
    if not configured and (require_configured or _enabled("JUDIKT_PRODUCTION")):
        raise AuditConfigurationError(
            "remote or production mode requires a configured shared audit HMAC secret via "
            "JUDIKT_AUDIT_HMAC_SECRET, JUDIKT_AUDIT_HMAC_SECRET_ARN, or "
            "JUDIKT_AUDIT_HMAC_SECRET_VAULT_PATH"
        )
    value = configured or _read_or_create_audit_key(state_root())
    if len(value.encode()) < MINIMUM_AUDIT_SECRET_BYTES:
        raise AuditConfigurationError(
            f"audit HMAC secret must be at least {MINIMUM_AUDIT_SECRET_BYTES} bytes"
        )
    return value


def _read_or_create_audit_key(directory: Path) -> str:
    ensure_private_directory(directory)
    path = directory / "audit.key"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _read_audit_key(path)
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


def _read_audit_key(path: Path) -> str:
    for _ in range(100):
        metadata = path.stat()
        if metadata.st_uid != os.getuid():
            raise AuditConfigurationError(
                f"audit key {path} is not owned by the current user; fix ownership and run: chmod 600 {path}"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AuditConfigurationError(
                f"audit key {path} must not be group- or world-readable; run: chmod 600 {path}"
            )
        value = path.read_text().strip()
        if value:
            return value
        time.sleep(0.01)
    raise AuditConfigurationError(f"audit key {path} was created but remained empty")


def load_checkpoint(value: str) -> dict[str, Any]:
    if value.startswith("s3://"):
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional AWS path
            raise RuntimeError("S3 checkpoints require the optional aws dependencies") from exc
        bucket, separator, key = value[5:].partition("/")
        if not separator or not bucket or not key:
            raise RuntimeError("checkpoint S3 URI must be s3://bucket/key")
        response = boto3.client("s3").get_object(Bucket=bucket, Key=key)
        raw = response["Body"].read()
        checkpoint = json.loads(raw)
    else:
        checkpoint = json.loads(Path(value).read_text())
    if not isinstance(checkpoint, dict):
        raise RuntimeError("checkpoint must contain one JSON object")
    return checkpoint


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise AuditConfigurationError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise AuditConfigurationError(f"{name} must be a positive integer")
    return value


def _positive_float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise AuditConfigurationError(f"{name} must be a positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise AuditConfigurationError(f"{name} must be a positive number")
    return value
