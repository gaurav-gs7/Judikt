from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from .audit_sink import build_audit_sink
from .secrets import resolve_configured_secret


class AuditStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._signing_secret = resolve_configured_secret(
            direct_env="JUDIKT_AUDIT_HMAC_SECRET",
            aws_secret_env="JUDIKT_AUDIT_HMAC_SECRET_ARN",
            vault_path_env="JUDIKT_AUDIT_HMAC_SECRET_VAULT_PATH",
            json_key_env="JUDIKT_AUDIT_HMAC_SECRET_JSON_KEY",
            description="audit HMAC secret",
        )
        self._signature_required = _enabled("JUDIKT_AUDIT_SIGNATURE_REQUIRED")
        if self._signature_required and not self._signing_secret:
            raise RuntimeError(
                "JUDIKT_AUDIT_SIGNATURE_REQUIRED=true requires JUDIKT_AUDIT_HMAC_SECRET "
                "or a brokered audit HMAC secret"
            )
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

    def verify_chain(self) -> dict[str, Any]:
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
            "errors": errors,
        }

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
        if not self._signing_secret:
            return ""
        return hmac.new(self._signing_secret.encode(), event_hash.encode(), hashlib.sha256).hexdigest()

    def close(self) -> None:
        self._connection.close()


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}
