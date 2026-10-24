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
import sys
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
    def __init__(
        self,
        path: Path,
        *,
        require_configured_key: bool = False,
        backpressure: dict[str, Any] | None = None,
        metrics: Any = None,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._signing_secret = resolve_audit_secret(
            require_configured=require_configured_key,
        )
        self._signature_required = True
        self._checkpoint_events = _positive_int_env("JUDIKT_AUDIT_CHECKPOINT_EVENTS", 100)
        self._checkpoint_seconds = _positive_float_env("JUDIKT_AUDIT_CHECKPOINT_SECONDS", 60.0)
        self._retry_interval = _positive_float_env("JUDIKT_AUDIT_RETRY_INTERVAL_SECONDS", 5.0)
        self._retry_base = _positive_float_env("JUDIKT_AUDIT_RETRY_BASE_SECONDS", 1.0)
        self._metrics = metrics
        self._production = require_configured_key or _enabled("JUDIKT_PRODUCTION")
        self._backpressure = _normalize_backpressure(backpressure, self._production)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.Lock()
        self._instance_id = os.getenv("JUDIKT_INSTANCE_ID", "local")
        self._sink_strict = os.getenv("JUDIKT_AUDIT_SINK_STRICT", "").lower() in {"1", "true", "yes"}
        self._sink = build_audit_sink(path.with_suffix(".audit.jsonl"))
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self.startup_integrity_failure: dict[str, Any] | None = None
        self._initialize_schema()
        if _enabled_default("JUDIKT_AUDIT_VERIFY_ON_STARTUP", True):
            report = self.verify_chain(full=False)
            if not report["valid"]:
                if self._production:
                    self._connection.close()
                    raise RuntimeError(
                        "audit integrity verification failed at startup: "
                        + json.dumps(report["errors"], separators=(",", ":"))
                    )
                self.startup_integrity_failure = report
                print(
                    "WARNING: Judikt audit integrity verification failed at startup: "
                    + json.dumps(report["errors"], separators=(",", ":")),
                    file=sys.stderr,
                )
        if self._sink.name != "none":
            self._worker = threading.Thread(
                target=self._retry_loop,
                name="judikt-audit-outbox",
                daemon=True,
            )
            self._worker.start()
        self._update_delivery_metrics()

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
            self._ensure_column("diagnostic", "TEXT")
            self._ensure_column("control_arguments_stripped", "INTEGER")
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
                """
                CREATE TABLE IF NOT EXISTS audit_outbox (
                    chain_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    lease_until REAL NOT NULL DEFAULT 0,
                    delivered_at TEXT,
                    last_error_hash TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(chain_id, seq, record_type)
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_outbox_delivery
                ON audit_outbox(delivered_at, next_attempt_at, lease_until)
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
        diagnostic: str | None = None,
        control_arguments_stripped: bool | None = None,
    ) -> int:
        """Append one hash-chained, signed audit event.

        ``diagnostic`` is operator-only detail about an upstream failure. Callers
        must redact it first; it is never returned to agents.
        ``control_arguments_stripped`` records that Judikt-owned arguments such
        as ``approval_token`` were withheld from the upstream.
        """
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
                if diagnostic is not None:
                    event["diagnostic"] = diagnostic
                if control_arguments_stripped is not None:
                    event["control_arguments_stripped"] = bool(control_arguments_stripped)
                event_hash = self._hash_event(event)
                signature = self._sign(event_hash)
                self._connection.execute(
                    """
                    INSERT INTO audit_events (
                        created_at, correlation_id, server, tool, allowed, rule,
                        reason, arguments_json, result_json, duration_ms, action,
                        previous_hash, event_hash, signature, instance_id,
                        event_version, evidence_json, seq, chain_id, hash_version,
                        diagnostic, control_arguments_stripped
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        diagnostic,
                        (
                            int(bool(control_arguments_stripped))
                            if control_arguments_stripped is not None
                            else None
                        ),
                    ),
                )
                envelope = {**event, "event_hash": event_hash, "signature": signature}
                self._enqueue_outbox(seq, "event", created_at, envelope)
                self._maybe_checkpoint(seq, event_hash, created_at=created_at)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        _, failed = self.flush_outbox(limit=1)
        if failed and self._sink_strict:
            raise RuntimeError("audit sink delivery failed; event remains in the durable outbox")
        return seq

    def record_intent(
        self,
        *,
        correlation_id: str,
        server: str,
        tool: str,
        arguments: Any,
    ) -> int:
        arguments_digest = hashlib.sha256(
            json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        return self.record(
            correlation_id=correlation_id,
            server=server,
            tool=tool,
            allowed=True,
            rule="execution_started",
            reason="upstream tool execution started",
            arguments={"redacted_arguments_sha256": arguments_digest},
            result=None,
            duration_ms=0,
            action="EXECUTION_STARTED",
            evidence=["intent"],
        )

    def recent(self, limit: int = 100, *, include_intents: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            where = "" if include_intents else "WHERE rule != 'execution_started'"
            rows = self._connection.execute(
                f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["allowed"] = bool(event["allowed"])
            if event.get("control_arguments_stripped") is not None:
                event["control_arguments_stripped"] = bool(event["control_arguments_stripped"])
            event["arguments"] = json.loads(event.pop("arguments_json"))
            raw_result = event.pop("result_json")
            event["result"] = json.loads(raw_result) if raw_result is not None else None
            event["evidence"] = json.loads(event.pop("evidence_json"))
            events.append(event)
        return events

    def verify_chain(
        self,
        checkpoint: dict[str, Any] | None = None,
        *,
        full: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            checkpoints = self._load_checkpoints()
            start_checkpoint = None if full else self._last_verified_checkpoint(checkpoints)
            previous_seq = int(start_checkpoint["seq"]) if start_checkpoint else 0
            previous_hash = str(start_checkpoint["head_hash"]) if start_checkpoint else ""
            rows = self._connection.execute(
                "SELECT * FROM audit_events WHERE seq > ? ORDER BY seq ASC",
                (previous_seq,),
            )
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
            if checkpoint is not None:
                checkpoints.append(checkpoint)
            for item in checkpoints:
                checkpoint_error = self._checkpoint_error(item, previous_seq, previous_hash)
                if checkpoint_error:
                    errors.append(checkpoint_error)
            incomplete_intents = self._incomplete_intents()
            if not errors and checkpoints:
                latest = checkpoints[-1]
                self._connection.execute(
                    "INSERT OR REPLACE INTO audit_meta (key, value) VALUES ('verified_checkpoint_seq', ?)",
                    (str(latest["seq"]),),
                )
                self._connection.execute(
                    "INSERT OR REPLACE INTO audit_meta (key, value) VALUES ('verified_checkpoint_hash', ?)",
                    (str(latest["head_hash"]),),
                )
                self._connection.commit()
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
            "verification_mode": "full" if full else "incremental",
            "verified_from_checkpoint_seq": int(start_checkpoint["seq"]) if start_checkpoint else 0,
            "incomplete_intents": incomplete_intents,
            "status": "tampered" if errors else ("incomplete" if incomplete_intents else "valid"),
            "checkpoint_limitation": CHECKPOINT_LIMITATION,
            "errors": errors,
        }

    def latest_checkpoint(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM audit_checkpoints ORDER BY seq DESC, id DESC LIMIT 1"
            ).fetchone()
            return self._checkpoint_from_row(row) if row else None

    def checkpoint_now(self) -> dict[str, Any]:
        """Force a signed checkpoint at the current chain head and return it.

        Uses the same transaction rules as event recording, so it cannot race
        a concurrent append. Re-running at an unchanged head returns the
        stored checkpoint for that sequence number.
        """

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                head = self._connection.execute(
                    "SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if head is None:
                    raise RuntimeError("the audit chain has no events to checkpoint")
                self._maybe_checkpoint(
                    int(head["seq"]),
                    str(head["event_hash"] or ""),
                    force=True,
                )
                row = self._connection.execute(
                    "SELECT * FROM audit_checkpoints WHERE chain_id = ? AND seq = ?",
                    (self._chain_id, int(head["seq"])),
                ).fetchone()
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        self.flush_outbox(limit=1)
        return self._checkpoint_from_row(row)

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
        cursor = self._connection.execute(
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
        if cursor.rowcount:
            self._enqueue_outbox(
                seq,
                "checkpoint",
                str(checkpoint["created_at"]),
                {"record_type": "checkpoint", **checkpoint},
            )
        return checkpoint

    def _enqueue_outbox(
        self,
        seq: int,
        record_type: str,
        created_at: str,
        payload: dict[str, Any],
    ) -> None:
        if self._sink.name == "none":
            return
        self._connection.execute(
            """
            INSERT OR IGNORE INTO audit_outbox (
                chain_id, seq, record_type, created_at, payload_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                self._chain_id,
                seq,
                record_type,
                created_at,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
            ),
        )

    def flush_outbox(self, limit: int = 100, *, force: bool = False) -> tuple[int, int]:
        if self._sink.name == "none" or limit <= 0:
            return 0, 0
        now = time.time()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                condition = "delivered_at IS NULL AND lease_until <= ?"
                parameters: list[Any] = [now]
                if not force:
                    condition += " AND next_attempt_at <= ?"
                    parameters.append(now)
                parameters.append(limit)
                rows = self._connection.execute(
                    f"SELECT * FROM audit_outbox WHERE {condition} "
                    "ORDER BY seq ASC, CASE record_type WHEN 'event' THEN 0 ELSE 1 END LIMIT ?",
                    parameters,
                ).fetchall()
                lease_until = now + 30
                for row in rows:
                    self._connection.execute(
                        """
                        UPDATE audit_outbox SET lease_until = ?
                        WHERE chain_id = ? AND seq = ? AND record_type = ?
                        """,
                        (lease_until, row["chain_id"], row["seq"], row["record_type"]),
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        delivered = 0
        failed = 0
        for row in rows:
            try:
                self._sink.write(json.loads(row["payload_json"]))
            except Exception as exc:
                failed += 1
                attempts = int(row["attempts"]) + 1
                retry_at = now + min(
                    300, self._retry_base * (2 ** min(attempts - 1, 8))
                )
                error_hash = hashlib.sha256(
                    f"{exc.__class__.__name__}:{exc}".encode()
                ).hexdigest()
                with self._lock:
                    self._connection.execute(
                        """
                        UPDATE audit_outbox
                        SET attempts = ?, next_attempt_at = ?, lease_until = 0,
                            last_error_hash = ?
                        WHERE chain_id = ? AND seq = ? AND record_type = ?
                        """,
                        (
                            attempts,
                            retry_at,
                            error_hash,
                            row["chain_id"],
                            row["seq"],
                            row["record_type"],
                        ),
                    )
                    self._connection.commit()
                if self._metrics is not None:
                    self._metrics.observe_audit_delivery_failure()
            else:
                delivered += 1
                with self._lock:
                    self._connection.execute(
                        """
                        UPDATE audit_outbox
                        SET attempts = attempts + 1, delivered_at = ?, lease_until = 0,
                            last_error_hash = ''
                        WHERE chain_id = ? AND seq = ? AND record_type = ?
                        """,
                        (
                            dt.datetime.now(dt.UTC).isoformat(),
                            row["chain_id"],
                            row["seq"],
                            row["record_type"],
                        ),
                    )
                    self._connection.commit()
        self._update_delivery_metrics()
        return delivered, failed

    def outbox_status(self) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    SUM(CASE WHEN delivered_at IS NULL THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN delivered_at IS NOT NULL THEN 1 ELSE 0 END) AS delivered,
                    MIN(CASE WHEN delivered_at IS NULL THEN created_at END) AS oldest
                FROM audit_outbox
                """
            ).fetchone()
        pending = int(row["pending"] or 0)
        oldest_age = 0.0
        if row["oldest"]:
            oldest = dt.datetime.fromisoformat(str(row["oldest"]))
            oldest_age = max(0.0, (dt.datetime.now(dt.UTC) - oldest).total_seconds())
        return {
            "enabled": self._sink.name != "none",
            "sink": self._sink.name,
            "pending": pending,
            "delivered": int(row["delivered"] or 0),
            "oldest_age_seconds": round(oldest_age, 3),
            "backpressure": dict(self._backpressure),
            "backpressure_exceeded": self._backpressure_exceeded(pending, oldest_age),
        }

    def reconcile(self, limit: int = 1000) -> dict[str, Any]:
        delivered, failed = self.flush_outbox(limit=limit, force=True)
        return {"delivered_now": delivered, "failed_now": failed, **self.outbox_status()}

    def deny_for_backpressure(self) -> bool:
        status = self.outbox_status()
        return bool(
            self._backpressure["mode"] == "deny" and status["backpressure_exceeded"]
        )

    def _backpressure_exceeded(self, pending: int, oldest_age: float) -> bool:
        return pending >= int(self._backpressure["max_pending"]) or (
            pending > 0 and oldest_age >= float(self._backpressure["max_age_seconds"])
        )

    def _update_delivery_metrics(self) -> None:
        if self._metrics is None:
            return
        status = self.outbox_status()
        self._metrics.set_audit_outbox(
            int(status["pending"]), float(status["oldest_age_seconds"])
        )

    def _retry_loop(self) -> None:
        while not self._stop.wait(self._retry_interval):
            self.flush_outbox()

    def _load_checkpoints(self) -> list[dict[str, Any]]:
        return [
            self._checkpoint_from_row(row)
            for row in self._connection.execute(
                "SELECT * FROM audit_checkpoints ORDER BY seq ASC, id ASC"
            )
        ]

    def _last_verified_checkpoint(
        self,
        checkpoints: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        values = {
            str(row["key"]): str(row["value"])
            for row in self._connection.execute(
                "SELECT key, value FROM audit_meta WHERE key IN "
                "('verified_checkpoint_seq', 'verified_checkpoint_hash')"
            )
        }
        try:
            verified_seq = int(values["verified_checkpoint_seq"])
            verified_hash = values["verified_checkpoint_hash"]
        except (KeyError, ValueError):
            return None
        for checkpoint in checkpoints:
            if (
                int(checkpoint["seq"]) == verified_seq
                and str(checkpoint["head_hash"]) == verified_hash
                and self._checkpoint_error(checkpoint, verified_seq, verified_hash) is None
            ):
                return checkpoint
        return None

    def _incomplete_intents(self) -> list[dict[str, Any]]:
        intents: dict[int, dict[str, Any]] = {}
        for row in self._connection.execute(
            "SELECT seq, correlation_id, server, tool, rule, evidence_json "
            "FROM audit_events ORDER BY seq"
        ):
            seq = int(row["seq"])
            if row["rule"] == "execution_started":
                intents[seq] = {
                    "seq": seq,
                    "correlation_id": str(row["correlation_id"]),
                    "server": str(row["server"]),
                    "tool": str(row["tool"]),
                }
            try:
                evidence = json.loads(row["evidence_json"])
            except (json.JSONDecodeError, TypeError):
                continue
            for marker in evidence:
                if isinstance(marker, str) and marker.startswith("intent_seq:"):
                    try:
                        intents.pop(int(marker.partition(":")[2]), None)
                    except ValueError:
                        continue
        return list(intents.values())

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
            "SELECT * FROM audit_events WHERE seq = ?",
            (normalized["seq"],),
        ).fetchone()
        if row is None:
            return {"seq": normalized["seq"], "error": "truncated"}
        if str(row["event_hash"] or "") != normalized["head_hash"]:
            return {"seq": normalized["seq"], "error": "checkpoint_head_mismatch"}
        try:
            expected = self._hash_event(self._row_hash_payload(row))
        except (json.JSONDecodeError, TypeError, ValueError):
            return {"seq": normalized["seq"], "error": "malformed_event_payload"}
        if not hmac.compare_digest(expected, normalized["head_hash"]):
            return {"seq": normalized["seq"], "error": "checkpoint_event_mismatch"}
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
        if row["diagnostic"] is not None:
            event["diagnostic"] = row["diagnostic"]
        if row["control_arguments_stripped"] is not None:
            event["control_arguments_stripped"] = bool(row["control_arguments_stripped"])
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

    @property
    def signing_secret(self) -> str:
        """The resolved audit HMAC key, for startup independence checks only."""
        return self._signing_secret

    def close(self) -> None:
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=5)
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
        self.flush_outbox(force=True)
        self._connection.close()


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}


def _enabled_default(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.lower() in {"1", "true", "yes"}


def _normalize_backpressure(
    configured: dict[str, Any] | None,
    production: bool,
) -> dict[str, Any]:
    value = configured or {}
    if not isinstance(value, dict):
        raise AuditConfigurationError("audit.backpressure must be an object")
    try:
        max_pending = int(value.get("max_pending", 10000))
        max_age_seconds = float(value.get("max_age_seconds", 300))
    except (TypeError, ValueError) as exc:
        raise AuditConfigurationError(
            "audit.backpressure limits must be positive numbers"
        ) from exc
    mode = str(value.get("mode", "deny" if production else "warn"))
    if max_pending <= 0 or not math.isfinite(max_age_seconds) or max_age_seconds <= 0:
        raise AuditConfigurationError("audit.backpressure limits must be positive numbers")
    if mode not in {"warn", "deny"}:
        raise AuditConfigurationError("audit.backpressure.mode must be warn or deny")
    return {
        "max_pending": max_pending,
        "max_age_seconds": max_age_seconds,
        "mode": mode,
    }


def ensure_independent_audit_key(approval_secret: bytes, audit: "AuditStore") -> None:
    """Refuse a deployment whose audit key equals its approval secret.

    A shared key would let anyone who can verify audit signatures mint
    approval tokens.
    """
    if hmac.compare_digest(approval_secret, audit.signing_secret.encode()):
        raise AuditConfigurationError(
            "JUDIKT_AUDIT_HMAC_SECRET must be independent from JUDIKT_APPROVAL_SECRET"
        )


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


def write_checkpoint(checkpoint: dict[str, Any], destination: str) -> None:
    """Write a signed checkpoint to a local file or ``s3://bucket/key``."""

    rendered = json.dumps(checkpoint, indent=2, sort_keys=True) + "\n"
    if not destination.startswith("s3://"):
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered)
        return
    bucket, separator, key = destination[5:].partition("/")
    if not separator or not bucket or not key:
        raise RuntimeError("checkpoint S3 URI must be s3://bucket/key")
    try:
        import boto3
        from botocore.exceptions import (
            BotoCoreError,
            ClientError,
            NoCredentialsError,
            PartialCredentialsError,
            ProfileNotFound,
        )
    except ImportError as exc:
        raise RuntimeError(
            "S3 checkpoints require boto3; install the optional aws dependencies "
            "with: python3 -m pip install 'judikt[aws]'"
        ) from exc
    try:
        boto3.client("s3").put_object(
            Bucket=bucket,
            Key=key,
            Body=rendered.encode(),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
    except (NoCredentialsError, PartialCredentialsError, ProfileNotFound) as exc:
        raise RuntimeError(
            "AWS credentials are not configured; cannot write the checkpoint to S3"
        ) from exc
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(
            f"could not write the checkpoint to {destination}: {exc.__class__.__name__}"
        ) from exc


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
