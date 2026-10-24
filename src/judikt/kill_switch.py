from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Protocol

from .audit import AuditStore
from .metrics import Metrics
from .paths import ensure_private_directory, state_root


class KillSwitchStoreError(RuntimeError):
    pass


class KillSwitchConfigurationError(KillSwitchStoreError, ValueError):
    """The kill-switch store cannot be built from the configured settings."""


class KillSwitchUnavailable(KillSwitchStoreError):
    pass


class KillSwitchStore(Protocol):
    def get_state(self) -> dict[str, Any]: ...

    def set(
        self,
        scope: str,
        name: str,
        enabled: bool,
        actor: str,
        reason: str,
    ) -> int: ...

    def close(self) -> None: ...


class SQLiteKillSwitchStore:
    def __init__(self, path: Path | None = None) -> None:
        configured = path or _configured_sqlite_path()
        if configured is None:
            self.path = state_root() / "control.db"
            ensure_private_directory(self.path.parent)
        else:
            self.path = configured
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.path,
            timeout=5,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS kill_switches (
                scope TEXT NOT NULL,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                updated_at REAL NOT NULL,
                version INTEGER NOT NULL,
                PRIMARY KEY (scope, name)
            );
            CREATE TABLE IF NOT EXISTS control_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO control_metadata(singleton, version) VALUES (1, 0);
            """
        )
        self._connection.commit()
        self._lock = threading.Lock()

    def get_state(self) -> dict[str, Any]:
        try:
            with self._lock:
                rows = self._connection.execute(
                    "SELECT scope, name FROM kill_switches WHERE enabled = 0"
                ).fetchall()
                version = int(
                    self._connection.execute(
                        "SELECT version FROM control_metadata WHERE singleton = 1"
                    ).fetchone()["version"]
                )
        except sqlite3.Error as exc:
            raise KillSwitchStoreError("SQLite kill-switch store is unavailable") from exc
        return {
            "tools": {row["name"] for row in rows if row["scope"] == "tool"},
            "servers": {row["name"] for row in rows if row["scope"] == "server"},
            "version": version,
        }

    def set(
        self,
        scope: str,
        name: str,
        enabled: bool,
        actor: str,
        reason: str,
    ) -> int:
        _validate_change(scope, name, enabled, actor, reason)
        try:
            with self._lock:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "UPDATE control_metadata SET version = version + 1 "
                    "WHERE singleton = 1 RETURNING version"
                ).fetchone()
                version = int(row["version"])
                self._connection.execute(
                    """
                    INSERT INTO kill_switches(
                        scope, name, enabled, actor, reason, updated_at, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scope, name) DO UPDATE SET
                        enabled = excluded.enabled,
                        actor = excluded.actor,
                        reason = excluded.reason,
                        updated_at = excluded.updated_at,
                        version = excluded.version
                    """,
                    (scope, name, int(enabled), actor, reason, time.time(), version),
                )
                self._connection.commit()
                return version
        except sqlite3.Error as exc:
            self._connection.rollback()
            raise KillSwitchStoreError("SQLite kill-switch update failed") from exc

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class RedisKillSwitchStore:
    _SET_SCRIPT = """
local version = redis.call('INCR', KEYS[2])
local field = ARGV[1] .. ':' .. ARGV[2]
redis.call('HSET', KEYS[1], field, cjson.encode({
  enabled = ARGV[3] == '1',
  actor = ARGV[4],
  reason = ARGV[5],
  version = version
}))
return version
"""

    def __init__(self, redis_url: str, prefix: str = "judikt:kill-switch") -> None:
        if not redis_url:
            raise KillSwitchConfigurationError("Redis kill-switch storage requires a Redis URL")
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Redis kill-switch storage requires optional redis dependency"
            ) from exc
        self._redis_module = redis
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._state_key = f"{prefix}:state"
        self._version_key = f"{prefix}:version"
        try:
            self._client.ping()
        except redis.RedisError as exc:
            raise KillSwitchStoreError("Redis kill-switch store is unavailable") from exc

    def get_state(self) -> dict[str, Any]:
        try:
            values = self._client.hgetall(self._state_key)
            version = int(self._client.get(self._version_key) or 0)
        except self._redis_module.RedisError as exc:
            raise KillSwitchStoreError("Redis kill-switch store is unavailable") from exc
        tools: set[str] = set()
        servers: set[str] = set()
        for field, encoded in values.items():
            try:
                scope, name = field.split(":", 1)
                value = json.loads(encoded)
            except (ValueError, json.JSONDecodeError, TypeError) as exc:
                raise KillSwitchStoreError(
                    "Redis kill-switch state is malformed"
                ) from exc
            if value.get("enabled") is False:
                (tools if scope == "tool" else servers).add(name)
        return {"tools": tools, "servers": servers, "version": version}

    def set(
        self,
        scope: str,
        name: str,
        enabled: bool,
        actor: str,
        reason: str,
    ) -> int:
        _validate_change(scope, name, enabled, actor, reason)
        try:
            return int(
                self._client.eval(
                    self._SET_SCRIPT,
                    2,
                    self._state_key,
                    self._version_key,
                    scope,
                    name,
                    "1" if enabled else "0",
                    actor,
                    reason,
                )
            )
        except self._redis_module.RedisError as exc:
            raise KillSwitchStoreError("Redis kill-switch update failed") from exc

    def close(self) -> None:
        self._client.close()


class DynamoDBKillSwitchStore:
    """DynamoDB adapter using the serverless KILL_SWITCH partition layout."""

    def __init__(self, table: Any) -> None:
        self._table = table

    def get_state(self) -> dict[str, Any]:
        if self._table is None:
            raise KillSwitchStoreError("DynamoDB kill-switch store is unavailable")
        try:
            from boto3.dynamodb.conditions import Key

            response = self._table.query(
                KeyConditionExpression=Key("pk").eq("KILL_SWITCH")
            )
        except Exception as exc:
            raise KillSwitchStoreError(
                "DynamoDB kill-switch store is unavailable"
            ) from exc
        tools: set[str] = set()
        servers: set[str] = set()
        version = 0
        for item in response.get("Items", []):
            if item.get("sk") == "VERSION":
                version = int(item.get("version", 0))
                continue
            if item.get("enabled") is not False:
                continue
            scope = item.get("target_type")
            target = item.get("target")
            if scope == "tool" and isinstance(target, str):
                tools.add(target)
            elif scope == "server" and isinstance(target, str):
                servers.add(target)
        return {"tools": tools, "servers": servers, "version": version}

    def set(
        self,
        scope: str,
        name: str,
        enabled: bool,
        actor: str,
        reason: str,
    ) -> int:
        _validate_change(scope, name, enabled, actor, reason)
        if self._table is None:
            raise KillSwitchStoreError("DynamoDB kill-switch store is unavailable")
        try:
            response = self._table.update_item(
                Key={"pk": "KILL_SWITCH", "sk": "VERSION"},
                UpdateExpression="ADD #version :one",
                ExpressionAttributeNames={"#version": "version"},
                ExpressionAttributeValues={":one": 1},
                ReturnValues="UPDATED_NEW",
            )
            version = int(response["Attributes"]["version"])
            self._table.put_item(
                Item={
                    "pk": "KILL_SWITCH",
                    "sk": f"{scope.upper()}#{name}",
                    "enabled": enabled,
                    "target": name,
                    "target_type": scope,
                    "actor": actor,
                    "reason": reason,
                    "version": version,
                    "updated_at": int(time.time()),
                }
            )
            return version
        except Exception as exc:
            raise KillSwitchStoreError("DynamoDB kill-switch update failed") from exc

    def close(self) -> None:
        return


class CachedKillSwitchStore:
    def __init__(
        self,
        store: KillSwitchStore,
        *,
        ttl_seconds: float = 1.0,
        on_store_failure: str = "last_known",
        metrics: Metrics | None = None,
        audit: AuditStore | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 <= ttl_seconds <= 1:
            raise KillSwitchConfigurationError("kill-switch cache TTL must be between 0 and 1 second")
        if on_store_failure not in {"deny", "last_known"}:
            raise KillSwitchConfigurationError(
                "kill_switches.on_store_failure must be 'deny' or 'last_known'"
            )
        self.store = store
        self.ttl_seconds = ttl_seconds
        self.on_store_failure = on_store_failure
        self.metrics = metrics
        self.audit = audit
        self._clock = clock
        self._cached = {"tools": set(), "servers": set(), "version": 0}
        self._cached_at = float("-inf")
        self._last_warning_at = float("-inf")
        self._lock = threading.Lock()

    def get_state(self) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            if now - self._cached_at <= self.ttl_seconds:
                return _copy_state(self._cached)
            try:
                self._cached = self.store.get_state()
                self._cached_at = now
                return _copy_state(self._cached)
            except Exception as exc:
                if self.metrics is not None:
                    self.metrics.observe_kill_switch_store_failure(
                        self.on_store_failure
                    )
                if self.on_store_failure == "deny":
                    raise KillSwitchUnavailable(
                        "kill-switch state is unavailable"
                    ) from exc
                if now - self._last_warning_at >= 60:
                    print(
                        "WARNING: kill-switch store unavailable; using last-known state",
                        file=sys.stderr,
                    )
                    self._last_warning_at = now
                return _copy_state(self._cached)

    def set(
        self,
        scope: str,
        name: str,
        enabled: bool,
        actor: str,
        reason: str,
    ) -> int:
        version = self.store.set(scope, name, enabled, actor, reason)
        with self._lock:
            target = self._cached["tools" if scope == "tool" else "servers"]
            if enabled:
                target.discard(name)
            else:
                target.add(name)
            self._cached["version"] = version
            self._cached_at = self._clock()
        if self.audit is not None:
            self.audit.record(
                correlation_id=f"kill-switch-{scope}-{version}",
                server="judikt",
                tool="kill_switch",
                allowed=True,
                rule="kill_switch_change",
                action="ENABLE" if enabled else "DISABLE",
                reason=reason,
                arguments={
                    "scope": scope,
                    "name": name,
                    "enabled": enabled,
                    "actor": actor,
                },
                result={"version": version},
                duration_ms=0,
                evidence=[f"kill_switch_version:{version}"],
            )
        return version

    def close(self) -> None:
        self.store.close()


def build_kill_switch_store(
    config: dict[str, Any],
    *,
    metrics: Metrics | None = None,
    audit: AuditStore | None = None,
    production: bool = False,
) -> CachedKillSwitchStore:
    configured = config.get("kill_switches", {})
    if not isinstance(configured, dict):
        raise KillSwitchConfigurationError("kill_switches policy configuration must be an object")
    backend = str(
        os.getenv("JUDIKT_KILL_SWITCH_BACKEND", configured.get("backend", "sqlite"))
    ).lower()
    if backend == "sqlite":
        store: KillSwitchStore = SQLiteKillSwitchStore()
    elif backend == "redis":
        store = RedisKillSwitchStore(os.getenv("JUDIKT_REDIS_URL", ""))
    else:
        raise KillSwitchConfigurationError("kill_switches.backend must be 'sqlite' or 'redis'")
    ttl = float(configured.get("cache_ttl_seconds", 1.0))
    failure_mode = str(
        configured.get("on_store_failure", "deny" if production else "last_known")
    )
    return CachedKillSwitchStore(
        store,
        ttl_seconds=ttl,
        on_store_failure=failure_mode,
        metrics=metrics,
        audit=audit,
    )


def _configured_sqlite_path() -> Path | None:
    configured = os.getenv("JUDIKT_CONTROL_DB")
    return Path(configured).expanduser() if configured else None


def _validate_change(
    scope: str,
    name: str,
    enabled: bool,
    actor: str,
    reason: str,
) -> None:
    if scope not in {"tool", "server"}:
        raise ValueError("kill-switch scope must be 'tool' or 'server'")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("kill-switch name must be a non-empty string")
    if not isinstance(enabled, bool):
        raise ValueError("kill-switch enabled must be a boolean")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("kill-switch actor must be a non-empty string")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("kill-switch reason must be a non-empty string")


def _copy_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "tools": set(state["tools"]),
        "servers": set(state["servers"]),
        "version": int(state["version"]),
    }
